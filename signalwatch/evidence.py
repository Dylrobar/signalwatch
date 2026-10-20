"""Scoped evidence browsing and source-level technology history.

Snapshots describe observations of one successfully collected source. Absence in a
feed, a failed probe, and identity re-attribution are never technology removals.
"""
import base64
import csv
import hashlib
import json
import os
import re
import tempfile
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException, Query
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask

from .companies import company

SCHEMA = """
CREATE INDEX IF NOT EXISTS evidence_fingerprint_page ON tech_fingerprints(organization_id,id);
CREATE INDEX IF NOT EXISTS company_identity_label_lookup ON company_identity_labels(label,company_id);
CREATE TABLE IF NOT EXISTS evidence_source_checks (
 source_entity_id TEXT PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
 checked_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence_company_revisions (
 organization_id TEXT PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
 revision TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS company_technology_snapshots (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
 source_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
 source_url TEXT NOT NULL, observed_at TEXT NOT NULL, captured_at TEXT NOT NULL,
 content_hash TEXT NOT NULL, items TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS technology_snapshots_source ON company_technology_snapshots(organization_id,source_entity_id,captured_at DESC,id DESC);
CREATE TABLE IF NOT EXISTS company_technology_events (
 id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL REFERENCES company_technology_snapshots(id) ON DELETE CASCADE,
 organization_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
 source_entity_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
 source_url TEXT NOT NULL, observed_at TEXT NOT NULL, kind TEXT NOT NULL,
 product_name TEXT NOT NULL, before_evidence TEXT NOT NULL, after_evidence TEXT NOT NULL,
 reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS technology_events_company ON company_technology_events(organization_id,observed_at DESC,id DESC);
"""


def ensure_schema(conn):
    # Additive, constant-time setup; history starts with the next observation.
    for statement in SCHEMA.split(";"):
        if statement.strip():
            conn.execute(statement)


def _now():
    return datetime.now(timezone.utc).isoformat()


def _parse(value):
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError, OverflowError):
        return None


def bump_revision(conn, organization_id):
    conn.execute("""INSERT INTO evidence_company_revisions VALUES(?,?) ON CONFLICT(organization_id)
     DO UPDATE SET revision=excluded.revision""", (organization_id, uuid.uuid4().hex))


def record_check(conn, source_entity_id, timestamp):
    conn.execute("""INSERT INTO evidence_source_checks VALUES(?,?) ON CONFLICT(source_entity_id)
     DO UPDATE SET checked_at=CASE WHEN evidence_source_checks.checked_at>excluded.checked_at
     THEN evidence_source_checks.checked_at ELSE excluded.checked_at END""", (source_entity_id, timestamp))


def incomplete_observation(entity):
    metadata = entity.get("metadata") or {}
    return (metadata.get("snapshot_complete") is False or metadata.get("scan_complete") is False
            or metadata.get("collection_status") in {"error", "failed", "partial"})


def record_source_snapshot(conn, entity, doc, organization_id, document_id, timestamp):
    """Record a capture after project() has validated the incoming completion state."""
    record_check(conn, entity["id"], timestamp)
    bump_revision(conn, organization_id)
    fields = ("id", "vendor", "product", "product_name", "category", "version", "status", "confidence", "evidence_snippet", "method")
    items = [{**{key: row[key] for key in fields}, "source_url": doc["source_url"], "source_type": doc["source_type"],
              "published_at": doc.get("published_at"), "observed_at": timestamp}
             for row in conn.execute("SELECT * FROM tech_fingerprints WHERE organization_id=? AND document_id=? ORDER BY id", (organization_id, document_id))]
    content_hash = hashlib.sha256(json.dumps([{key: value for key, value in item.items() if key != "observed_at"}
                                             for item in items], sort_keys=True).encode()).hexdigest()
    previous = conn.execute("""SELECT * FROM company_technology_snapshots WHERE organization_id=? AND source_entity_id=?
      ORDER BY captured_at DESC,id DESC LIMIT 1""", (organization_id, entity["id"])).fetchone()
    # Re-projection and unchanged content do not create artificial churn.
    if previous is not None and (previous["content_hash"] == content_hash or timestamp < previous["observed_at"]):
        return
    snapshot_id, captured_at = uuid.uuid4().hex, _now()
    conn.execute("INSERT INTO company_technology_snapshots VALUES(?,?,?,?,?,?,?,?)",
                 (snapshot_id, organization_id, entity["id"], doc["source_url"], timestamp, captured_at, content_hash, json.dumps(items)))
    before = json.loads(previous["items"]) if previous else []

    def event(kind, name, old, new, reason):
        conn.execute("INSERT INTO company_technology_events VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                     (uuid.uuid4().hex, snapshot_id, organization_id, entity["id"], doc["source_url"], timestamp,
                      kind, name, json.dumps(old), json.dumps(new), reason))

    def grouped(values):
        result = {}
        for item in values:
            result.setdefault((item["vendor"], item["product"]), []).append(item)
        return result

    old, new = grouped(before), grouped(items)
    for key in sorted(old.keys() | new.keys()):
        previous_items, current_items = old.get(key, []), new.get(key, [])
        name = (current_items or previous_items)[0]["product_name"]
        if not previous_items:
            event("added", name, [], current_items, "First observed in this source; this is not proof of a new deployment.")
        elif not current_items:
            event("no_longer_observed", name, previous_items, [], "Absent from a complete refresh of this source; other sources and deployments may still use it.")
        elif {(i["status"], i["version"], i["evidence_snippet"]) for i in previous_items} != {(i["status"], i["version"], i["evidence_snippet"]) for i in current_items}:
            event("changed", name, previous_items, current_items, "The evidence in this source changed; verify deployment changes independently.")
    # Only explicit migration language within the same sentence connects products.
    previous_assertions = {(i["vendor"], i["product"], i["status"], i["evidence_snippet"], i["version"]) for i in before}
    snippets = {}
    for item in items:
        snippets.setdefault(item["evidence_snippet"], []).append(item)
    for snippet, values in snippets.items():
        if {(i["vendor"], i["product"], i["status"], i["evidence_snippet"], i["version"]) for i in values}.issubset(previous_assertions):
            continue
        if not re.search(r"\b(migrat\w*|replac\w*|moving|moved)\b", snippet, re.I):
            continue
        targets = [i for i in values if i["status"] == "planned"]
        sources = [i for i in values if i["status"] in {"asserted_use", "historical"}]
        kind = "migration_planned"
        if not targets:
            targets = [i for i in values if i["status"] == "asserted_use"]
            sources = [i for i in values if i["status"] == "historical"]
            kind = "migration_reported"
        if sources and targets and {(i["vendor"], i["product"]) for i in sources}.isdisjoint({(i["vendor"], i["product"]) for i in targets}):
            event(kind, " → ".join([", ".join(i["product_name"] for i in sources), ", ".join(i["product_name"] for i in targets)]), sources, targets,
                  "Migration candidate from a public source statement; deployment completion is not independently verified.")


# The active evidence source fence mirrors organization ownership, even for
# retained historical documents and shared content hashes.
ACTIVE = """EXISTS (SELECT 1 FROM technographic_sources s JOIN evidence_resolution r
 ON r.source_entity_id=s.source_entity_id AND r.organization_id=s.organization_id
 WHERE s.document_id=f.document_id AND s.organization_id=f.organization_id AND r.status='resolved')"""
SELECT = """SELECT f.*,d.title AS document_title,d.published_at,
 (SELECT s.source_url FROM technographic_sources s JOIN evidence_resolution r ON r.source_entity_id=s.source_entity_id AND r.organization_id=s.organization_id
  WHERE s.document_id=f.document_id AND s.organization_id=f.organization_id AND r.status='resolved' ORDER BY s.last_seen_at DESC,s.source_url LIMIT 1) AS source_url,
 (SELECT s.source_type FROM technographic_sources s JOIN evidence_resolution r ON r.source_entity_id=s.source_entity_id AND r.organization_id=s.organization_id
  WHERE s.document_id=f.document_id AND s.organization_id=f.organization_id AND r.status='resolved' ORDER BY s.last_seen_at DESC,s.source_url LIMIT 1) AS source_type,
 (SELECT max(c.checked_at) FROM evidence_source_checks c JOIN technographic_sources s ON s.source_entity_id=c.source_entity_id
  JOIN evidence_resolution r ON r.source_entity_id=s.source_entity_id AND r.organization_id=s.organization_id
  WHERE s.document_id=f.document_id AND s.organization_id=f.organization_id AND r.status='resolved') AS last_checked_at
 FROM tech_fingerprints f JOIN technographic_documents d ON d.id=f.document_id AND d.organization_id=f.organization_id"""


def decorate(finding, config=None, now=None):
    finding = dict(finding)
    details = finding.pop("evidence_details", {})
    if isinstance(details, str):
        details = json.loads(details)
    finding.update({key: details[key] for key in ("asset_id", "evidence_type", "implied_by", "csp_directive", "matched_host") if key in details})
    source_type = finding.get("source_type")
    direct = source_type in {"http_fingerprint", "dns_txt"}
    basis = "last_observed_at" if direct else "published_at" if _parse(finding.get("published_at")) else "first_seen_at"
    stamp = finding.get("last_seen_at") if direct else finding.get(basis)
    parsed = _parse(stamp)
    age = max(0.0, ((now or datetime.now(timezone.utc)) - parsed).total_seconds() / 86400) if parsed else None
    default_days = 7 if source_type == "http_fingerprint" else 30 if source_type == "dns_txt" else 90
    configured = (config or {}).get("evidence_freshness_days", {}).get(source_type, default_days)
    days = float(configured) if isinstance(configured, (int, float)) and not isinstance(configured, bool) and 0 < configured <= 36500 else default_days
    status = "unknown" if age is None else "stale" if age > days else "fresh"
    reason = ("HTTP evidence ages from the last collected response; an unchanged check is not a new direct observation." if source_type == "http_fingerprint"
              else "DNS verification evidence ages from its last observed answer; it does not verify software deployment." if source_type == "dns_txt"
              else "Public text ages from publication, or first collection when publication is unknown; a recheck does not verify current deployment.")
    finding.update(last_checked_at=finding.get("last_checked_at"), first_observed_at=finding.get("first_seen_at"), last_observed_at=finding.get("last_seen_at"),
                   direct_observed_at=finding.get("last_seen_at") if source_type == "http_fingerprint" else None,
                   freshness={"status": status, "basis": basis, "age_days": round(age, 1) if age is not None else None, "max_age_days": days, "reason": reason})
    return finding


def _filters(organization_id, q, status, category):
    clauses, args = ["f.organization_id=?", ACTIVE], [organization_id]
    if q:
        escaped = q.casefold().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        clauses.append("(lower(f.product_name) LIKE ? ESCAPE '\\' OR lower(f.vendor_name) LIKE ? ESCAPE '\\' OR lower(f.cpe) LIKE ? ESCAPE '\\' OR lower(f.evidence_snippet) LIKE ? ESCAPE '\\')")
        args.extend(["%" + escaped + "%"] * 4)
    for column, value in (("status", status), ("category", category)):
        if value:
            clauses.append("f." + column + "=?")
            args.append(value)
    return " AND ".join(clauses), args


def _revision(conn, organization_id):
    row = conn.execute("SELECT revision FROM evidence_company_revisions WHERE organization_id=?", (organization_id,)).fetchone()
    return row[0] if row else "initial"


def _encode(value):
    return base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode()).decode().rstrip("=")


def _page_cursor(cursor, scope, revision):
    if not cursor:
        return "", _now()
    try:
        value = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
        if not isinstance(value, dict) or value.get("scope") != scope or not isinstance(value.get("after"), str) or not _parse(value.get("snapshot_at")):
            raise ValueError()
    except (ValueError, TypeError, UnicodeDecodeError):
        raise HTTPException(400, "Invalid cursor for these filters") from None
    if value.get("revision") != revision:
        raise HTTPException(409, "Evidence changed; restart pagination")
    return value["after"], value["snapshot_at"]


def _validate_company(conn, organization_id):
    try:
        return company(conn, organization_id)
    except LookupError as exc:
        raise HTTPException(404, str(exc)) from None
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


def evidence_page(conn, organization_id, *, q="", status="", category="", cursor=None, limit=25, config=None):
    _validate_company(conn, organization_id)
    scope = ["evidence", organization_id, q, status, category]
    revision = _revision(conn, organization_id)
    after, snapshot_at = _page_cursor(cursor, scope, revision)
    where, args = _filters(organization_id, q, status, category)
    total = conn.execute("SELECT count(*) FROM tech_fingerprints f WHERE " + where, args).fetchone()[0]
    rows = conn.execute(SELECT + " WHERE " + where + " AND f.id>? ORDER BY f.id LIMIT ?", [*args, after, limit + 1]).fetchall()
    choices = conn.execute("SELECT DISTINCT f.category,f.status FROM tech_fingerprints f WHERE f.organization_id=? AND " + ACTIVE, (organization_id,)).fetchall()
    items = [decorate(row, config, _parse(snapshot_at)) for row in rows[:limit]]
    next_cursor = _encode({"scope": scope, "revision": revision, "after": items[-1]["id"], "snapshot_at": snapshot_at}) if len(rows) > limit else None
    return {"items": items, "total": total, "next_cursor": next_cursor, "snapshot_at": snapshot_at,
            "categories": sorted({row[0] for row in choices}), "statuses": sorted({row[1] for row in choices})}


def history_page(conn, organization_id, *, cursor=None, limit=25):
    _validate_company(conn, organization_id)
    scope, revision = ["history", organization_id], _revision(conn, organization_id)
    after, snapshot_at = _page_cursor(cursor, scope, revision)
    where = """e.organization_id=? AND EXISTS(SELECT 1 FROM evidence_resolution r
     WHERE r.source_entity_id=e.source_entity_id AND r.organization_id=e.organization_id AND r.status='resolved')"""
    total = conn.execute("SELECT count(*) FROM company_technology_events e WHERE " + where, (organization_id,)).fetchone()[0]
    args = [organization_id]
    if after:
        try:
            after_time, after_id = after.split("\0", 1)
        except ValueError:
            raise HTTPException(400, "Invalid history cursor") from None
        where += " AND (e.observed_at<? OR (e.observed_at=? AND e.id<?))"
        args.extend((after_time, after_time, after_id))
    rows = conn.execute("SELECT e.* FROM company_technology_events e WHERE " + where + " ORDER BY e.observed_at DESC,e.id DESC LIMIT ?", [*args, limit + 1]).fetchall()
    items = []
    for row in rows[:limit]:
        item = dict(row)
        item["before"], item["after"] = json.loads(item.pop("before_evidence")), json.loads(item.pop("after_evidence"))
        items.append(item)
    next_cursor = _encode({"scope": scope, "revision": revision, "after": items[-1]["observed_at"] + "\0" + items[-1]["id"], "snapshot_at": snapshot_at}) if len(rows) > limit else None
    return {"items": items, "total": total, "next_cursor": next_cursor, "snapshot_at": snapshot_at}


def _read_snapshot(conn):
    if not getattr(conn, "in_transaction", False):
        conn.execute("BEGIN")
        if getattr(conn, "dialect", "") == "postgresql":
            conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")


def _csv_value(value):
    value = "" if value is None else str(value)
    return "'" + value if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")) else value


def register_evidence_routes(app, store, config):
    @app.get("/api/companies/evidence")
    def evidence(id: str = Query(..., min_length=1, max_length=2000), q: str = Query("", max_length=500),
                 status: str = Query("", max_length=100), category: str = Query("", max_length=200),
                 cursor: str | None = Query(None, max_length=10000), limit: int = Query(25, ge=1, le=100)):
        with store.connection() as conn:
            _read_snapshot(conn)
            return evidence_page(conn, id, q=q, status=status, category=category, cursor=cursor, limit=limit, config=config)

    @app.get("/api/companies/history")
    def history(id: str = Query(..., min_length=1, max_length=2000), cursor: str | None = Query(None, max_length=10000),
                limit: int = Query(25, ge=1, le=100)):
        with store.connection() as conn:
            _read_snapshot(conn)
            return history_page(conn, id, cursor=cursor, limit=limit)

    @app.get("/api/companies/evidence/export")
    def export(id: str = Query(..., min_length=1, max_length=2000), q: str = Query("", max_length=500),
               status: str = Query("", max_length=100), category: str = Query("", max_length=200)):
        path = None
        try:
            with store.connection() as conn:
                _read_snapshot(conn)
                _validate_company(conn, id)
                where, args = _filters(id, q, status, category)
                snapshot_at = _now()
                fd, path = tempfile.mkstemp(prefix="signalwatch-evidence-", suffix=".csv")
                with os.fdopen(fd, "w", newline="", encoding="utf-8") as stream:
                    writer = csv.writer(stream)
                    fields = ("id", "organization_id", "document_id", "product_name", "vendor_name", "vendor", "product", "category", "part", "status", "version", "cpe", "confidence", "method", "evidence_snippet", "source_url", "source_type", "document_title", "published_at", "first_observed_at", "last_observed_at", "last_checked_at", "direct_observed_at")
                    writer.writerow([*fields, "freshness", "freshness_reason", "snapshot_at", "filter_q", "filter_status", "filter_category"])
                    for row in conn.execute(SELECT + " WHERE " + where + " ORDER BY f.id", args):
                        finding = decorate(row, config, _parse(snapshot_at))
                        writer.writerow([_csv_value(finding.get(field)) for field in fields] + [_csv_value(value) for value in (finding["freshness"]["status"], finding["freshness"]["reason"], snapshot_at, q, status, category)])
            return FileResponse(path, media_type="text/csv; charset=utf-8", filename="company-evidence.csv", background=BackgroundTask(os.unlink, path))
        except BaseException:
            if path and os.path.exists(path):
                os.unlink(path)
            raise
