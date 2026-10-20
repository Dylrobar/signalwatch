import re
from collections import defaultdict
from datetime import datetime, timezone

from fastapi import Query

from .companies import company_assets
from .evidence import _read_snapshot, _validate_company

KINDS = ("freshness", "duplicate_articles", "ambiguous_alias", "coverage_gap", "missing_version")
ARTICLE_WINDOW = 5000
COVERAGE_COMPANIES = 100
STALE_FACTOR = 2


def _parse(value):
    try:
        stamp = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)


def _term(value):
    return re.sub(r"\s+", " ", str(value or "")).strip().casefold()


def freshness(store, config, now=None):
    now = now or datetime.now(timezone.utc)
    states = {row["name"]: row for row in store.sources()}
    rows = []
    for name, enabled in sorted(config.get("sources", {}).items()):
        state = states.get(name, {})
        interval = float(config.get("source_intervals", {}).get(name) or config.get("interval_minutes") or 0) or None
        last = _parse(state["last_success"]) if state.get("last_success") else None
        age = round((now - last).total_seconds() / 60, 1) if last else None
        if not enabled:
            status = "disabled"
        elif last is None:
            status = "never_collected"
        elif interval is None:
            status = "unknown"
        elif age > interval * STALE_FACTOR:
            status = "stale"
        else:
            status = "fresh"
        errored = bool(state.get("error")) or state.get("status") in {"error", "partial"}
        rows.append({"source": name, "status": status, "last_success": state.get("last_success"), "age_minutes": age,
                     "interval_minutes": interval, "last_status": state.get("status"), "has_errors": errored})
    return rows


def duplicate_articles(store, limit=50, offset=0):
    # A bounded recent window; duplicate reports never delete or merge sources.
    with store.connection() as conn:
        rows = conn.execute("""SELECT id,url,title,source,published FROM articles WHERE trim(title)!=''
         ORDER BY coalesce(published,updated_at) DESC,id LIMIT ?""", (ARTICLE_WINDOW,)).fetchall()
    groups = defaultdict(list)
    for row in rows:
        groups[_term(row["title"])].append(dict(row))
    duplicate = [(title, records) for title, records in groups.items() if len({row["url"] for row in records}) > 1]
    duplicate.sort(key=lambda item: (-len(item[1]), item[0]))
    items = [{"title": title, "count": len(records), "distinct_sources": len({row["source"] for row in records}),
              "records": [{key: row[key] for key in ("id", "url", "source", "published")} for row in records[:10]],
              "records_truncated": len(records) > 10} for title, records in duplicate[offset:offset + limit]]
    return {"items": items, "total": len(duplicate), "window": ARTICLE_WINDOW}


def ambiguous_aliases(store, limit=50, offset=0):
    # Use exactly the deterministic normalized labels used by attribution.
    with store.connection() as conn:
        _read_snapshot(conn)
        total = conn.execute("SELECT count(*) FROM (SELECT label FROM company_identity_labels GROUP BY label HAVING count(*)>1) shared").fetchone()[0]
        labels = conn.execute("SELECT label FROM company_identity_labels GROUP BY label HAVING count(*)>1 ORDER BY label LIMIT ? OFFSET ?", (limit, offset)).fetchall()
        items = []
        for (label,) in labels:
            rows = conn.execute("""SELECT e.id,coalesce(p.name,e.name) AS name FROM company_identity_labels l
             JOIN entities e ON e.id=l.company_id LEFT JOIN company_profiles p ON p.company_id=e.id
             WHERE l.label=? ORDER BY e.id""", (label,)).fetchall()
            items.append({"term": label, "companies": [dict(row) for row in rows], "resolution": "candidate_only"})
        count = conn.execute("SELECT count(DISTINCT company_id) FROM company_identity_labels").fetchone()[0]
    return {"items": items, "total": total, "profiles_scanned": count, "truncated": False}


def company_gaps(conn, company_id):
    assets, truncated = company_assets(conn, company_id)
    included = [asset["id"] for asset in assets if asset.get("included")]
    gaps = []
    observed = versioned = 0
    if not included:
        gaps.append("no_included_assets")
    else:
        marks = ",".join("?" * len(included))
        row = conn.execute(f"SELECT count(*), sum(CASE WHEN version!='' THEN 1 ELSE 0 END) FROM observations WHERE asset_id IN ({marks})", included).fetchone()
        observed, versioned = row[0], row[1] or 0
        if not observed:
            gaps.append("no_software_observations")
        elif not versioned:
            gaps.append("no_versioned_observations")
    return {"included_assets": len(included), "observations": observed, "versioned_observations": versioned,
            "gaps": gaps, "assets_truncated": truncated}


def coverage_gaps(store, limit=50, offset=0):
    with store.connection() as conn:
        _read_snapshot(conn)
        companies = conn.execute("SELECT e.id AS company_id,coalesce(p.name,e.name) AS name FROM entities e LEFT JOIN company_profiles p ON p.company_id=e.id WHERE e.kind='company' ORDER BY name,e.id LIMIT ?",
                                 (COVERAGE_COMPANIES + 1,)).fetchall()
        rows = [{"company_id": row["company_id"], "name": row["name"], **company_gaps(conn, row["company_id"])}
                for row in companies[:COVERAGE_COMPANIES]]
    flagged = [row for row in rows if row["gaps"]]
    return {"items": flagged[offset:offset + limit], "total": len(flagged), "companies_scanned": len(rows),
            "truncated": len(companies) > COVERAGE_COMPANIES}


def missing_versions(store, limit=50, offset=0):
    with store.connection() as conn:
        _read_snapshot(conn)
        total = conn.execute("SELECT count(*) FROM (SELECT 1 FROM observations WHERE version='' GROUP BY vendor,product) missing").fetchone()[0]
        rows = conn.execute("""SELECT min(vendor_name) AS vendor_name,min(product_name) AS product_name,vendor,product,count(*) AS n, count(DISTINCT asset_id) AS assets
                               FROM observations WHERE version='' GROUP BY vendor,product ORDER BY n DESC,vendor,product LIMIT ? OFFSET ?""",
                            (limit, offset)).fetchall()
    return {"items": [dict(row) for row in rows], "total": total}


def summary(store, config):
    fresh = freshness(store, config)
    with store.connection() as conn:
        _read_snapshot(conn)
        obs = conn.execute("SELECT count(*), sum(CASE WHEN version='' THEN 1 ELSE 0 END) FROM observations").fetchone()
        states = {row[0] if row[0] is not None else "unknown": row[1] for row in
                  conn.execute("SELECT version_state,count(*) FROM alerts GROUP BY version_state")}
    duplicates, aliases, coverage = duplicate_articles(store, 0), ambiguous_aliases(store, 0), coverage_gaps(store, 0)
    counts = defaultdict(int)
    for row in fresh:
        counts[row["status"]] += 1
    return {"generated_at": datetime.now(timezone.utc).isoformat(), "method": "deterministic_sql_checks",
            "scope": "workspace; company coverage is restricted to included assets",
            "freshness": {"counts": dict(counts), "stale_factor": STALE_FACTOR},
            "duplicate_articles": {"groups": duplicates["total"], "window": duplicates["window"], "action": "reported_not_merged"},
            "ambiguous_aliases": {"terms": aliases["total"], "profiles_scanned": aliases["profiles_scanned"], "truncated": aliases["truncated"]},
            "coverage": {"companies_with_gaps": coverage["total"], "companies_scanned": coverage["companies_scanned"], "truncated": coverage["truncated"]},
            "versions": {"observations": obs[0], "without_version": obs[1] or 0, "alerts_by_version_state": states}}


def issues(store, config, kind, limit=50, offset=0):
    if kind == "freshness":
        rows = [row for row in freshness(store, config) if row["status"] in {"stale", "never_collected"} or row["has_errors"]]
        return {"kind": kind, "items": rows[offset:offset + limit], "total": len(rows)}
    handler = {"duplicate_articles": duplicate_articles, "ambiguous_alias": ambiguous_aliases,
               "coverage_gap": coverage_gaps, "missing_version": missing_versions}[kind]
    return {"kind": kind, **handler(store, limit, offset)}


def register_quality_routes(app, store, config):
    @app.get("/api/quality/summary")
    def quality_summary():
        return summary(store, config)

    @app.get("/api/quality/issues")
    def quality_issues(kind: str = Query(..., pattern="^(" + "|".join(KINDS) + ")$"),
                       limit: int = Query(default=50, ge=1, le=100), offset: int = Query(default=0, ge=0, le=10000)):
        return issues(store, config, kind, limit, offset)

    @app.get("/api/quality/company")
    def quality_company(id: str = Query(..., min_length=1, max_length=2000)):
        with store.connection() as conn:
            _read_snapshot(conn)
            row = _validate_company(conn, id)
            return {"company_id": id, "name": row["name"], **company_gaps(conn, id)}
