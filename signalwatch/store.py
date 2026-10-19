import hashlib
import ipaddress
import json
import re
import sqlite3
import uuid
from contextlib import contextmanager, nullcontext
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .companies import COMPANY_SCHEMA, asset_identity, company, company_assets, company_profile, labels, validate_parent
from .matching import cpe_fields, ecosystem_identity, identifier, normalize, osv_version_match, package_identity, rank, version_match
from .staging import STAGING_SCHEMA
from .wireless import WIRELESS_SCHEMA, ingest_wireless
from .wireless_attribution import ATTRIBUTION_SCHEMA, company_wireless_summary


SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
 id TEXT PRIMARY KEY, canonical_id TEXT NOT NULL, title TEXT NOT NULL DEFAULT '',
 summary TEXT NOT NULL DEFAULT '', published TEXT, modified TEXT, severity REAL,
 source TEXT, url TEXT, aliases TEXT NOT NULL DEFAULT '[]', affected TEXT NOT NULL DEFAULT '[]',
 refs TEXT NOT NULL DEFAULT '[]', configurations TEXT, rejected INTEGER NOT NULL DEFAULT 0,
 raw TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS advisories_canonical ON advisories(canonical_id, rejected);
CREATE INDEX IF NOT EXISTS advisories_modified ON advisories(modified DESC);
CREATE TABLE IF NOT EXISTS advisory_aliases (alias TEXT PRIMARY KEY, canonical_id TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS aliases_canonical ON advisory_aliases(canonical_id);
CREATE TABLE IF NOT EXISTS affected (
 advisory_id TEXT NOT NULL, fingerprint TEXT NOT NULL, vendor TEXT NOT NULL,
 product TEXT NOT NULL, part TEXT, vulnerable INTEGER NOT NULL DEFAULT 1, raw TEXT NOT NULL,
 PRIMARY KEY(advisory_id, fingerprint)
);
CREATE INDEX IF NOT EXISTS affected_product ON affected(vendor, product, vulnerable, advisory_id);
CREATE TABLE IF NOT EXISTS entities (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, name TEXT NOT NULL, value TEXT NOT NULL,
 metadata TEXT NOT NULL DEFAULT '{}', observed_at TEXT, source_url TEXT,
 confidence REAL NOT NULL DEFAULT 1, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS entities_kind ON entities(kind, name);
CREATE TABLE IF NOT EXISTS edges (
 from_id TEXT NOT NULL, to_id TEXT NOT NULL, relation TEXT NOT NULL, source_url TEXT NOT NULL DEFAULT '',
 observed_at TEXT, confidence REAL NOT NULL DEFAULT 1,
 PRIMARY KEY(from_id, to_id, relation, source_url)
);
CREATE INDEX IF NOT EXISTS edges_target ON edges(to_id);
CREATE TABLE IF NOT EXISTS observations (
 id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, vendor TEXT NOT NULL, product TEXT NOT NULL,
 vendor_name TEXT NOT NULL, product_name TEXT NOT NULL, part TEXT NOT NULL DEFAULT 'a', version TEXT NOT NULL DEFAULT '',
 source_url TEXT NOT NULL DEFAULT '', evidence TEXT, observed_at TEXT NOT NULL,
 confidence REAL NOT NULL DEFAULT 1, cpe TEXT, raw TEXT NOT NULL, origin TEXT NOT NULL DEFAULT 'imported'
);
CREATE INDEX IF NOT EXISTS observations_product ON observations(vendor, product);
CREATE INDEX IF NOT EXISTS observations_asset ON observations(asset_id);
CREATE TABLE IF NOT EXISTS articles (
 id TEXT PRIMARY KEY, url TEXT NOT NULL UNIQUE, title TEXT NOT NULL DEFAULT '',
 summary TEXT NOT NULL DEFAULT '', published TEXT, source TEXT, cves TEXT NOT NULL DEFAULT '[]',
 raw TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS articles_published ON articles(published DESC);
CREATE TABLE IF NOT EXISTS article_links (
 article_id TEXT NOT NULL, advisory_id TEXT NOT NULL, PRIMARY KEY(article_id, advisory_id)
);
CREATE INDEX IF NOT EXISTS article_links_advisory ON article_links(advisory_id);
CREATE TABLE IF NOT EXISTS kev (cve TEXT PRIMARY KEY, raw TEXT NOT NULL, date_added TEXT, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS epss (cve TEXT PRIMARY KEY, epss REAL, percentile REAL, date TEXT, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS alerts (
 id TEXT PRIMARY KEY, asset_id TEXT NOT NULL, advisory_id TEXT NOT NULL,
 title TEXT, summary TEXT, url TEXT, severity REAL, kev INTEGER NOT NULL DEFAULT 0,
 epss REAL, percentile REAL, epss_date TEXT, kev_date TEXT, rank REAL NOT NULL, confidence REAL NOT NULL,
 status TEXT NOT NULL DEFAULT 'potential', version_state TEXT, reasons TEXT NOT NULL,
 first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, source_url TEXT, evidence TEXT,
 vendor TEXT, product TEXT, version TEXT, observed_at TEXT, checked_token TEXT NOT NULL,
 UNIQUE(asset_id, advisory_id)
);
CREATE INDEX IF NOT EXISTS alerts_rank ON alerts(rank DESC, last_seen DESC);
CREATE INDEX IF NOT EXISTS alerts_asset ON alerts(asset_id);
CREATE TABLE IF NOT EXISTS events (
 id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, title TEXT NOT NULL,
 subject_id TEXT NOT NULL, canonical_id TEXT, source TEXT, url TEXT,
 observed_at TEXT NOT NULL, before_json TEXT, after_json TEXT
);
CREATE INDEX IF NOT EXISTS events_time ON events(observed_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS events_kind_time ON events(kind,observed_at DESC,id DESC);
CREATE INDEX IF NOT EXISTS events_canonical ON events(canonical_id);
CREATE TABLE IF NOT EXISTS advisory_seen (canonical_id TEXT PRIMARY KEY, first_seen TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sources (name TEXT PRIMARY KEY, state TEXT NOT NULL DEFAULT '{}');
CREATE TABLE IF NOT EXISTS crawl_urls (
 url TEXT PRIMARY KEY, source_url TEXT NOT NULL DEFAULT '', company_id TEXT,
 status TEXT NOT NULL DEFAULT 'queued', last_fetched TEXT, leased_at TEXT, error TEXT
);
CREATE INDEX IF NOT EXISTS crawl_due ON crawl_urls(status, last_fetched);
CREATE VIRTUAL TABLE IF NOT EXISTS entity_fts USING fts5(name, value, kind, content=entities, content_rowid=rowid);
CREATE TRIGGER IF NOT EXISTS entity_ai AFTER INSERT ON entities BEGIN
 INSERT INTO entity_fts(rowid,name,value,kind) VALUES(new.rowid,new.name,new.value,new.kind);
END;
CREATE TRIGGER IF NOT EXISTS entity_ad AFTER DELETE ON entities BEGIN
 INSERT INTO entity_fts(entity_fts,rowid,name,value,kind) VALUES('delete',old.rowid,old.name,old.value,old.kind);
END;
CREATE TRIGGER IF NOT EXISTS entity_au AFTER UPDATE ON entities WHEN old.name!=new.name OR old.value!=new.value OR old.kind!=new.kind BEGIN
 INSERT INTO entity_fts(entity_fts,rowid,name,value,kind) VALUES('delete',old.rowid,old.name,old.value,old.kind);
 INSERT INTO entity_fts(rowid,name,value,kind) VALUES(new.rowid,new.name,new.value,new.kind);
END;
CREATE VIRTUAL TABLE IF NOT EXISTS advisory_fts USING fts5(id,title,summary,aliases,content=advisories,content_rowid=rowid);
CREATE TRIGGER IF NOT EXISTS advisory_ai AFTER INSERT ON advisories BEGIN
 INSERT INTO advisory_fts(rowid,id,title,summary,aliases) VALUES(new.rowid,new.id,new.title,new.summary,new.aliases);
END;
CREATE TRIGGER IF NOT EXISTS advisory_ad AFTER DELETE ON advisories BEGIN
 INSERT INTO advisory_fts(advisory_fts,rowid,id,title,summary,aliases) VALUES('delete',old.rowid,old.id,old.title,old.summary,old.aliases);
END;
CREATE TRIGGER IF NOT EXISTS advisory_au AFTER UPDATE ON advisories WHEN old.id!=new.id OR old.title!=new.title OR old.summary!=new.summary OR old.aliases!=new.aliases BEGIN
 INSERT INTO advisory_fts(advisory_fts,rowid,id,title,summary,aliases) VALUES('delete',old.rowid,old.id,old.title,old.summary,old.aliases);
 INSERT INTO advisory_fts(rowid,id,title,summary,aliases) VALUES(new.rowid,new.id,new.title,new.summary,new.aliases);
END;
CREATE VIRTUAL TABLE IF NOT EXISTS article_fts USING fts5(title,summary,source,content=articles,content_rowid=rowid);
CREATE TRIGGER IF NOT EXISTS article_ai AFTER INSERT ON articles BEGIN
 INSERT INTO article_fts(rowid,title,summary,source) VALUES(new.rowid,new.title,new.summary,new.source);
END;
CREATE TRIGGER IF NOT EXISTS article_ad AFTER DELETE ON articles BEGIN
 INSERT INTO article_fts(article_fts,rowid,title,summary,source) VALUES('delete',old.rowid,old.title,old.summary,old.source);
END;
CREATE TRIGGER IF NOT EXISTS article_au AFTER UPDATE ON articles WHEN old.title!=new.title OR old.summary!=new.summary OR old.source!=new.source BEGIN
 INSERT INTO article_fts(article_fts,rowid,title,summary,source) VALUES('delete',old.rowid,old.title,old.summary,old.source);
 INSERT INTO article_fts(rowid,title,summary,source) VALUES(new.rowid,new.title,new.summary,new.source);
END;
"""


AUTHORITATIVE_CVE = "((authority.id LIKE 'CVE-%' AND lower(authority.source)='nvd') OR (authority.id LIKE 'CVE5:CVE-%' AND authority.source='cve_program' AND json_extract(authority.configurations,'$.cve_state') IN ('PUBLISHED','REJECTED')))"
ACTIVE_CVE_STATE = "coalesce((SELECT authority.rejected FROM advisories authority WHERE authority.canonical_id=a.canonical_id AND " + AUTHORITATIVE_CVE + " ORDER BY coalesce(julianday(authority.modified),julianday(authority.published),0) DESC,(authority.source='cve_program') DESC,authority.id LIMIT 1),0)=0"
ACTIVE_ADVISORY_FILTERS = (
    "a.rejected=0",
    ACTIVE_CVE_STATE,
    "a.id=(SELECT chosen.id FROM advisories chosen WHERE chosen.canonical_id=a.canonical_id AND chosen.rejected=0 ORDER BY (chosen.id=chosen.canonical_id) DESC,chosen.modified DESC,chosen.id LIMIT 1)",
)
ADVISORY_TABLE = "advisories a LEFT JOIN kev k ON k.cve=a.canonical_id LEFT JOIN epss p ON p.cve=a.canonical_id"
ADVISORY_SELECT = "a.*,k.cve IS NOT NULL AS kev,k.date_added AS kev_date,p.epss,p.percentile,p.date AS epss_date,min(100.0,max(0.0,coalesce(a.severity,0))*5+CASE WHEN k.cve IS NOT NULL THEN 40 ELSE 0 END+max(0.0,min(1.0,coalesce(p.epss,0)))*10) AS rank"


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def digest(value):
    return hashlib.sha256(str(value).encode()).hexdigest()[:32]


def fts_query(value):
    return " AND ".join('"' + token.replace('"', '""') + '"*' for token in re.findall(r"[\w]+", value))


def public_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return address.is_global and not address.is_multicast


def article_contributions(item):
    records = dict(item.get("feed_records") or {})
    if not records and item.get("feed_url"):
        records[item["feed_url"]] = {key: item.get(key) for key in ("source", "title", "summary", "published", "cves", "guid")}
    return records


def merge_article(previous, incoming):
    previous_records = article_contributions(previous)
    incoming_records = article_contributions(incoming)
    records = {**previous_records, **incoming_records}
    unattributed = dict(previous.get("unattributed_record") or (previous if previous and not previous_records else {}))
    if not incoming_records:
        older_cves = unattributed.get("cves") or []
        older_summary = unattributed.get("summary") or ""
        unattributed.update(incoming)
        unattributed["cves"] = sorted({identifier(value) for value in older_cves + (incoming.get("cves") or [])})
        unattributed["summary"] = max((older_summary, incoming.get("summary") or ""), key=len)
    contributions = list(records.values()) + ([unattributed] if unattributed else [])
    merged = {**previous, **incoming}
    merged["cves"] = sorted({identifier(value) for record in contributions for value in record.get("cves") or []})
    merged["summary"] = max((record.get("summary") or "" for record in contributions), key=len, default="")
    merged["feed_urls"] = sorted(set(previous.get("feed_urls") or []) | set(incoming.get("feed_urls") or []) | set(records))
    merged["feed_sources"] = sorted(set(previous.get("feed_sources") or []) | set(incoming.get("feed_sources") or []) | {record["source"] for record in contributions if record.get("source")})
    if records:
        merged["feed_records"] = records
    if unattributed:
        merged["unattributed_record"] = {key: unattributed.get(key) for key in ("source", "title", "summary", "published", "cves", "guid")}
    return merged


def advisory_change_state(item):
    fields = ("vendor", "product", "part", "criteria", "version", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding", "ecosystem", "package", "purl", "ranges", "versions", "version_range", "first_patched_version", "vulnerable", "version_unverified", "cve_versions", "cve_default_status", "cve_version_status")
    affected = []
    for product in item.get("affected") or []:
        record = {key: product[key] for key in fields if product.get(key) is not None}
        if "versions" in record:
            record["versions"] = sorted(set(record["versions"]))
        affected.append(encode(record))
    return {"title": item.get("title") or item["id"], "severity": float(item["severity"]) if item.get("severity") is not None else None, "rejected": bool(item.get("rejected")), "affected": sorted(set(affected))}


def advisory_event_state(state):
    fields = ("vendor", "product", "ecosystem", "package", "part", "criteria", "version", "versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding", "version_range")
    affected = []
    for value in state["affected"][:20]:
        record = json.loads(value)
        affected.append({key: record[key] for key in fields if key in record})
    return {"title": state["title"][:500], "severity": state["severity"], "rejected": state["rejected"], "affected_count": len(state["affected"]), "affected_digest": digest(encode(state["affected"])), "affected": affected}


def warning_event_state(item):
    state = {key: item.get(key) for key in ("asset_id", "advisory_id", "vendor", "product", "version", "version_state", "status", "kev", "severity", "rank", "source_url")}
    state["evidence"] = str(item.get("evidence") or "")[:2000]
    return state


def kev_event_state(item):
    return {key: item.get(key) for key in ("cveID", "vendorProject", "product", "vulnerabilityName", "dateAdded", "dueDate", "knownRansomwareCampaignUse")}


def decoded(row):
    if row is None:
        return None
    item = dict(row)
    for key in ("metadata", "aliases", "affected", "references", "configurations", "cves", "reasons", "raw", "before", "after"):
        if key in item and isinstance(item[key], str):
            try:
                item[key] = json.loads(item[key])
            except (ValueError, TypeError):
                pass
    for key in ("kev", "rejected"):
        if key in item:
            item[key] = bool(item[key])
    if "refs" in item:
        item["references"] = json.loads(item.pop("refs"))
    if isinstance(item.get("raw"), dict):
        for key in ("feed_url", "feed_urls", "feed_sources"):
            if key in item["raw"]:
                item[key] = item["raw"][key]
    item.pop("raw", None)
    item.pop("checked_token", None)
    return item


class Store:
    def __init__(self, path):
        self.path = str(path)
        self.uri = self.path == ":memory:"
        self._keeper = None
        if self.uri:
            self.path = "file:signalwatch_" + uuid.uuid4().hex + "?mode=memory&cache=shared"
            self._keeper = sqlite3.connect(self.path, uri=True, check_same_thread=False)
        else:
            Path(self.path).expanduser().parent.mkdir(parents=True, exist_ok=True)
            self.path = str(Path(self.path).expanduser())
        with self.connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            had_advisory_seen = conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='advisory_seen'").fetchone() is not None
            conn.executescript(SCHEMA)
            conn.executescript(COMPANY_SCHEMA)
            conn.executescript(STAGING_SCHEMA)
            conn.executescript(WIRELESS_SCHEMA)
            conn.executescript(ATTRIBUTION_SCHEMA)
            if "superseded_by" not in {row[1] for row in conn.execute("PRAGMA table_info(raw_ingress)")}:
                conn.execute("ALTER TABLE raw_ingress ADD COLUMN superseded_by INTEGER")
            if not had_advisory_seen:
                conn.execute("INSERT OR IGNORE INTO advisory_seen(canonical_id,first_seen) SELECT canonical_id,min(updated_at) FROM advisories GROUP BY canonical_id")
            if "part" not in {row[1] for row in conn.execute("PRAGMA table_info(observations)")}:
                conn.execute("ALTER TABLE observations ADD COLUMN part TEXT NOT NULL DEFAULT 'a'")
            if "origin" not in {row[1] for row in conn.execute("PRAGMA table_info(observations)")}:
                conn.execute("ALTER TABLE observations ADD COLUMN origin TEXT NOT NULL DEFAULT 'imported'")
                for row in conn.execute("SELECT id,asset_id,vendor,product,source_url,raw FROM observations").fetchall():
                    origin = str(json.loads(row["raw"]).get("origin") or "imported")
                    identity = digest(encode([row["asset_id"], row["vendor"], row["product"], row["source_url"], origin]))
                    conn.execute("UPDATE observations SET id=?,origin=? WHERE id=?", (identity, origin, row["id"]))
            conn.execute("CREATE INDEX IF NOT EXISTS observations_page_origin ON observations(asset_id,source_url,origin)")
            alert_columns = {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}
            for column in ("epss_date", "kev_date"):
                if column not in alert_columns:
                    conn.execute("ALTER TABLE alerts ADD COLUMN " + column + " TEXT")

    @contextmanager
    def connection(self, write=False):
        conn = sqlite3.connect(self.path, uri=self.uri, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=30000")
        conn.execute("PRAGMA synchronous=NORMAL")
        try:
            if write:
                conn.execute("BEGIN IMMEDIATE")
            yield conn
            conn.commit()
        except BaseException:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _event(self, conn, kind, title, subject_id, canonical_id, source, url, timestamp, before=None, after=None):
        conn.execute("INSERT INTO events(kind,title,subject_id,canonical_id,source,url,observed_at,before_json,after_json) VALUES(?,?,?,?,?,?,?,?,?)",
         (kind, title, subject_id, canonical_id, source, url, timestamp, encode(before) if before is not None else None, encode(after) if after is not None else None))

    def _entity(self, conn, item, timestamp):
        key = str(item["id"])
        conn.execute("""INSERT INTO entities(id,kind,name,value,metadata,observed_at,source_url,confidence,updated_at)
         VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
         kind=excluded.kind,name=excluded.name,value=excluded.value,
         metadata=json_patch(entities.metadata,excluded.metadata),observed_at=excluded.observed_at,
         source_url=CASE WHEN excluded.source_url!='' THEN excluded.source_url ELSE entities.source_url END,
         confidence=excluded.confidence,updated_at=excluded.updated_at
         WHERE entities.kind!=excluded.kind OR entities.name!=excluded.name OR entities.value!=excluded.value
          OR json_patch(entities.metadata,excluded.metadata)!=entities.metadata
          OR entities.observed_at!=excluded.observed_at OR entities.source_url!=excluded.source_url
          OR entities.confidence!=excluded.confidence""",
         (key, item.get("kind") or "technology", str(item.get("name") or item.get("value") or key),
          str(item.get("value") or item.get("name") or key), encode(item.get("metadata") or {}),
          item.get("observed_at") or timestamp, item.get("source_url") or "", float(item.get("confidence", 1)), timestamp))

    def _edge(self, conn, item, timestamp):
        conn.execute("""INSERT INTO edges(from_id,to_id,relation,source_url,observed_at,confidence) VALUES(?,?,?,?,?,?)
         ON CONFLICT(from_id,to_id,relation,source_url) DO UPDATE SET
         observed_at=excluded.observed_at,confidence=excluded.confidence""",
         (item["from_id"], item["to_id"], item["relation"], item.get("source_url") or "",
          item.get("observed_at") or timestamp, float(item.get("confidence", 1))))

    def _canonical(self, conn, ids):
        ids = sorted({identifier(value) for value in ids if value})
        placeholders = ",".join("?" for _ in ids)
        known = [row[0] for row in conn.execute(f"SELECT canonical_id FROM advisory_aliases WHERE alias IN ({placeholders})", ids)]
        candidates = sorted(set(ids + known))
        canonical = next((value for value in candidates if value.startswith("CVE-")), next((value for value in candidates if value.startswith("GHSA-")), next((value for value in candidates if not value.startswith("OSV:")), candidates[0])))
        for previous in set(known) - {canonical}:
            conn.execute("""INSERT INTO advisory_seen(canonical_id,first_seen) SELECT ?,first_seen FROM advisory_seen WHERE canonical_id=?
             ON CONFLICT(canonical_id) DO UPDATE SET first_seen=min(advisory_seen.first_seen,excluded.first_seen)""", (canonical, previous))
            conn.execute("DELETE FROM advisory_seen WHERE canonical_id=?", (previous,))
            conn.execute("UPDATE events SET canonical_id=? WHERE canonical_id=?", (canonical, previous))
            for alert in conn.execute("SELECT id,asset_id,first_seen FROM alerts WHERE advisory_id=?", (previous,)).fetchall():
                existing = conn.execute("SELECT id,first_seen FROM alerts WHERE asset_id=? AND advisory_id=?", (alert["asset_id"], canonical)).fetchone()
                if existing:
                    conn.execute("UPDATE alerts SET first_seen=? WHERE id=?", (min(existing["first_seen"], alert["first_seen"]), existing["id"]))
                    conn.execute("DELETE FROM alerts WHERE id=?", (alert["id"],))
                else:
                    conn.execute("UPDATE alerts SET id=?,advisory_id=? WHERE id=?", ("alert:" + digest(alert["asset_id"] + "\0" + canonical), canonical, alert["id"]))
            conn.execute("UPDATE advisories SET canonical_id=? WHERE canonical_id=?", (canonical, previous))
            conn.execute("UPDATE advisory_aliases SET canonical_id=? WHERE canonical_id=?", (canonical, previous))
        conn.executemany("INSERT INTO advisory_aliases(alias,canonical_id) VALUES(?,?) ON CONFLICT(alias) DO UPDATE SET canonical_id=excluded.canonical_id", ((value, canonical) for value in ids))
        return canonical

    def _product(self, conn, value, source_url, observed_at, timestamp):
        fields = cpe_fields(value.get("criteria") or value.get("cpe"))
        ecosystem = value.get("ecosystem")
        package = value.get("package")
        if isinstance(package, dict):
            ecosystem = package.get("ecosystem") or ecosystem
            package = package.get("name")
        vendor = value.get("vendor") or ecosystem or fields.get("vendor") or ""
        product = value.get("product") or package or fields.get("product") or ""
        part = value.get("part") or fields.get("part") or "a"
        if not vendor or not product or vendor == "*" or product == "*":
            return None
        vendor_key, product_key = normalize(vendor), normalize(product)
        if ecosystem:
            part = "package"
            vendor_key = ecosystem_identity(ecosystem)
            product_key = package_identity(ecosystem, product)
            key = f"package:{vendor_key}:{product_key}"
            kind = "package"
            metadata = {"ecosystem": ecosystem, "package": product, "purl": value.get("purl"), "evidence_role": "osv_affected_package"}
        else:
            vendor_id = "vendor:" + vendor_key
            self._entity(conn, {"id": vendor_id, "kind": "vendor", "name": vendor, "metadata": {"evidence_role": "cpe_vendor_label", "verified_legal_company": False}, "source_url": source_url, "observed_at": observed_at}, timestamp)
            key = f"cpe:{part}:{vendor_key}:{product_key}"
            kind = {"h": "device", "o": "os"}.get(part, "technology")
            metadata = {"vendor": vendor, "product": product, "part": part, "evidence_role": "product_identifier"}
            self._edge(conn, {"from_id": vendor_id, "to_id": key, "relation": "publishes", "source_url": source_url, "observed_at": observed_at}, timestamp)
        self._entity(conn, {"id": key, "kind": kind, "name": product, "metadata": metadata, "source_url": source_url, "observed_at": observed_at}, timestamp)
        return key, vendor_key, product_key, part

    def ingest(self, batch, *, conn=None):
        timestamp = now()
        snapshot = batch.get("kev_snapshot") if "kev_snapshot" in batch else None
        if snapshot is not None:
            batch = {**batch, "kev": snapshot}
        if batch.get("kev"):
            stubs = [{"id": "KEV:" + identifier(item["cveID"]), "aliases": [identifier(item["cveID"])],
             "title": item.get("vulnerabilityName") or item["cveID"], "summary": item.get("shortDescription") or "",
             "published": item.get("dateAdded"), "modified": item.get("dateAdded"), "severity": None,
             "source": "CISA KEV", "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
             "affected": [], "references": [], "raw": item} for item in batch["kev"]]
            batch = {**batch, "advisories": list(batch.get("advisories") or []) + stubs}
        counts = {key: len(batch.get(key) or []) for key in ("advisories", "articles", "entities", "edges", "observations", "kev", "epss")}
        with self.connection(write=True) if conn is None else nullcontext(conn) as conn:
            if "wireless_batch" in batch:
                counts.update(ingest_wireless(self, conn, batch["wireless_batch"], timestamp))
            if snapshot is not None:
                conn.execute("CREATE TEMP TABLE kev_current(cve TEXT PRIMARY KEY)")
                conn.executemany("INSERT OR IGNORE INTO kev_current(cve) VALUES(?)", ((identifier(item["cveID"]),) for item in snapshot))
                for removed_kev in conn.execute("SELECT cve,raw FROM kev WHERE cve NOT IN (SELECT cve FROM kev_current)"):
                    old_kev = json.loads(removed_kev["raw"])
                    self._event(conn, "kev_removed", "KEV catalog removal observed locally: " + removed_kev["cve"], removed_kev["cve"], removed_kev["cve"], "CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", timestamp, kev_event_state(old_kev), None)
                conn.execute("DELETE FROM kev WHERE cve NOT IN (SELECT cve FROM kev_current)")
                conn.execute("CREATE TEMP TABLE kev_removed AS SELECT id FROM advisories WHERE source='CISA KEV' AND id LIKE 'KEV:%' AND canonical_id NOT IN (SELECT cve FROM kev_current)")
                conn.execute("DELETE FROM edges WHERE from_id IN (SELECT id FROM kev_removed) OR to_id IN (SELECT id FROM kev_removed)")
                conn.execute("DELETE FROM entities WHERE id IN (SELECT id FROM kev_removed)")
                conn.execute("DELETE FROM advisories WHERE id IN (SELECT id FROM kev_removed)")
                conn.execute("DELETE FROM advisory_aliases WHERE alias LIKE 'KEV:%' AND canonical_id NOT IN (SELECT cve FROM kev_current)")
            for inventory in batch.get("observation_snapshots") or []:
                conn.execute("DELETE FROM observations WHERE asset_id=? AND origin=?", (inventory["asset_id"], inventory["origin"]))
                conn.execute("""DELETE FROM edges WHERE from_id=? AND relation='observed_technology'
                 AND NOT EXISTS (SELECT 1 FROM observations o WHERE o.asset_id=edges.from_id AND o.source_url=edges.source_url
                  AND edges.to_id=CASE WHEN o.part='package' THEN 'package:'||o.vendor||':'||o.product ELSE 'cpe:'||o.part||':'||o.vendor||':'||o.product END)""", (inventory["asset_id"],))
            for page in batch.get("observation_pages") or []:
                conn.execute("DELETE FROM observations WHERE asset_id=? AND source_url=? AND origin='web'", (page["asset_id"], page["source_url"]))
                conn.execute("""DELETE FROM edges WHERE from_id=? AND source_url=? AND relation='observed_technology'
                 AND NOT EXISTS (SELECT 1 FROM observations o WHERE o.asset_id=edges.from_id AND o.source_url=edges.source_url
                  AND edges.to_id=CASE WHEN o.part='package' THEN 'package:'||o.vendor||':'||o.product ELSE 'cpe:'||o.part||':'||o.vendor||':'||o.product END)""", (page["asset_id"], page["source_url"]))
            for item in batch.get("entities") or []:
                self._entity(conn, item, timestamp)
            for item in batch.get("edges") or []:
                self._edge(conn, item, timestamp)
            for item in batch.get("advisories") or []:
                advisory_id = identifier(item["id"])
                canonical = self._canonical(conn, [advisory_id] + (item.get("aliases") or []))
                raw = encode(item)
                previous = conn.execute("SELECT raw,url,canonical_id FROM advisories WHERE id=?", (advisory_id,)).fetchone()
                if previous and previous[0] == raw:
                    continue
                change_state = advisory_change_state(item)
                first_local = conn.execute("INSERT OR IGNORE INTO advisory_seen(canonical_id,first_seen) VALUES(?,?)", (canonical, timestamp)).rowcount == 1
                if first_local:
                    self._event(conn, "advisory_added", "Advisory first observed locally: " + canonical + " — " + change_state["title"][:300], advisory_id, canonical, item.get("source") or "", item.get("url") or "", timestamp, None, advisory_event_state(change_state))
                elif previous:
                    previous_state = advisory_change_state(json.loads(previous["raw"]))
                    changed = [key for key in change_state if change_state[key] != previous_state[key]]
                    if changed:
                        after = advisory_event_state(change_state)
                        after["changed_fields"] = changed
                        self._event(conn, "advisory_changed", "Local advisory record changed: " + advisory_id + " — " + change_state["title"][:300], advisory_id, canonical, item.get("source") or "", item.get("url") or "", timestamp, advisory_event_state(previous_state), after)
                source_url = item.get("url") or ""
                observed_at = item.get("modified") or item.get("published") or timestamp
                conn.execute("""INSERT INTO advisories(id,canonical_id,title,summary,published,modified,severity,source,url,aliases,affected,refs,configurations,rejected,raw,updated_at)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                 canonical_id=excluded.canonical_id,title=excluded.title,summary=excluded.summary,published=excluded.published,
                 modified=excluded.modified,severity=excluded.severity,source=excluded.source,url=excluded.url,
                 aliases=excluded.aliases,affected=excluded.affected,refs=excluded.refs,configurations=excluded.configurations,
                 rejected=excluded.rejected,raw=excluded.raw,updated_at=excluded.updated_at""",
                 (advisory_id, canonical, item.get("title") or advisory_id, item.get("summary") or "", item.get("published"),
                  item.get("modified"), item.get("severity"), item.get("source") or "", source_url,
                  encode(item.get("aliases") or []), encode(item.get("affected") or []), encode(item.get("references") or []),
                  encode(item.get("configurations")) if item.get("configurations") else None, int(bool(item.get("rejected"))), raw, timestamp))
                conn.execute("DELETE FROM affected WHERE advisory_id=?", (advisory_id,))
                if previous:
                    conn.execute("DELETE FROM edges WHERE to_id=? AND source_url=? AND relation IN ('affected_by','configuration_context')", (previous["canonical_id"], previous["url"]))
                self._entity(conn, {"id": canonical, "kind": "vulnerability", "name": item.get("title") or canonical, "value": canonical, "metadata": {"advisory_id": canonical}, "source_url": source_url, "observed_at": observed_at}, timestamp)
                if advisory_id != canonical:
                    self._entity(conn, {"id": advisory_id, "kind": "vulnerability", "name": advisory_id, "source_url": source_url, "observed_at": observed_at}, timestamp)
                    self._edge(conn, {"from_id": advisory_id, "to_id": canonical, "relation": "alias_of", "source_url": source_url, "observed_at": observed_at}, timestamp)
                for value in ([] if item.get("rejected") or item.get("withdrawn") else item.get("affected") or []):
                    product = self._product(conn, value, source_url, observed_at, timestamp)
                    if product is None:
                        continue
                    key, vendor_key, product_key, part = product
                    vulnerable = value.get("vulnerable", True) not in (False, "false", "False", 0)
                    conn.execute("INSERT OR IGNORE INTO affected(advisory_id,fingerprint,vendor,product,part,vulnerable,raw) VALUES(?,?,?,?,?,?,?)",
                     (advisory_id, digest(encode(value)), vendor_key, product_key, part, int(vulnerable), encode(value)))
                    self._edge(conn, {"from_id": key, "to_id": canonical, "relation": "affected_by" if vulnerable else "configuration_context", "source_url": source_url, "observed_at": observed_at}, timestamp)
            for item in batch.get("observations") or []:
                asset_id = item["asset_id"]
                source_url = item.get("source_url") or ""
                observed_at = item.get("observed_at") or timestamp
                product = self._product(conn, item, source_url, observed_at, timestamp)
                if product is None:
                    continue
                key, vendor_key, product_key, part = product
                conn.execute("INSERT OR IGNORE INTO entities(id,kind,name,value,metadata,observed_at,source_url,confidence,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                 (asset_id, "asset", asset_id, asset_id, "{}", observed_at, source_url, float(item.get("confidence", 1)), timestamp))
                origin = str(item.get("origin") or "imported")
                version = str(item.get("version") or "") if origin.startswith("sbom:") and "version" in item else str(item.get("version") or cpe_fields(item.get("cpe")).get("version") or "")
                identity_fields = [asset_id, vendor_key, product_key, source_url, origin]
                if origin.startswith("sbom:"):
                    identity_fields.extend((part, version))
                identity = digest(encode(identity_fields))
                conn.execute("""INSERT INTO observations(id,asset_id,vendor,product,vendor_name,product_name,part,version,source_url,evidence,observed_at,confidence,cpe,raw,origin)
                 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
                 part=excluded.part,version=excluded.version,evidence=excluded.evidence,observed_at=excluded.observed_at,
                 confidence=excluded.confidence,cpe=excluded.cpe,raw=excluded.raw""",
                 (identity, asset_id, vendor_key, product_key, str(item.get("vendor") or item.get("ecosystem") or vendor_key),
                  str(item.get("product") or item.get("package") or product_key), part, version, source_url,
                  str(item.get("evidence") or ""), observed_at, float(item.get("confidence", 1)), item.get("cpe"), encode(item), origin))
                self._edge(conn, {"from_id": asset_id, "to_id": key, "relation": "observed_technology", "source_url": source_url, "observed_at": observed_at, "confidence": item.get("confidence", 1)}, timestamp)
            for item in batch.get("articles") or []:
                previous = conn.execute("SELECT raw FROM articles WHERE url=?", (item["url"],)).fetchone()
                item = merge_article(json.loads(previous[0]) if previous else {}, item)
                article_id = str(item.get("id") or "article:" + digest(item["url"]))
                aliases = sorted({identifier(value) for value in item.get("cves") or []})
                conn.execute("""INSERT INTO articles(id,url,title,summary,published,source,cves,raw,updated_at) VALUES(?,?,?,?,?,?,?,?,?)
                 ON CONFLICT(url) DO UPDATE SET title=excluded.title,summary=excluded.summary,published=excluded.published,
                 source=excluded.source,cves=excluded.cves,raw=excluded.raw,updated_at=excluded.updated_at
                 WHERE articles.raw!=excluded.raw""",
                 (article_id, item["url"], item.get("title") or item["url"], item.get("summary") or "", item.get("published"),
                  item.get("source") or "", encode(aliases), encode(item), timestamp))
                article_id = conn.execute("SELECT id FROM articles WHERE url=?", (item["url"],)).fetchone()[0]
                conn.execute("DELETE FROM article_links WHERE article_id=?", (article_id,))
                conn.execute("DELETE FROM edges WHERE from_id=? AND relation='mentions' AND source_url=?", (article_id, item["url"]))
                conn.executemany("INSERT OR IGNORE INTO article_links(article_id,advisory_id) VALUES(?,?)", ((article_id, value) for value in aliases))
                self._entity(conn, {"id": article_id, "kind": "article", "name": item.get("title") or item["url"], "value": item["url"], "source_url": item["url"], "observed_at": item.get("published") or timestamp}, timestamp)
                for value in aliases:
                    target = conn.execute("SELECT canonical_id FROM advisory_aliases WHERE alias=?", (value,)).fetchone()
                    self._edge(conn, {"from_id": article_id, "to_id": target[0] if target else value, "relation": "mentions", "source_url": item["url"], "observed_at": item.get("published") or timestamp}, timestamp)
            if batch.get("kev"):
                conn.execute("CREATE TEMP TABLE kev_incoming(cve TEXT PRIMARY KEY,raw TEXT NOT NULL)")
                conn.executemany("INSERT OR REPLACE INTO kev_incoming(cve,raw) VALUES(?,?)", ((identifier(item["cveID"]), encode(item)) for item in batch["kev"]))
                for added_kev in conn.execute("SELECT incoming.cve,incoming.raw FROM kev_incoming incoming LEFT JOIN kev existing ON existing.cve=incoming.cve WHERE existing.cve IS NULL"):
                    new_kev = json.loads(added_kev["raw"])
                    self._event(conn, "kev_added", "KEV catalog entry first observed locally: " + added_kev["cve"], added_kev["cve"], added_kev["cve"], "CISA KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", timestamp, None, kev_event_state(new_kev))
            conn.executemany("""INSERT INTO kev(cve,raw,date_added,updated_at) VALUES(?,?,?,?) ON CONFLICT(cve)
             DO UPDATE SET raw=excluded.raw,date_added=excluded.date_added,updated_at=excluded.updated_at WHERE kev.raw!=excluded.raw""",
             ((identifier(item["cveID"]), encode(item), item.get("dateAdded"), timestamp) for item in batch.get("kev") or []))
            conn.executemany("""INSERT INTO epss(cve,epss,percentile,date,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(cve)
             DO UPDATE SET epss=excluded.epss,percentile=excluded.percentile,date=excluded.date,updated_at=excluded.updated_at
             WHERE epss.epss!=excluded.epss OR epss.percentile!=excluded.percentile OR epss.date!=excluded.date""",
             ((identifier(item["cve"]), float(item.get("epss") or 0), float(item.get("percentile") or 0), item.get("date"), timestamp) for item in batch.get("epss") or []))
        return counts

    def reconcile(self):
        timestamp, token = now(), uuid.uuid4().hex
        candidates = {}
        evaluated = 0
        query = """SELECT o.*,a.id AS source_advisory_id,a.canonical_id,a.title,a.summary,a.url,a.severity,
         a.configurations,f.raw AS affected_raw,k.cve AS kev_cve,k.date_added AS kev_date,p.epss,p.percentile,p.date AS epss_date
         FROM observations o JOIN affected f ON f.vendor=o.vendor AND f.product=o.product AND f.part=o.part AND f.vulnerable=1
         JOIN advisories a ON a.id=f.advisory_id AND a.rejected=0
         LEFT JOIN kev k ON k.cve=a.canonical_id LEFT JOIN epss p ON p.cve=a.canonical_id
         WHERE """ + ACTIVE_CVE_STATE
        with self.connection(write=True) as conn:
            for row in conn.execute(query):
                evaluated += 1
                affected = json.loads(row["affected_raw"])
                matcher = osv_version_match if affected.get("ecosystem") or affected.get("package") else version_match
                matches, state, reason = matcher(row["version"], affected)
                if not matches:
                    continue
                reasons = ["Exact normalized product and vendor/ecosystem match.", reason,
                 "Potential match: deployment, CPE configuration logic, and operating-system prerequisites require verification."]
                is_kev = row["kev_cve"] is not None
                if is_kev:
                    reasons.append("CISA KEV lists this CVE as exploited in the wild; this asset's exploitability is unverified.")
                if row["epss"] is not None:
                    reasons.append("EPSS is a CVE-level exploitation probability, not evidence about this asset.")
                confidence = min(1.0, max(0.0, float(row["confidence"])))
                record = {
                 "id": "alert:" + digest(row["asset_id"] + "\0" + row["canonical_id"]),
                 "asset_id": row["asset_id"], "advisory_id": row["canonical_id"], "title": row["title"],
                 "summary": row["summary"], "url": row["url"], "severity": row["severity"], "kev": int(is_kev),
                 "epss": row["epss"], "percentile": row["percentile"], "epss_date": row["epss_date"], "kev_date": row["kev_date"], "rank": rank(row["severity"], is_kev, row["epss"]),
                 "confidence": round(confidence, 4), "status": "potential", "version_state": state, "reasons": encode(reasons),
                 "first_seen": timestamp, "last_seen": timestamp, "source_url": row["source_url"], "evidence": row["evidence"],
                 "vendor": row["vendor_name"], "product": row["product_name"], "version": row["version"],
                 "observed_at": row["observed_at"], "checked_token": token}
                key = (row["asset_id"], row["canonical_id"])
                previous = candidates.get(key)
                strengths = {"exact": 3, "affected_range": 2, "version_unverified": 1, "unknown": 0}
                if previous is None or (record["confidence"], strengths[state], record["rank"], record["observed_at"]) > (previous["confidence"], strengths[previous["version_state"]], previous["rank"], previous["observed_at"]):
                    candidates[key] = record
            conn.execute("CREATE TEMP TABLE alert_current(asset_id TEXT NOT NULL,advisory_id TEXT NOT NULL,PRIMARY KEY(asset_id,advisory_id))")
            conn.executemany("INSERT INTO alert_current(asset_id,advisory_id) VALUES(?,?)", candidates)
            existing_alerts = {row["id"] for row in conn.execute("SELECT id FROM alerts")}
            for current in candidates.values():
                if current["id"] not in existing_alerts:
                    self._event(conn, "warning_opened", "Potential exposure warning opened locally: " + current["advisory_id"], current["asset_id"], current["advisory_id"], "correlation", current.get("source_url") or "", timestamp, None, warning_event_state(current))
            for resolved in conn.execute("""SELECT alerts.* FROM alerts LEFT JOIN alert_current current
             ON current.asset_id=alerts.asset_id AND current.advisory_id=alerts.advisory_id WHERE current.asset_id IS NULL"""):
                self._event(conn, "warning_resolved", "Potential exposure warning cleared locally: " + resolved["advisory_id"], resolved["asset_id"], resolved["advisory_id"], "correlation", resolved["source_url"] or "", timestamp, warning_event_state(dict(resolved)), None)
            before = conn.execute("SELECT count(*) FROM alerts").fetchone()[0]
            if candidates:
                columns = list(next(iter(candidates.values())))
                updates = ",".join(f"{column}=excluded.{column}" for column in columns if column not in {"id", "asset_id", "advisory_id", "first_seen"})
                sql = "INSERT INTO alerts(" + ",".join(columns) + ") VALUES(" + ",".join("?" for _ in columns) + ") ON CONFLICT(asset_id,advisory_id) DO UPDATE SET " + updates
                conn.executemany(sql, (tuple(record[column] for column in columns) for record in candidates.values()))
            removed = conn.execute("DELETE FROM alerts WHERE checked_token!=?", (token,)).rowcount
        return {"evaluated": evaluated, "alerts": len(candidates), "removed": removed, "previous": before}

    def stats(self):
        with self.connection() as conn:
            counts = {name: conn.execute("SELECT count(*) FROM " + name).fetchone()[0] for name in ("entities", "edges", "advisories", "articles", "observations", "alerts", "kev", "epss", "crawl_urls", "events")}
            counts["advisory_documents"] = counts["advisories"]
            counts["advisories"] = conn.execute("SELECT count(DISTINCT a.canonical_id) FROM advisories a WHERE " + " AND ".join(ACTIVE_ADVISORY_FILTERS[:2])).fetchone()[0]
            counts["entity_kinds"] = {row[0]: row[1] for row in conn.execute("SELECT kind,count(*) FROM entities GROUP BY kind")}
            counts["kev_alerts"] = conn.execute("SELECT count(*) FROM alerts WHERE kev=1").fetchone()[0]
            counts["sources"] = conn.execute("SELECT count(*) FROM sources").fetchone()[0]
            return counts

    def _page(self, conn, table, where, values, order, limit, offset, select="*"):
        limit, offset = min(500, max(1, int(limit))), max(0, int(offset))
        suffix = " WHERE " + where if where else ""
        total = conn.execute("SELECT count(*) FROM " + table + suffix, values).fetchone()[0]
        rows = conn.execute("SELECT " + select + " FROM " + table + suffix + " ORDER BY " + order + " LIMIT ? OFFSET ?", (*values, limit, offset))
        return {"items": [decoded(row) for row in rows], "total": total}

    def search(self, q="", kind="", limit=50, offset=0):
        filters, values = [], []
        if q:
            expression = fts_query(q)
            if expression:
                filters.append("(e.rowid IN (SELECT rowid FROM entity_fts WHERE entity_fts MATCH ?) OR e.id IN (SELECT p.company_id FROM company_profiles p JOIN company_profile_fts ON p.rowid=company_profile_fts.rowid WHERE company_profile_fts MATCH ?))")
                values.extend((expression, expression))
        if kind:
            filters.append("e.kind=?")
            values.append(kind)
        with self.connection() as conn:
            result = self._page(conn, "entities e", " AND ".join(filters), values, "e.updated_at DESC,e.id", limit, offset,
                                "e.*,(SELECT name FROM company_profiles WHERE company_id=e.id) AS profile_name")
            for item in result["items"]:
                name = item.pop("profile_name", None)
                if name is not None:
                    item["name"] = name
            return result

    def save_company_profile(self, company_id="", name="", legal_name="", aliases=None, brands=None,
                             parent_company_id="", notes="", source_url=""):
        name = str(name).strip()
        if not name:
            raise ValueError("Company name is required")
        aliases, brands = labels(aliases if aliases is not None else []), labels(brands if brands is not None else [])
        timestamp = now()
        with self.connection(write=True) as conn:
            if company_id:
                company(conn, company_id)
            else:
                company_id = "company:manual:" + uuid.uuid4().hex
                self._entity(conn, {"id": company_id, "kind": "company", "name": name, "value": name,
                                    "metadata": {"origin": "manual"}, "source_url": source_url}, timestamp)
            validate_parent(conn, company_id, parent_company_id)
            conn.execute("""INSERT INTO company_profiles(company_id,name,legal_name,aliases,brands,parent_company_id,notes,source_url,updated_at)
             VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(company_id) DO UPDATE SET name=excluded.name,legal_name=excluded.legal_name,
             aliases=excluded.aliases,brands=excluded.brands,parent_company_id=excluded.parent_company_id,
             notes=excluded.notes,source_url=excluded.source_url,updated_at=excluded.updated_at""",
                         (company_id, name, str(legal_name).strip(), encode(aliases), encode(brands), parent_company_id,
                          notes, source_url, timestamp))
        return self.detail(company_id)

    def set_company_asset(self, company_id, asset_url, status="confirmed", role="owned", evidence="", source_url=""):
        if status not in {"confirmed", "candidate", "rejected", "automatic"}:
            raise ValueError("Invalid company asset status")
        if role not in {"owned", "service"}:
            raise ValueError("Invalid company asset role")
        if status != "automatic" and (not evidence.strip() or not source_url):
            raise ValueError("Manual company asset decisions require evidence and a source URL")
        asset_id, host = asset_identity(asset_url)
        timestamp = now()
        with self.connection(write=True) as conn:
            company(conn, company_id)
            if status == "automatic":
                conn.execute("DELETE FROM company_asset_decisions WHERE company_id=? AND asset_id=?", (company_id, asset_id))
            else:
                if conn.execute("SELECT 1 FROM entities WHERE id=?", (asset_id,)).fetchone() is None:
                    self._entity(conn, {"id": asset_id, "kind": "domain", "name": host, "value": host,
                                        "metadata": {}, "source_url": source_url}, timestamp)
                conn.execute("""INSERT INTO company_asset_decisions(company_id,asset_id,status,role,evidence,source_url,updated_at)
                 VALUES(?,?,?,?,?,?,?) ON CONFLICT(company_id,asset_id) DO UPDATE SET status=excluded.status,
                 role=excluded.role,evidence=excluded.evidence,source_url=excluded.source_url,updated_at=excluded.updated_at""",
                             (company_id, asset_id, status, role, evidence.strip(), source_url, timestamp))
        return self.detail(company_id)

    def advisories(self, q="", kev=False, limit=50, offset=0, *, sort="rank"):
        if sort not in {"rank", "newest"}:
            raise ValueError("Invalid advisory sort")
        filters = list(ACTIVE_ADVISORY_FILTERS)
        values = []
        if q and fts_query(q):
            filters.append("a.canonical_id IN (SELECT matched.canonical_id FROM advisory_fts JOIN advisories matched ON matched.rowid=advisory_fts.rowid WHERE advisory_fts MATCH ?)")
            values.append(fts_query(q))
        if kev:
            filters.append("k.cve IS NOT NULL")
        order = "rank DESC,a.modified DESC,a.id" if sort == "rank" else "a.modified DESC,rank DESC,a.id"
        with self.connection() as conn:
            return self._page(conn, ADVISORY_TABLE, " AND ".join(filters), values, order, limit, offset, ADVISORY_SELECT)

    def alerts(self, q="", limit=50, offset=0, *, kev=False, version_state="", sort="rank"):
        if sort not in {"rank", "newest"}:
            raise ValueError("Invalid alert sort")
        if version_state not in {"", "exact", "affected_range", "unknown", "version_unverified"}:
            raise ValueError("Invalid version state")
        filters, values = [], []
        if q:
            filters.append("(a.advisory_id LIKE ? OR a.title LIKE ? OR e.name LIKE ? OR a.product LIKE ? OR a.vendor LIKE ?)")
            values.extend(["%" + q + "%"] * 5)
        if kev:
            filters.append("a.kev=1")
        if version_state:
            filters.append("a.version_state=?")
            values.append(version_state)
        order = "a.rank DESC,a.last_seen DESC,a.id" if sort == "rank" else "a.first_seen DESC,a.rank DESC,a.id"
        with self.connection() as conn:
            return self._page(conn, "alerts a LEFT JOIN entities e ON e.id=a.asset_id", " AND ".join(filters), values, order, limit, offset, "a.*,e.name AS asset_name,e.kind AS asset_kind")

    def events(self, q="", kind="", limit=50, offset=0):
        filters, values = [], []
        if q:
            filters.append("(title LIKE ? OR subject_id LIKE ? OR canonical_id LIKE ? OR source LIKE ?)")
            values.extend(["%" + q + "%"] * 4)
        if kind:
            filters.append("kind=?")
            values.append(kind)
        with self.connection() as conn:
            return self._page(conn, "events", " AND ".join(filters), values, "observed_at DESC,id DESC", limit, offset,
             "id,kind,title,subject_id,canonical_id,source,url,observed_at,before_json AS before,after_json AS after")

    def event(self, event_id):
        with self.connection() as conn:
            return decoded(conn.execute("SELECT id,kind,title,subject_id,canonical_id,source,url,observed_at,before_json AS before,after_json AS after FROM events WHERE id=?", (event_id,)).fetchone())

    def prune_events(self, max_rows=50000, days=90):
        cutoff = (datetime.now(timezone.utc) - timedelta(days=max(0, float(days)))).isoformat(timespec="seconds")
        with self.connection(write=True) as conn:
            removed = conn.execute("DELETE FROM events WHERE julianday(observed_at)<julianday(?)", (cutoff,)).rowcount
            removed += conn.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY observed_at DESC,id DESC LIMIT ?)", (max(0, int(max_rows)),)).rowcount
            return removed

    def articles(self, q="", limit=50, offset=0):
        where, values = "", []
        if q and fts_query(q):
            where = "rowid IN (SELECT rowid FROM article_fts WHERE article_fts MATCH ?)"
            values = [fts_query(q)]
        with self.connection() as conn:
            return self._page(conn, "articles", where, values, "published DESC,id", limit, offset)

    def detail(self, entity_id):
        entity_id = identifier(entity_id)
        with self.connection() as conn:
            entity = decoded(conn.execute("SELECT * FROM entities WHERE id=?", (entity_id,)).fetchone())
            advisory = decoded(conn.execute("SELECT " + ADVISORY_SELECT + " FROM " + ADVISORY_TABLE + " WHERE a.id=?", (entity_id,)).fetchone())
            if advisory is None:
                alias = conn.execute("SELECT canonical_id FROM advisory_aliases WHERE alias=?", (entity_id,)).fetchone()
                canonical = alias[0] if alias else entity_id
                advisory = decoded(conn.execute("SELECT " + ADVISORY_SELECT + " FROM " + ADVISORY_TABLE + " WHERE a.canonical_id=? ORDER BY a.rejected,(a.id=a.canonical_id) DESC,a.modified DESC,a.id LIMIT 1", (canonical,)).fetchone())
            article = decoded(conn.execute("SELECT * FROM articles WHERE id=?", (entity_id,)).fetchone())
            if entity is None and advisory is None and article is None:
                return None
            result = dict(entity or advisory or article)
            relationship_ids = {entity_id}
            if advisory:
                result["advisory"] = advisory
                result["requested_id"] = entity_id
                result["canonical_id"] = advisory["canonical_id"]
                result["source_record_id"] = advisory["id"]
                relationship_ids.update((advisory["id"], advisory["canonical_id"]))
                result["aliases"] = [row[0] for row in conn.execute("SELECT alias FROM advisory_aliases WHERE canonical_id=? ORDER BY alias", (advisory["canonical_id"],))]
                result["articles"] = [decoded(row) for row in conn.execute("""SELECT DISTINCT articles.* FROM articles JOIN article_links l ON l.article_id=articles.id
                 LEFT JOIN advisory_aliases x ON x.alias=l.advisory_id WHERE coalesce(x.canonical_id,l.advisory_id)=? ORDER BY articles.published DESC LIMIT 200""", (advisory["canonical_id"],))]
            if article:
                result["article"] = article
            relationship_ids = sorted(relationship_ids)
            relationship_slots = ",".join("?" for _ in relationship_ids)
            result["relationships"] = [decoded(row) for row in conn.execute("""SELECT e.*,f.name AS from_name,t.name AS to_name FROM edges e
             LEFT JOIN entities f ON f.id=e.from_id LEFT JOIN entities t ON t.id=e.to_id
             WHERE e.from_id IN (""" + relationship_slots + ") OR e.to_id IN (" + relationship_slots + ") ORDER BY e.observed_at DESC,e.from_id,e.to_id LIMIT 500", (*relationship_ids, *relationship_ids))]
            asset_ids = {entity_id}
            if entity and entity.get("kind") == "company":
                result["company_profile"] = company_profile(conn, entity)
                result["wireless_summary"] = company_wireless_summary(conn, entity_id)
                result["name"] = result["company_profile"]["name"]
                profile = result["company_profile"]
                profile["assets"], profile["assets_truncated"] = company_assets(conn, entity_id)
                asset_ids.update(asset["id"] for asset in profile["assets"] if asset["included"])
            placeholders = ",".join("?" for _ in asset_ids)
            asset_ids = sorted(asset_ids)
            result["observations"] = [decoded(row) for row in conn.execute("SELECT * FROM observations WHERE asset_id IN (" + placeholders + ") ORDER BY observed_at DESC LIMIT 500", asset_ids)]
            result["alerts"] = [decoded(row) for row in conn.execute("SELECT * FROM alerts WHERE asset_id IN (" + placeholders + ") OR advisory_id=? ORDER BY rank DESC LIMIT 500", (*asset_ids, advisory["canonical_id"] if advisory else entity_id))]
            result["related_articles"] = self._related_articles(conn, entity_id, result["observations"], advisory, asset_ids)
            advisory_links = "a.canonical_id IN (SELECT advisory_id FROM alerts WHERE asset_id IN (" + placeholders + "))"
            advisory_values = list(asset_ids)
            if entity and entity.get("kind") in {"technology", "device", "os", "package"}:
                advisory_links += " OR a.canonical_id IN (SELECT coalesce(x.canonical_id,e.to_id) FROM edges e LEFT JOIN advisory_aliases x ON x.alias=e.to_id WHERE e.from_id=? AND e.relation='affected_by')"
                advisory_values.append(entity_id)
            advisory_where = " AND ".join(ACTIVE_ADVISORY_FILTERS) + " AND (" + advisory_links + ")"
            result["advisories"] = [decoded(row) for row in conn.execute("SELECT " + ADVISORY_SELECT + " FROM " + ADVISORY_TABLE + " WHERE " + advisory_where + " ORDER BY rank DESC,a.modified DESC,a.id LIMIT 200", advisory_values)]
            return result

    def _related_articles(self, conn, entity_id, observations, advisory=None, asset_ids=None):
        pairs = {(row["vendor"], row["product"]) for row in observations}
        entity = conn.execute("SELECT metadata FROM entities WHERE id=?", (entity_id,)).fetchone()
        if entity:
            metadata = json.loads(entity[0])
            vendor = metadata.get("vendor") or metadata.get("ecosystem")
            product = metadata.get("product") or metadata.get("package")
            if vendor and product:
                pairs.add((normalize(vendor), normalize(product)))
        phrases = set()
        generic = {"server", "client", "firmware", "system", "router", "enterprise", "software", "application", "network", "service", "device", "kernel", "platform", "package", "security", "hardware", "storage", "desktop", "gateway", "database"}
        for vendor, product in sorted(pairs)[:50]:
            vendor, product = normalize(vendor), normalize(product)
            words = (product if vendor == product or product.startswith(vendor + " ") else vendor + " " + product).split()
            if len(words) >= 2 and len(" ".join(words)) >= 8:
                phrases.add(" ".join(words))
            if " " not in product and len(product) >= 5 and product not in generic:
                phrases.add(product)
        phrases = sorted(phrases)[:100]
        found = {}
        if phrases:
            expression = " OR ".join('"' + phrase.replace('"', '""') + '"' for phrase in phrases)
            rows = conn.execute("SELECT articles.* FROM articles JOIN article_fts ON article_fts.rowid=articles.rowid WHERE article_fts MATCH ? ORDER BY published DESC LIMIT 100", (expression,))
            for row in rows:
                item = decoded(row)
                haystack = normalize(item["title"] + " " + item["summary"])
                matches = [phrase for phrase in phrases if re.search(r"(?<!\w)" + re.escape(phrase) + r"(?!\w)", haystack)]
                if matches:
                    item.update(match_type="product_mention", match_phrases=matches, status="candidate", reason="Exact observed vendor/product phrase appears in this article; impact is unverified.")
                    found[item["id"]] = item
        asset_ids = list(asset_ids or [entity_id])
        canonical_ids = {row[0] for row in conn.execute("SELECT advisory_id FROM alerts WHERE asset_id IN (" + ",".join("?" for _ in asset_ids) + ")", asset_ids)}
        if advisory:
            canonical_ids.add(advisory["canonical_id"])
        if canonical_ids:
            placeholders = ",".join("?" for _ in canonical_ids)
            rows = conn.execute("SELECT DISTINCT a.* FROM articles a JOIN article_links l ON l.article_id=a.id LEFT JOIN advisory_aliases x ON x.alias=l.advisory_id WHERE coalesce(x.canonical_id,l.advisory_id) IN (" + placeholders + ") ORDER BY a.published DESC LIMIT 100", sorted(canonical_ids))
            for row in rows:
                item = decoded(row)
                item.update(match_type="advisory_reference", status="candidate", reason="The article mentions an advisory associated with this entity; impact is unverified.")
                found[item["id"]] = item
        return sorted(found.values(), key=lambda item: item.get("published") or "", reverse=True)[:100]

    def network_targets(self, limit=100, refresh_hours=24):
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=float(refresh_hours))).isoformat(timespec="seconds")
        with self.connection() as conn:
            conn.create_function("public_ip", 1, public_ip, deterministic=True)
            rows = conn.execute("""SELECT * FROM entities WHERE kind='ip' AND public_ip(value)=1
             AND (julianday(json_extract(metadata,'$.network_enriched_at')) IS NULL
              OR julianday(json_extract(metadata,'$.network_enriched_at'))<julianday(?))
             ORDER BY coalesce(julianday(json_extract(metadata,'$.network_enriched_at')),0),id LIMIT ?""", (cutoff, max(1, int(limit))))
            return [decoded(row) for row in rows]

    def network_pending_count(self, refresh_hours=24):
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=float(refresh_hours))).isoformat(timespec="seconds")
        with self.connection() as conn:
            conn.create_function("public_ip", 1, public_ip, deterministic=True)
            return conn.execute("""SELECT count(*) FROM entities WHERE kind='ip' AND public_ip(value)=1
             AND (julianday(json_extract(metadata,'$.network_enriched_at')) IS NULL
              OR julianday(json_extract(metadata,'$.network_enriched_at'))<julianday(?))""", (cutoff,)).fetchone()[0]

    def sources(self):
        with self.connection() as conn:
            return [{"name": row["name"], **json.loads(row["state"])} for row in conn.execute("SELECT * FROM sources ORDER BY name")]

    def source_state(self, name):
        with self.connection() as conn:
            row = conn.execute("SELECT state FROM sources WHERE name=?", (name,)).fetchone()
            return json.loads(row[0]) if row else {}

    def update_source(self, name, **fields):
        with self.connection(write=True) as conn:
            row = conn.execute("SELECT state FROM sources WHERE name=?", (name,)).fetchone()
            state = json.loads(row[0]) if row else {}
            state.update(fields)
            conn.execute("INSERT INTO sources(name,state) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET state=excluded.state", (name, encode(state)))
        return state

    def enqueue_url(self, url, source_url="", company_id=None):
        with self.connection(write=True) as conn:
            conn.execute("""INSERT INTO crawl_urls(url,source_url,company_id) VALUES(?,?,?) ON CONFLICT(url) DO UPDATE SET
             source_url=CASE WHEN crawl_urls.source_url='' OR excluded.source_url IN ('configured-seed','user-seed') THEN excluded.source_url ELSE crawl_urls.source_url END,
             company_id=coalesce(crawl_urls.company_id,excluded.company_id)""", (url, source_url or "", company_id))

    def crawl_targets(self, limit=100, refresh_hours=24):
        timestamp = now()
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=float(refresh_hours))).isoformat(timespec="seconds")
        lease_cutoff = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat(timespec="seconds")
        with self.connection(write=True) as conn:
            rows = [dict(row) for row in conn.execute("""SELECT * FROM crawl_urls WHERE status='queued'
             OR (status IN ('done','error') AND (last_fetched IS NULL OR last_fetched<?))
             OR (status='fetching' AND leased_at<?) ORDER BY CASE WHEN source_url IN ('configured-seed','user-seed') THEN 0 WHEN company_id IS NOT NULL THEN 1 ELSE 2 END,coalesce(last_fetched,''),url LIMIT ?""", (cutoff, lease_cutoff, max(1, int(limit))))]
            conn.executemany("UPDATE crawl_urls SET status='fetching',leased_at=? WHERE url=?", ((timestamp, row["url"]) for row in rows))
            return rows

    def finish_url(self, url, error=None):
        with self.connection(write=True) as conn:
            conn.execute("UPDATE crawl_urls SET status=?,last_fetched=?,leased_at=NULL,error=? WHERE url=?", ("error" if error else "done", now(), str(error) if error else None, url))
