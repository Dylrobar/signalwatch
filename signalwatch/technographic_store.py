import hashlib
import json
import re

from bs4 import BeautifulSoup

from .extract import canonical_url


SCHEMA = """
CREATE TABLE IF NOT EXISTS technographic_documents (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, content_hash TEXT NOT NULL,
 title TEXT NOT NULL, raw_excerpt TEXT NOT NULL, published_at TEXT,
 first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
 UNIQUE(organization_id,content_hash)
);
CREATE TABLE IF NOT EXISTS technographic_sources (
 organization_id TEXT NOT NULL, source_entity_id TEXT NOT NULL, document_id TEXT NOT NULL,
 source_url TEXT NOT NULL, url_hash TEXT NOT NULL, endpoint_url TEXT NOT NULL,
 source_type TEXT NOT NULL, first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
 PRIMARY KEY(organization_id,source_entity_id)
);
CREATE INDEX IF NOT EXISTS technographic_source_document ON technographic_sources(document_id,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS technographic_source_endpoint ON technographic_sources(endpoint_url,organization_id);
CREATE TABLE IF NOT EXISTS tech_fingerprints (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, document_id TEXT NOT NULL,
 vendor TEXT NOT NULL, product TEXT NOT NULL, vendor_name TEXT NOT NULL,
 product_name TEXT NOT NULL, category TEXT NOT NULL, part TEXT NOT NULL,
 version TEXT NOT NULL DEFAULT '', cpe TEXT, status TEXT NOT NULL,
 confidence REAL NOT NULL, evidence_snippet TEXT NOT NULL, method TEXT NOT NULL,
 first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS tech_fingerprints_org ON tech_fingerprints(organization_id,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS tech_fingerprints_document ON tech_fingerprints(document_id);
CREATE INDEX IF NOT EXISTS tech_fingerprints_product ON tech_fingerprints(vendor,product,status);
"""

_DNS_PROVIDERS = (
    ("Google", "google", r"google-site-verification\s*="),
    ("Microsoft", "microsoft", r"(?<!\w)MS=ms\w+"),
    ("Atlassian", "atlassian", r"atlassian-domain-verification\s*="),
    ("KnowBe4", "knowbe4", r"knowbe4-site-verification\s*="),
    ("DocuSign", "docusign", r"docusign(?:-domain-verification)?\s*="),
    ("Slack", "slack", r"slack-domain-verification\s*="),
    ("Okta", "okta", r"okta-domain-verification\s*="),
)
_DNS_SIGNATURES = [(name, vendor, re.compile(pattern, re.I)) for name, vendor, pattern in _DNS_PROVIDERS]


def document_input(entity):
    metadata = entity.get("metadata") or {}
    if entity.get("kind") == "source_record" and metadata.get("provider") == "dns_txt":
        record = metadata.get("provider_fields") or {}
        if not isinstance(record, dict) or not isinstance(record.get("data"), str) or not any(pattern.search(record["data"]) for _, _, pattern in _DNS_SIGNATURES):
            return None
        context = {"domain": metadata.get("target_domain")}
        fields = {"title": "DNS TXT: " + str(record.get("name") or metadata.get("target_domain")), "description": record["data"]}
    elif entity.get("kind") in {"job_posting", "company_article"}:
        context, fields = metadata.get("company_context") or {}, metadata.get("fields") or {}
    else:
        return None
    if not isinstance(context, dict) or not isinstance(fields, dict):
        return None
    title = str(fields.get("title") or fields.get("text") or entity.get("name") or "")
    body = str(fields.get("description") or fields.get("summary") or fields.get("content") or "")
    body = BeautifulSoup(body, "html.parser").get_text("\n") if "<" in body else body
    paragraphs = [" ".join(value.split()) for value in re.split(r"\n+", title + "\n" + body)]
    text = "\n".join(value for value in paragraphs if value)[:64000]
    url = canonical_url(str(fields.get("url") or fields.get("absolute_url") or fields.get("hostedUrl") or entity.get("source_url") or ""))
    if not url or not text:
        return None
    return {"organization_context": context, "title": title[:1000], "text": text,
            "source_url": url, "url_hash": hashlib.sha256(url.encode()).hexdigest(),
            "endpoint_url": entity.get("source_url") or url, "source_type": metadata.get("provider") or entity["kind"],
            "published_at": fields.get("published_at"), "content_hash": hashlib.sha256(text.encode()).hexdigest()}


def organization(conn, context):
    key = context.get("company_id")
    if key:
        row = conn.execute("SELECT id FROM entities WHERE id=? AND kind='company'", (key,)).fetchone()
        return row[0] if row else None
    domain = str(context.get("domain") or "").lower().rstrip(".").removeprefix("www.")
    if not domain:
        return None
    rows = conn.execute("""SELECT DISTINCT c.id FROM entities c JOIN edges e ON e.from_id=c.id
     WHERE c.kind='company' AND e.relation='official_website' AND e.to_id IN (?,?) LIMIT 2""",
                        ("domain:" + domain, "domain:www." + domain)).fetchall()
    return rows[0][0] if len(rows) == 1 else None


def document_seen(conn, context, content_hash):
    company_id = organization(conn, context)
    return bool(company_id and conn.execute("SELECT 1 FROM technographic_documents WHERE organization_id=? AND content_hash=?",
                                           (company_id, content_hash)).fetchone())


def project(store, conn, entity, timestamp):
    from .technographics import extract

    doc = document_input(entity)
    if doc is None:
        return {}
    company_id = organization(conn, doc["organization_context"])
    if company_id is None:
        return {"technographic_unattributed": 1}
    document_id = "technographic_document:" + hashlib.sha256((company_id + "\0" + doc["content_hash"]).encode()).hexdigest()
    previous = conn.execute("SELECT document_id FROM technographic_sources WHERE organization_id=? AND source_entity_id=?",
                            (company_id, entity["id"])).fetchone()
    duplicate = conn.execute("SELECT 1 FROM technographic_documents WHERE id=?", (document_id,)).fetchone() is not None
    conn.execute("""INSERT INTO technographic_documents VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id)
     DO UPDATE SET last_seen_at=max(technographic_documents.last_seen_at,excluded.last_seen_at)""",
                 (document_id, company_id, doc["content_hash"], doc["title"], doc["text"][:2000], doc["published_at"], timestamp, timestamp))
    conn.execute("""INSERT INTO technographic_sources VALUES(?,?,?,?,?,?,?,?,?)
     ON CONFLICT(organization_id,source_entity_id) DO UPDATE SET document_id=excluded.document_id,
     source_url=excluded.source_url,url_hash=excluded.url_hash,endpoint_url=excluded.endpoint_url,
     source_type=excluded.source_type,last_seen_at=excluded.last_seen_at""",
                 (company_id, entity["id"], document_id, doc["source_url"], doc["url_hash"], doc["endpoint_url"], doc["source_type"], timestamp, timestamp))
    if previous and previous[0] != document_id and not conn.execute("SELECT 1 FROM technographic_sources WHERE document_id=?", (previous[0],)).fetchone():
        _clear_projection(store, conn, company_id, previous[0], timestamp)
    if duplicate:
        conn.execute("UPDATE tech_fingerprints SET last_seen_at=max(last_seen_at,?) WHERE document_id=?", (timestamp, document_id))
        _graph(store, conn, entity["id"], document_id, doc["source_url"], timestamp)
        if not previous or previous[0] != document_id:
            _observations(store, conn, company_id, document_id, timestamp)
        return {"technographic_duplicates": 1}
    if doc["source_type"] == "dns_txt":
        findings = [{"vendor": vendor, "vendor_name": name, "product": "domain verification", "product_name": name + " domain verification",
                     "category": "SaaS verification", "part": "a", "version": "", "cpe": None, "status": "domain_verification",
                     "confidence": 1.0, "evidence_snippet": doc["text"][:600], "method": "dns-verification-v1"}
                    for name, vendor, pattern in _DNS_SIGNATURES if pattern.search(doc["text"])]
    else:
        findings = extract(doc["text"], source_type=doc["source_type"])
    verification = (entity.get("metadata") or {}).get("technographic_verification") or {}
    if verification.get("content_hash") == doc["content_hash"]:
        for checked in verification.get("findings", []):
            index = checked.get("index")
            if (type(index) is int and 0 <= index < len(findings)
                    and checked.get("status") in {"asserted_use", "requirement", "alternative", "negated", "historical", "planned", "mention"}
                    and isinstance(checked.get("confidence"), (float, int)) and 0 <= checked["confidence"] <= 1
                    and (checked["status"] != "asserted_use" or findings[index]["status"] == "asserted_use")):
                findings[index] = {**findings[index], **{key: checked[key] for key in ("status", "confidence", "method")}}
    for finding in findings:
        fingerprint_id = "tech_fingerprint:" + hashlib.sha256(json.dumps([document_id, finding["vendor"], finding["product"], finding.get("version"), finding["status"], finding["evidence_snippet"]], ensure_ascii=False).encode()).hexdigest()
        conn.execute("""INSERT INTO tech_fingerprints VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (fingerprint_id, company_id, document_id, finding["vendor"], finding["product"], finding["vendor_name"],
                      finding["product_name"], finding["category"], finding["part"], finding.get("version") or "", finding.get("cpe"),
                      finding["status"], finding["confidence"], finding["evidence_snippet"], finding["method"], timestamp, timestamp))
    store._edge(conn, {"from_id": company_id, "to_id": entity["id"], "relation": "has_public_evidence",
                       "source_url": doc["source_url"], "confidence": 1.0}, timestamp)
    _graph(store, conn, entity["id"], document_id, doc["source_url"], timestamp)
    _observations(store, conn, company_id, document_id, timestamp)
    return {"technographic_documents": 1, "tech_fingerprints": len(findings)}


def _graph(store, conn, entity_id, document_id, source_url, timestamp):
    conn.execute("DELETE FROM edges WHERE from_id=? AND relation LIKE 'technology_%'", (entity_id,))
    for finding in conn.execute("SELECT * FROM tech_fingerprints WHERE document_id=?", (document_id,)):
        key = "technographic_product:" + hashlib.sha256((finding["vendor"] + "\0" + finding["product"]).encode()).hexdigest()
        store._entity(conn, {"id": key, "kind": "technology", "name": finding["product_name"],
                            "metadata": {"vendor": finding["vendor"], "product": finding["product"], "evidence_role": "textual_technology_label"},
                            "source_url": source_url}, timestamp)
        store._edge(conn, {"from_id": entity_id, "to_id": key, "relation": "technology_" + finding["status"],
                           "source_url": source_url, "confidence": finding["confidence"]}, timestamp)


def _clear_projection(store, conn, company_id, document_id, timestamp):
    store.ingest({"observation_snapshots": [{"asset_id": company_id, "origin": "technographic:" + document_id}]}, conn=conn)


def _observations(store, conn, company_id, document_id, timestamp):
    source = conn.execute("SELECT source_url FROM technographic_sources WHERE document_id=? ORDER BY last_seen_at DESC,source_url LIMIT 1", (document_id,)).fetchone()
    if source is None:
        return
    observations = []
    for finding in conn.execute("SELECT * FROM tech_fingerprints WHERE document_id=? AND status='asserted_use'", (document_id,)):
        observations.append({"asset_id": company_id, "vendor": finding["vendor"], "product": finding["product"],
                             "part": finding["part"], "version": finding["version"], "cpe": finding["cpe"],
                             "origin": "technographic:" + document_id, "source_url": source[0], "observed_at": timestamp,
                             "confidence": finding["confidence"], "evidence": finding["evidence_snippet"],
                             "evidence_role": "public_text_assertion", "deployment_verified": False, "method": finding["method"]})
    store.ingest({"observation_snapshots": [{"asset_id": company_id, "origin": "technographic:" + document_id}], "observations": observations}, conn=conn)


def touch_source(conn, source_url, context, timestamp):
    company_id = organization(conn, context)
    if company_id is None:
        return 0
    documents = [row[0] for row in conn.execute("SELECT DISTINCT document_id FROM technographic_sources WHERE endpoint_url=? AND organization_id=?", (source_url, company_id))]
    conn.execute("UPDATE technographic_sources SET last_seen_at=max(last_seen_at,?) WHERE endpoint_url=? AND organization_id=?", (timestamp, source_url, company_id))
    for key in documents:
        conn.execute("UPDATE technographic_documents SET last_seen_at=max(last_seen_at,?) WHERE id=?", (timestamp, key))
        conn.execute("UPDATE tech_fingerprints SET last_seen_at=max(last_seen_at,?) WHERE document_id=?", (timestamp, key))
    return len(documents)


def company_evidence(conn, company_id, limit=100):
    rows = conn.execute("""SELECT f.*,d.title AS document_title,d.published_at,
     (SELECT source_url FROM technographic_sources s WHERE s.document_id=d.id ORDER BY last_seen_at DESC,source_url LIMIT 1) AS source_url,
     (SELECT source_type FROM technographic_sources s WHERE s.document_id=d.id ORDER BY last_seen_at DESC,source_url LIMIT 1) AS source_type
     FROM tech_fingerprints f JOIN technographic_documents d ON d.id=f.document_id
     WHERE f.organization_id=? AND EXISTS (SELECT 1 FROM technographic_sources s WHERE s.document_id=d.id)
     ORDER BY f.last_seen_at DESC,f.id LIMIT ?""", (company_id, limit + 1)).fetchall()
    total = conn.execute("""SELECT count(*) FROM tech_fingerprints f WHERE organization_id=?
     AND EXISTS (SELECT 1 FROM technographic_sources s WHERE s.document_id=f.document_id)""", (company_id,)).fetchone()[0]
    documents = conn.execute("SELECT count(DISTINCT document_id) FROM technographic_sources WHERE organization_id=?", (company_id,)).fetchone()[0]
    return {"documents": documents, "fingerprints": [dict(row) for row in rows[:limit]], "total": total, "truncated": len(rows) > limit}
