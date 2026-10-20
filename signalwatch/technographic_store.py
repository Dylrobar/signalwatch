import hashlib
import json
import math
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
CREATE INDEX IF NOT EXISTS technographic_source_entity ON technographic_sources(source_entity_id);
CREATE TABLE IF NOT EXISTS tech_fingerprints (
 id TEXT PRIMARY KEY, organization_id TEXT NOT NULL, document_id TEXT NOT NULL,
 vendor TEXT NOT NULL, product TEXT NOT NULL, vendor_name TEXT NOT NULL,
 product_name TEXT NOT NULL, category TEXT NOT NULL, part TEXT NOT NULL,
 version TEXT NOT NULL DEFAULT '', cpe TEXT, status TEXT NOT NULL,
 confidence REAL NOT NULL, evidence_snippet TEXT NOT NULL, method TEXT NOT NULL,
 first_seen_at TEXT NOT NULL, last_seen_at TEXT NOT NULL,
 evidence_details TEXT NOT NULL DEFAULT '{}'
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
_HTTP_STATUSES = {"http_detected", "implied_dependency", "csp_integration"}
_HTTP_DETAILS = ("evidence_type", "implied_by", "csp_directive", "matched_host")


def ensure_schema(conn):
    if "evidence_details" not in {row[1] for row in conn.execute("PRAGMA table_info(tech_fingerprints)")}:
        conn.execute("ALTER TABLE tech_fingerprints ADD COLUMN evidence_details TEXT NOT NULL DEFAULT '{}'")


def _http_document(entity, metadata):
    from .companies import asset_identity

    url = canonical_url(str(entity.get("source_url") or ""))
    if not url:
        return None
    asset_id, domain = asset_identity(url)
    findings = metadata.get("fingerprints")
    if not isinstance(findings, list) or len(findings) > 500:
        raise ValueError("HTTP fingerprint evidence requires a bounded findings array")
    retained = {}
    for finding in findings:
        if (not isinstance(finding, dict) or finding.get("status") not in _HTTP_STATUSES
                or not all(isinstance(finding.get(key), str) and finding[key] for key in ("vendor", "product", "evidence_snippet"))):
            raise ValueError("Invalid HTTP fingerprint finding")
        confidence = finding.get("confidence", 0.0)
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise ValueError("Invalid HTTP fingerprint confidence")
        value = {key: str(finding.get(key) or "")[:2000] for key in
                 ("vendor", "product", "vendor_name", "product_name", "category", "version", "evidence_snippet")}
        value.update(vendor_name=value["vendor_name"] or value["vendor"], product_name=value["product_name"] or value["product"],
                     part=finding.get("part") if finding.get("part") in {"a", "o", "h"} else "a",
                     cpe=str(finding["cpe"])[:1000] if finding.get("cpe") else None,
                     status=finding["status"], confidence=confidence,
                     method="projectdiscovery_wappalyzer" if finding.get("method") == "projectdiscovery_wappalyzer" else "http_fingerprint_v1")
        if value["status"] != "http_detected":
            value.update(version="", cpe=None)
        if value["method"] == "projectdiscovery_wappalyzer":
            value["cpe"] = None
        details = {"asset_id": asset_id}
        for key in _HTTP_DETAILS:
            detail = finding.get(key)
            if isinstance(detail, str):
                details[key] = detail[:1000]
            elif key == "implied_by" and isinstance(detail, list):
                details[key] = [str(name)[:200] for name in detail[:20]]
        value["evidence_details"] = details
        identity = json.dumps([value[key] for key in ("vendor", "product", "version", "status", "evidence_snippet", "method", "part", "cpe", "evidence_details")],
                              sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if identity not in retained or confidence > retained[identity]["confidence"]:
            retained[identity] = value
    retained = list(retained.values())
    # A page's own evidence remains distinct from an identical response on a
    # different host. Collection time is deliberately outside the content hash.
    content = json.dumps({"source_url": url, "findings": retained}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    title = "HTTP technology evidence: " + domain
    text = title + "\n" + "\n".join(finding["evidence_snippet"] for finding in retained)
    return {"organization_context": {"domain": domain}, "asset_id": asset_id,
            "title": title, "text": text, "source_url": url,
            "url_hash": hashlib.sha256(url.encode()).hexdigest(), "endpoint_url": url,
            "source_type": "http_fingerprint", "published_at": None,
            "content_hash": hashlib.sha256(content.encode()).hexdigest(), "findings": retained}


def document_input(entity):
    metadata = entity.get("metadata") or {}
    if entity.get("kind") == "web_fingerprint":
        return _http_document(entity, metadata)
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


def _domain(context):
    return str(context.get("domain") or "").strip().lower().rstrip(".").removeprefix("www.")


def _excluded(conn, company_id, domain):
    return bool(domain and conn.execute("""SELECT 1 FROM company_asset_decisions
     WHERE company_id=? AND asset_id IN (?,?) AND (status!='confirmed' OR role!='owned') LIMIT 1""",
     (company_id, "domain:" + domain, "domain:www." + domain)).fetchone())


def organization(conn, context):
    domain = _domain(context)
    key = context.get("company_id")
    if key:
        row = conn.execute("SELECT id FROM entities WHERE id=? AND kind='company'", (key,)).fetchone()
        return row[0] if row and not _excluded(conn, key, domain) else None
    if not domain:
        return None
    rows = conn.execute("""SELECT DISTINCT c.id FROM entities c JOIN (
      SELECT from_id AS company_id FROM edges WHERE relation='official_website' AND to_id IN (?,?)
      UNION SELECT company_id FROM company_asset_decisions
       WHERE asset_id IN (?,?) AND status='confirmed' AND role='owned'
     ) association ON association.company_id=c.id
     WHERE c.kind='company' AND NOT EXISTS (SELECT 1 FROM company_asset_decisions rejected
      WHERE rejected.company_id=c.id AND rejected.asset_id IN (?,?)
       AND (rejected.status!='confirmed' OR rejected.role!='owned')) LIMIT 2""",
     ("domain:" + domain, "domain:www." + domain) * 3).fetchall()
    return rows[0][0] if len(rows) == 1 else None


def _http_organization(conn, asset_id):
    from .companies import company_assets

    domain = asset_id.removeprefix("domain:")
    apex = domain.removeprefix("www.")
    candidates = conn.execute("""SELECT DISTINCT association.company_id FROM (
     SELECT from_id AS company_id FROM edges WHERE relation='official_website' AND to_id IN (?,?)
     UNION SELECT company_id FROM company_asset_decisions WHERE asset_id IN (?,?)
    ) association JOIN entities c ON c.id=association.company_id AND c.kind='company'
    ORDER BY association.company_id""", ("domain:" + apex, "domain:www." + apex) * 2).fetchall()
    owners = []
    for (company_id,) in candidates:
        # Exact manual/official decisions must not disappear merely because
        # the bounded UI asset graph omitted this host from its first page.
        decision = conn.execute("SELECT status,role FROM company_asset_decisions WHERE company_id=? AND asset_id=?",
                                (company_id, asset_id)).fetchone()
        if decision is not None:
            included = tuple(decision) == ("confirmed", "owned")
        elif conn.execute("SELECT 1 FROM edges WHERE from_id=? AND to_id=? AND relation='official_website' LIMIT 1",
                          (company_id, asset_id)).fetchone():
            included = True
        else:
            assets, _ = company_assets(conn, company_id)
            included = any(asset["id"] == asset_id and asset["included"] for asset in assets)
        if included:
            owners.append(company_id)
            if len(owners) > 1:
                return None
    return owners[0] if len(owners) == 1 else None


def enrichment_targets(conn, limit):
    rows = conn.execute("""WITH associations AS (
      SELECT e.from_id AS company_id,e.to_id AS asset_id FROM edges e WHERE e.relation='official_website'
      UNION SELECT company_id,asset_id FROM company_asset_decisions WHERE status='confirmed' AND role='owned'
     ), domains AS (
      SELECT c.id AS company_id,c.name,lower(rtrim(d.value,'.')) AS domain,
       CASE WHEN lower(d.value) LIKE 'www.%' THEN substr(lower(rtrim(d.value,'.')),5)
        ELSE lower(rtrim(d.value,'.')) END AS canonical_domain
      FROM associations a JOIN entities c ON c.id=a.company_id AND c.kind='company'
      JOIN entities d ON d.id=a.asset_id AND d.kind='domain'
     ), included AS (
      SELECT * FROM domains d WHERE NOT EXISTS (SELECT 1 FROM company_asset_decisions rejected
       WHERE rejected.company_id=d.company_id
        AND rejected.asset_id IN ('domain:'||d.canonical_domain,'domain:www.'||d.canonical_domain)
        AND (rejected.status!='confirmed' OR rejected.role!='owned'))
     ), owners AS (
      SELECT canonical_domain,CASE WHEN count(DISTINCT company_id)=1 THEN min(company_id) ELSE '' END AS company_id,
       CASE WHEN count(DISTINCT company_id)=1 THEN min(name) ELSE '' END AS name
      FROM included GROUP BY canonical_domain
     ) SELECT DISTINCT i.domain,o.company_id,o.name FROM included i
      JOIN owners o ON o.canonical_domain=i.canonical_domain ORDER BY i.domain LIMIT ?""", (max(1, int(limit)),))
    return [dict(row) for row in rows]


def reproject_domain(store, conn, asset_id):
    """Apply a manual decision to retained evidence without changing its source record."""
    domain = asset_id.removeprefix("domain:").removeprefix("www.")
    rows = conn.execute("""SELECT * FROM entities WHERE kind IN ('job_posting','company_article','source_record','web_fingerprint')
     AND lower(rtrim(coalesce(json_extract(metadata,'$.company_context.domain'),
      json_extract(metadata,'$.target_domain'),''),'.')) IN (?,?)""", (domain, "www." + domain)).fetchall()
    affected = set()
    for row in rows:
        entity = dict(row)
        entity["metadata"] = json.loads(entity["metadata"])
        affected.update(item[0] for item in conn.execute("SELECT organization_id FROM technographic_sources WHERE source_entity_id=?", (entity["id"],)))
        project(store, conn, entity, entity["updated_at"])
        affected.update(item[0] for item in conn.execute("SELECT organization_id FROM technographic_sources WHERE source_entity_id=?", (entity["id"],)))
    return affected


def document_seen(conn, context, content_hash):
    company_id = organization(conn, context)
    return bool(company_id and conn.execute("SELECT 1 FROM technographic_documents WHERE organization_id=? AND content_hash=?",
                                           (company_id, content_hash)).fetchone())


def project(store, conn, entity, timestamp):
    from .technographics import extract

    # Entity updates merge metadata; attribution must use that retained state,
    # not interpret an omitted field in a partial refresh as its removal.
    if entity.get("kind") in {"job_posting", "company_article", "source_record", "web_fingerprint"}:
        saved = conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone()
        if saved is not None:
            entity = dict(saved)
            entity["metadata"] = json.loads(entity["metadata"])
    doc = document_input(entity)
    if doc is None:
        if conn.execute("SELECT 1 FROM technographic_sources WHERE source_entity_id=?", (entity["id"],)).fetchone():
            _detach_sources(store, conn, entity["id"], None, None, timestamp)
        return {}
    company_id = (_http_organization(conn, doc["asset_id"]) if doc["source_type"] == "http_fingerprint"
                  else organization(conn, doc["organization_context"]))
    document_id = ("technographic_document:" + hashlib.sha256((company_id + "\0" + doc["content_hash"]).encode()).hexdigest()) if company_id else None
    _detach_sources(store, conn, entity["id"], company_id, document_id, timestamp)
    if company_id is None:
        return {"technographic_unattributed": 1}
    duplicate = conn.execute("SELECT 1 FROM technographic_documents WHERE id=?", (document_id,)).fetchone() is not None
    conn.execute("""INSERT INTO technographic_documents VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id)
     DO UPDATE SET last_seen_at=max(technographic_documents.last_seen_at,excluded.last_seen_at)""",
                 (document_id, company_id, doc["content_hash"], doc["title"], doc["text"][:2000], doc["published_at"], timestamp, timestamp))
    conn.execute("""INSERT INTO technographic_sources VALUES(?,?,?,?,?,?,?,?,?)
     ON CONFLICT(organization_id,source_entity_id) DO UPDATE SET document_id=excluded.document_id,
     source_url=excluded.source_url,url_hash=excluded.url_hash,endpoint_url=excluded.endpoint_url,
     source_type=excluded.source_type,last_seen_at=excluded.last_seen_at""",
                 (company_id, entity["id"], document_id, doc["source_url"], doc["url_hash"], doc["endpoint_url"], doc["source_type"], timestamp, timestamp))
    store._edge(conn, {"from_id": company_id, "to_id": entity["id"], "relation": "has_public_evidence",
                       "source_url": doc["source_url"], "confidence": 1.0}, timestamp)
    if duplicate:
        conn.execute("UPDATE tech_fingerprints SET last_seen_at=max(last_seen_at,?) WHERE document_id=?", (timestamp, document_id))
        _graph(store, conn, entity["id"], document_id, doc["source_url"], timestamp)
        _observations(store, conn, company_id, document_id, timestamp)
        return {"technographic_duplicates": 1}
    if doc["source_type"] == "http_fingerprint":
        findings = doc["findings"]
    elif doc["source_type"] == "dns_txt":
        findings = [{"vendor": vendor, "vendor_name": name, "product": "domain verification", "product_name": name + " domain verification",
                     "category": "SaaS verification", "part": "a", "version": "", "cpe": None, "status": "domain_verification",
                     "confidence": 1.0, "evidence_snippet": doc["text"][:600], "method": "dns-verification-v1"}
                    for name, vendor, pattern in _DNS_SIGNATURES if pattern.search(doc["text"])]
    else:
        findings = extract(doc["text"], source_type=doc["source_type"])
    verification = (entity.get("metadata") or {}).get("technographic_verification") or {}
    if doc["source_type"] != "http_fingerprint" and verification.get("content_hash") == doc["content_hash"]:
        for checked in verification.get("findings", []):
            index = checked.get("index")
            if (type(index) is int and 0 <= index < len(findings)
                    and checked.get("status") in {"asserted_use", "requirement", "alternative", "negated", "historical", "planned", "mention"}
                    and isinstance(checked.get("confidence"), (float, int)) and 0 <= checked["confidence"] <= 1
                    and (checked["status"] != "asserted_use" or findings[index]["status"] == "asserted_use")):
                findings[index] = {**findings[index], **{key: checked[key] for key in ("status", "confidence", "method")}}
    for finding in findings:
        details = finding.get("evidence_details") or {}
        identity = [document_id, finding["vendor"], finding["product"], finding.get("version"), finding["status"], finding["evidence_snippet"]]
        if details:
            identity.extend((finding["method"], finding["part"], finding.get("cpe"), details))
        fingerprint_id = "tech_fingerprint:" + hashlib.sha256(json.dumps(identity, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        conn.execute("""INSERT INTO tech_fingerprints(id,organization_id,document_id,vendor,product,vendor_name,
         product_name,category,part,version,cpe,status,confidence,evidence_snippet,method,first_seen_at,last_seen_at,evidence_details)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                     (fingerprint_id, company_id, document_id, finding["vendor"], finding["product"], finding["vendor_name"],
                      finding["product_name"], finding["category"], finding["part"], finding.get("version") or "", finding.get("cpe"),
                      finding["status"], finding["confidence"], finding["evidence_snippet"], finding["method"], timestamp, timestamp,
                      json.dumps(details, sort_keys=True, separators=(",", ":"))))
    _graph(store, conn, entity["id"], document_id, doc["source_url"], timestamp)
    _observations(store, conn, company_id, document_id, timestamp)
    return {"technographic_documents": 1, "tech_fingerprints": len(findings)}


def _detach_sources(store, conn, entity_id, company_id, document_id, timestamp):
    previous = conn.execute("SELECT organization_id,document_id FROM technographic_sources WHERE source_entity_id=?", (entity_id,)).fetchall()
    for old_company, old_document in previous:
        if (old_company, old_document) == (company_id, document_id):
            continue
        conn.execute("DELETE FROM technographic_sources WHERE organization_id=? AND source_entity_id=?", (old_company, entity_id))
        if not conn.execute("SELECT 1 FROM technographic_sources WHERE document_id=?", (old_document,)).fetchone():
            _clear_projection(store, conn, old_company, old_document, timestamp)
        else:
            _observations(store, conn, old_company, old_document, timestamp)
    conn.execute("""DELETE FROM edges WHERE to_id=? AND relation='has_public_evidence'
     AND from_id IN (SELECT id FROM entities WHERE kind='company') AND (? IS NULL OR from_id!=?)""",
                 (entity_id, company_id, company_id))
    if company_id is None:
        conn.execute("DELETE FROM edges WHERE from_id=? AND relation LIKE 'technology_%'", (entity_id,))


def _graph(store, conn, entity_id, document_id, source_url, timestamp):
    conn.execute("DELETE FROM edges WHERE from_id=? AND relation LIKE 'technology_%'", (entity_id,))
    for finding in conn.execute("SELECT * FROM tech_fingerprints WHERE document_id=?", (document_id,)):
        key = "technographic_product:" + hashlib.sha256((finding["vendor"] + "\0" + finding["product"]).encode()).hexdigest()
        role = "http_technology_label" if finding["status"] in _HTTP_STATUSES else "textual_technology_label"
        store._entity(conn, {"id": key, "kind": "technology", "name": finding["product_name"],
                            "metadata": {"vendor": finding["vendor"], "product": finding["product"], "evidence_role": role},
                            "source_url": source_url}, timestamp)
        store._edge(conn, {"from_id": entity_id, "to_id": key, "relation": "technology_" + finding["status"],
                           "source_url": source_url, "confidence": finding["confidence"]}, timestamp)


def _clear_projection(store, conn, company_id, document_id, timestamp):
    store.ingest({"observation_snapshots": [{"asset_id": company_id, "origin": "technographic:" + document_id}]}, conn=conn)


def _observations(store, conn, company_id, document_id, timestamp):
    source = conn.execute("SELECT source_url,last_seen_at FROM technographic_sources WHERE document_id=? ORDER BY last_seen_at DESC,source_url LIMIT 1", (document_id,)).fetchone()
    if source is None:
        return
    observations = []
    for finding in conn.execute("SELECT * FROM tech_fingerprints WHERE document_id=? AND status='asserted_use'", (document_id,)):
        observations.append({"asset_id": company_id, "vendor": finding["vendor"], "product": finding["product"],
                             "part": finding["part"], "version": finding["version"], "cpe": finding["cpe"],
                             "origin": "technographic:" + document_id, "source_url": source[0], "observed_at": source[1],
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
    fingerprints = []
    for row in rows[:limit]:
        finding = dict(row)
        details = json.loads(finding.pop("evidence_details"))
        finding.update({key: details[key] for key in ("asset_id", *_HTTP_DETAILS) if key in details})
        fingerprints.append(finding)
    return {"documents": documents, "fingerprints": fingerprints, "total": total, "truncated": len(rows) > limit}
