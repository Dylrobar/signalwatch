import hashlib
import json
import logging
import math
import re
import time
from urllib.parse import urlsplit, unquote

from bs4 import BeautifulSoup

from .extract import canonical_url

log = logging.getLogger("signalwatch")


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
CREATE TABLE IF NOT EXISTS evidence_resolution (
 source_entity_id TEXT PRIMARY KEY REFERENCES entities(id) ON DELETE CASCADE,
 organization_id TEXT REFERENCES entities(id) ON DELETE SET NULL, status TEXT NOT NULL,
 method TEXT NOT NULL, reason TEXT NOT NULL, candidates TEXT NOT NULL DEFAULT '[]',
 source_url TEXT NOT NULL DEFAULT '', context TEXT NOT NULL DEFAULT '{}',
 matched_domain TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS evidence_resolution_org ON evidence_resolution(organization_id,status);
CREATE INDEX IF NOT EXISTS evidence_resolution_binding ON evidence_resolution(json_extract(context,'$.binding_key'));
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


def organization(conn, context):
    from .entity_resolution import resolve
    return resolve(conn, context=context).get("organization_id")


def persist_resolution(conn, entity_id, result, source_url, context, timestamp):
    conn.execute("""INSERT INTO evidence_resolution VALUES(?,?,?,?,?,?,?,?,?,?)
     ON CONFLICT(source_entity_id) DO UPDATE SET organization_id=excluded.organization_id,
     status=excluded.status,method=excluded.method,reason=excluded.reason,candidates=excluded.candidates,
     source_url=excluded.source_url,context=excluded.context,matched_domain=excluded.matched_domain,updated_at=excluded.updated_at""",
     (entity_id, result.get("organization_id"), result["status"], result.get("method") or "none",
      result.get("reason") or "", json.dumps(result.get("candidates") or []), source_url or "",
      json.dumps(context or {}, sort_keys=True), result.get("matched_domain") or "", timestamp))


def _unresolved(result, reason, *, conflict=False):
    candidates = sorted(set(result.get("candidates") or []) | ({result["organization_id"]} if result.get("organization_id") else set()))
    return {**result, "organization_id": None, "status": "conflict" if conflict or result.get("status") == "conflict" else "candidate" if candidates else "unattributed",
            "candidates": candidates, "reason": reason}


def _board(url, provider, *, endpoint=False):
    try:
        parsed = urlsplit(url)
        parsed.port
    except (TypeError, ValueError):
        return None
    if parsed.scheme != "https" or parsed.username or parsed.password:
        return None
    host, path = (parsed.hostname or "").lower(), parsed.path.rstrip("/")
    patterns = {
        "greenhouse": ({"boards-api.greenhouse.io"}, r"/v1/boards/([^/]+)/jobs") if endpoint else
                       ({"boards.greenhouse.io", "job-boards.greenhouse.io", "boards.eu.greenhouse.io"}, r"/([^/]+)(?:/.*)?"),
        "lever": ({"api.lever.co", "api.eu.lever.co"}, r"/v0/postings/([^/]+)") if endpoint else
                 ({"jobs.lever.co", "jobs.eu.lever.co"}, r"/([^/]+)(?:/.*)?"),
        "ashby": ({"api.ashbyhq.com"}, r"/posting-api/job-board/([^/]+)") if endpoint else
                 ({"jobs.ashbyhq.com"}, r"/([^/]+)(?:/.*)?"),
    }
    hosts, pattern = patterns.get(provider, (set(), r"(?!)"))
    match = re.fullmatch(pattern, path)
    if host not in hosts or not match:
        return None
    # Greenhouse's supported public job hosts share its boards API namespace.
    # Lever has separate EU and global API endpoints and must retain that fence.
    region = "eu:" if provider == "lever" and ".eu." in host else "global:"
    return region + unquote(match.group(1)).casefold()


def _resolve_document(conn, entity, doc):
    from .companies import asset_identity
    from .entity_resolution import resolve

    context, metadata = doc["organization_context"], entity.get("metadata") or {}
    result = resolve(conn, context=context, source_url=doc["source_url"], text=doc["text"])
    if doc["source_type"] == "dns_txt":
        record = metadata.get("provider_fields") or {}
        try:
            actual = asset_identity("https://" + str(record.get("name") or ""))[1]
            requested = asset_identity("https://" + str(metadata.get("target_domain") or ""))[1]
        except ValueError:
            return _unresolved(result, "DNS answer has no valid queried domain")
        if actual != requested:
            return _unresolved(result, "DNS answer owner differs from the queried domain", conflict=True)
        return resolve(conn, context={"domain": actual}, text=doc["text"])
    if doc["source_type"] == "http_fingerprint":
        # Primary roots identify evidence on child hosts. Legacy asset decisions
        # retain their exact-host semantics and never widen the risk inventory.
        if result.get("method") == "legacy_domain" and result.get("organization_id") != _http_organization(conn, doc["asset_id"]):
            return _unresolved(result, "HTTP host has no unique approved legacy owner")
        return result
    provider = doc["source_type"]
    binding = metadata.get("source_binding") or {}
    if provider in {"greenhouse", "lever", "ashby"}:
        endpoint = _board(doc["endpoint_url"], provider, endpoint=True)
        bound = _board(str(binding.get("endpoint_url") or ""), provider, endpoint=True)
        if not endpoint or endpoint != bound or binding.get("provider") != provider or binding.get("kind") not in {"configured", "discovered"}:
            return _unresolved(result, "Shared job board has no validated company endpoint binding")
        owner = resolve(conn, context=context)
        if owner.get("status") != "resolved":
            return owner
        if binding["kind"] == "discovered":
            discovery = resolve(conn, source_url=str(binding.get("discovered_from") or ""))
            if discovery.get("organization_id") != owner["organization_id"]:
                return _unresolved(owner, "Job board discovery page is outside the approved company scope", conflict=True)
        job_board = _board(doc["source_url"], provider)
        if job_board is not None:
            if job_board != endpoint:
                return _unresolved(owner, "Job URL belongs to a different board", conflict=True)
        else:
            job_owner = resolve(conn, source_url=doc["source_url"])
            if job_owner.get("organization_id") != owner["organization_id"]:
                return _unresolved(owner, "Job URL has no matching approved company owner", conflict=True)
        binding_key = provider + "/" + endpoint
        owners = {owner["organization_id"]}
        claims = {(owner["organization_id"], str(context.get("domain") or ""))}
        for saved in conn.execute("""SELECT DISTINCT json_extract(e.metadata,'$.source_binding') AS source_binding,e.source_url,r.context
         FROM evidence_resolution r JOIN entities e ON e.id=r.source_entity_id
         WHERE json_extract(r.context,'$.binding_key')=?""", (binding_key,)):
            other_binding = json.loads(saved["source_binding"] or "{}")
            if (_board(str(other_binding.get("endpoint_url") or ""), provider, endpoint=True) != endpoint
                    or _board(saved["source_url"], provider, endpoint=True) != endpoint):
                continue
            recorded = json.loads(saved["context"])
            prior_claims = recorded.get("binding_claims") or [recorded.get("company_context") or {}]
            for claim in prior_claims:
                current_owner = resolve(conn, context=claim)
                if current_owner.get("organization_id"):
                    owners.add(current_owner["organization_id"])
                    claims.add((current_owner["organization_id"], str(claim.get("domain") or "")))
        binding_claims = [{"company_id": company, "domain": domain} for company, domain in sorted(claims)]
        if len(owners) > 1:
            return {**owner, "organization_id": None, "status": "conflict", "method": "ats_board_conflict",
                    "binding_key": binding_key, "binding_claims": binding_claims,
                    "candidates": sorted(owners), "reason": "The same shared job board is bound to different companies"}
        return {**owner, "method": "ats_binding", "binding_key": binding_key,
                "binding_claims": binding_claims,
                "reason": "Approved company domain and validated job board binding agree"}
    source = resolve(conn, source_url=doc["source_url"])
    endpoint = resolve(conn, source_url=doc["endpoint_url"])
    if not source.get("organization_id") or source.get("organization_id") != endpoint.get("organization_id"):
        return _unresolved(result, "Document and fetched source do not share an approved company owner",
                           conflict=bool(source.get("organization_id") and endpoint.get("organization_id")))
    return result


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
    limit = max(1, int(limit))
    rows = conn.execute("""WITH associations AS (
      SELECT e.from_id AS company_id,e.to_id AS asset_id FROM edges e WHERE e.relation IN ('official_website','primary_domain_anchor')
      UNION SELECT company_id,asset_id FROM company_asset_decisions WHERE status='confirmed' AND role='owned'
     ), domains AS (
      SELECT c.id AS company_id,c.name,lower(rtrim(substr(d.id,8),'.')) AS domain,
       CASE WHEN lower(substr(d.id,8)) LIKE 'www.%' THEN substr(lower(rtrim(substr(d.id,8),'.')),5)
        ELSE lower(rtrim(substr(d.id,8),'.')) END AS canonical_domain
      FROM associations a JOIN entities c ON c.id=a.company_id AND c.kind='company'
      JOIN entities d ON d.id=a.asset_id AND d.id LIKE 'domain:%' AND d.kind IN ('domain','asset')
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
      JOIN owners o ON o.canonical_domain=i.canonical_domain ORDER BY i.domain""")
    from .entity_resolution import resolve
    targets = []
    for row in rows:
        target = dict(row)
        decision = resolve(conn, context={"domain": target["domain"]})
        if decision.get("organization_id"):
            target["company_id"] = decision["organization_id"]
            owner = conn.execute("SELECT coalesce(p.name,e.name) FROM entities e LEFT JOIN company_profiles p ON p.company_id=e.id WHERE e.id=?",
                                 (target["company_id"],)).fetchone()
            target["name"] = owner[0] if owner else ""
            targets.append(target)
            # Stream candidates until the accepted-target budget is filled;
            # earlier ambiguous domains must not starve later valid owners.
            if len(targets) >= limit:
                break
    return targets


def reproject_domain(store, conn, asset_id):
    """Apply a manual decision to retained evidence without changing its source record."""
    # A root decision affects descendants and final-URL-derived HTTP evidence,
    # including records whose supplied context was originally absent or wrong.
    return reproject_company_identity(store, conn, "") - {""}


def reproject_company_identity(store, conn, company_id, old_domains=(), new_domains=()):
    """Re-evaluate retained evidence after identity decisions, in the caller's transaction."""
    affected = {company_id}
    # Conflicts and aliases can involve a company outside the previous owner.
    # Stream the retained source catalogue instead of trusting stale attribution.
    rows = conn.execute("""SELECT * FROM entities WHERE kind IN ('job_posting','company_article','web_fingerprint')
     OR (kind='source_record' AND json_extract(metadata,'$.provider')='dns_txt')
     OR (kind IN ('corporate_record','document','procurement_record','freight_record')
         AND json_type(metadata,'$.company_context')='object')
     OR EXISTS(SELECT 1 FROM technographic_sources s WHERE s.source_entity_id=entities.id)""")
    for row in rows:
        entity = dict(row)
        entity["metadata"] = json.loads(entity["metadata"])
        before = {tuple(item) for item in conn.execute("SELECT organization_id,document_id FROM technographic_sources WHERE source_entity_id=?", (entity["id"],))}
        project(store, conn, entity, entity["updated_at"], affected=affected)
        after = {tuple(item) for item in conn.execute("SELECT organization_id,document_id FROM technographic_sources WHERE source_entity_id=?", (entity["id"],))}
        if before != after:
            affected.update(item[0] for item in before | after)
    from .text_signals import refresh_company_resolution
    refresh_company_resolution(store, conn, company_id)
    return affected


def backfill_resolution(store, conn):
    conn.execute("CREATE TABLE IF NOT EXISTS evidence_resolution_migrations(version TEXT PRIMARY KEY)")
    if conn.execute("SELECT 1 FROM evidence_resolution_migrations WHERE version='company-isolation-v1'").fetchone():
        return
    started = time.monotonic()
    log.info("Company evidence migration started: version=company-isolation-v1")
    affected = reproject_company_identity(store, conn, "") - {""}
    if affected:
        store.reconcile(asset_ids=affected, conn=conn)
    conn.execute("INSERT INTO evidence_resolution_migrations VALUES('company-isolation-v1')")
    log.info("Company evidence migration completed: version=company-isolation-v1 elapsed_seconds=%.3f affected_companies=%d",
             time.monotonic() - started, len(affected))


def document_seen(conn, context, content_hash):
    company_id = organization(conn, context)
    return bool(company_id and conn.execute("SELECT 1 FROM technographic_documents WHERE organization_id=? AND content_hash=?",
                                           (company_id, content_hash)).fetchone())


def project(store, conn, entity, timestamp, *, affected=None):
    from .technographics import extract

    # Entity updates merge metadata; attribution must use that retained state,
    # not interpret an omitted field in a partial refresh as its removal.
    if entity.get("kind") in {"job_posting", "company_article", "source_record", "web_fingerprint",
                              "corporate_record", "document", "procurement_record", "freight_record"}:
        saved = conn.execute("SELECT * FROM entities WHERE id=?", (entity["id"],)).fetchone()
        if saved is not None:
            entity = dict(saved)
            entity["metadata"] = json.loads(entity["metadata"])
    doc = document_input(entity)
    if doc is None:
        detached = set()
        context = (entity.get("metadata") or {}).get("company_context")
        if isinstance(context, dict):
            from .entity_resolution import resolve
            result = resolve(conn, context=context, source_url=entity.get("source_url") or "", text=entity.get("name") or "")
            # Search results and corporate metadata are related records, not a
            # first-party document merely because they carry a target context.
            source = resolve(conn, source_url=entity.get("source_url") or "")
            if source.get("organization_id") != result.get("organization_id"):
                result = _unresolved(result, "Third-party record requires an approved identity binding")
            persist_resolution(conn, entity["id"], result, entity.get("source_url"), context, timestamp)
            detached.update(_detach_sources(store, conn, entity["id"], None, None, timestamp))
            if result.get("organization_id"):
                store._edge(conn, {"from_id": result["organization_id"], "to_id": entity["id"], "relation": "has_public_evidence",
                                   "source_url": entity.get("source_url") or ""}, timestamp)
        else:
            # A removed identity context or DNS verification token invalidates
            # the saved attribution too, even when there was no tech document.
            removed = conn.execute("DELETE FROM evidence_resolution WHERE source_entity_id=?", (entity["id"],)).rowcount
            if removed or conn.execute("SELECT 1 FROM technographic_sources WHERE source_entity_id=?", (entity["id"],)).fetchone():
                detached.update(_detach_sources(store, conn, entity["id"], None, None, timestamp))
        if affected is not None:
            affected.update(detached)
        return {}
    resolution = _resolve_document(conn, entity, doc)
    provenance = {"company_context": doc["organization_context"],
                  "endpoint_url": doc["endpoint_url"], "source_binding": (entity.get("metadata") or {}).get("source_binding"),
                  "binding_key": resolution.get("binding_key"), "binding_claims": resolution.get("binding_claims")}
    persist_resolution(conn, entity["id"], resolution, doc["source_url"], provenance, timestamp)
    detached = set()
    if resolution.get("method") == "ats_board_conflict":
        for previous in conn.execute("SELECT * FROM evidence_resolution WHERE json_extract(context,'$.binding_key')=? AND source_entity_id!=?",
                                     (resolution["binding_key"], entity["id"])).fetchall():
            detached.update(_detach_sources(store, conn, previous["source_entity_id"], None, None, timestamp))
            previous_context = json.loads(previous["context"])
            previous_context["binding_claims"] = resolution.get("binding_claims")
            persist_resolution(conn, previous["source_entity_id"], resolution, previous["source_url"], previous_context, timestamp)
    company_id = resolution.get("organization_id")
    document_id = ("technographic_document:" + hashlib.sha256((company_id + "\0" + doc["content_hash"]).encode()).hexdigest()) if company_id else None
    detached.update(_detach_sources(store, conn, entity["id"], company_id, document_id, timestamp))
    if affected is not None:
        affected.update(detached)
    elif detached and resolution.get("method") == "ats_board_conflict":
        # Shared-board invalidation can clear sources processed earlier in this
        # batch. Withdraw their alerts in the same ingestion transaction.
        store.reconcile(asset_ids=detached, conn=conn)
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
    affected = set()
    previous = conn.execute("SELECT organization_id,document_id FROM technographic_sources WHERE source_entity_id=?", (entity_id,)).fetchall()
    for old_company, old_document in previous:
        if (old_company, old_document) == (company_id, document_id):
            continue
        affected.add(old_company)
        conn.execute("DELETE FROM technographic_sources WHERE organization_id=? AND source_entity_id=?", (old_company, entity_id))
        if not conn.execute("SELECT 1 FROM technographic_sources WHERE document_id=? AND organization_id=?", (old_document, old_company)).fetchone():
            _clear_projection(store, conn, old_company, old_document, timestamp)
        else:
            _observations(store, conn, old_company, old_document, timestamp)
    conn.execute("""DELETE FROM edges WHERE to_id=? AND relation IN ('has_public_evidence','candidate_evidence')
     AND EXISTS (SELECT 1 FROM entities e WHERE e.id=edges.from_id AND e.kind='company')
     AND (? IS NULL OR from_id!=?)""",
                 (entity_id, company_id, company_id))
    if company_id is None:
        conn.execute("DELETE FROM edges WHERE from_id=? AND relation LIKE 'technology_%'", (entity_id,))
    return affected


def _graph(store, conn, entity_id, document_id, source_url, timestamp):
    conn.execute("DELETE FROM edges WHERE from_id=? AND relation LIKE 'technology_%'", (entity_id,))
    for finding in conn.execute("""SELECT f.* FROM tech_fingerprints f JOIN technographic_documents d
     ON d.id=f.document_id AND d.organization_id=f.organization_id WHERE f.document_id=?""", (document_id,)):
        key = "technographic_product:" + hashlib.sha256((finding["vendor"] + "\0" + finding["product"]).encode()).hexdigest()
        role = "http_technology_label" if finding["status"] in _HTTP_STATUSES else "textual_technology_label"
        store._entity(conn, {"id": key, "kind": "technology", "name": finding["product_name"],
                            "metadata": {"vendor": finding["vendor"], "product": finding["product"], "evidence_role": role},
                            "source_url": source_url}, timestamp)
        store._edge(conn, {"from_id": entity_id, "to_id": key, "relation": "technology_" + finding["status"],
                           "source_url": source_url, "confidence": finding["confidence"]}, timestamp)
        if finding["vendor"] and finding["vendor"] != "unknown":
            vendor_id = "technographic_vendor:" + hashlib.sha256(finding["vendor"].encode()).hexdigest()
            store._entity(conn, {"id": vendor_id, "kind": "vendor", "name": finding["vendor_name"] or finding["vendor"],
                                "metadata": {"evidence_role": "technology_vendor_label", "verified_legal_company": False}}, timestamp)
            store._edge(conn, {"from_id": key, "to_id": vendor_id, "relation": "vendor_label", "source_url": source_url}, timestamp)


def _clear_projection(store, conn, company_id, document_id, timestamp):
    store.ingest({"observation_snapshots": [{"asset_id": company_id, "origin": "technographic:" + document_id}]}, conn=conn)


def _observations(store, conn, company_id, document_id, timestamp):
    source = conn.execute("SELECT source_url,last_seen_at FROM technographic_sources WHERE document_id=? AND organization_id=? ORDER BY last_seen_at DESC,source_url LIMIT 1", (document_id, company_id)).fetchone()
    if source is None:
        return
    observations = []
    for finding in conn.execute("SELECT * FROM tech_fingerprints WHERE document_id=? AND organization_id=? AND status='asserted_use'", (document_id, company_id)):
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
        conn.execute("UPDATE technographic_documents SET last_seen_at=max(last_seen_at,?) WHERE id=? AND organization_id=?", (timestamp, key, company_id))
        conn.execute("UPDATE tech_fingerprints SET last_seen_at=max(last_seen_at,?) WHERE document_id=? AND organization_id=?", (timestamp, key, company_id))
    return len(documents)


def company_evidence(conn, company_id, limit=100):
    rows = conn.execute("""SELECT f.*,d.title AS document_title,d.published_at,
     (SELECT source_url FROM technographic_sources s WHERE s.document_id=d.id AND s.organization_id=d.organization_id ORDER BY last_seen_at DESC,source_url LIMIT 1) AS source_url,
     (SELECT source_type FROM technographic_sources s WHERE s.document_id=d.id AND s.organization_id=d.organization_id ORDER BY last_seen_at DESC,source_url LIMIT 1) AS source_type
     FROM tech_fingerprints f JOIN technographic_documents d ON d.id=f.document_id AND d.organization_id=f.organization_id
     WHERE f.organization_id=? AND EXISTS (SELECT 1 FROM technographic_sources s WHERE s.document_id=d.id AND s.organization_id=f.organization_id)
     ORDER BY f.last_seen_at DESC,f.id LIMIT ?""", (company_id, limit + 1)).fetchall()
    total = conn.execute("""SELECT count(*) FROM tech_fingerprints f WHERE organization_id=?
     AND EXISTS (SELECT 1 FROM technographic_sources s JOIN technographic_documents d ON d.id=s.document_id AND d.organization_id=s.organization_id
                 WHERE s.document_id=f.document_id AND s.organization_id=f.organization_id)""", (company_id,)).fetchone()[0]
    documents = conn.execute("SELECT count(DISTINCT s.document_id) FROM technographic_sources s JOIN technographic_documents d ON d.id=s.document_id AND d.organization_id=s.organization_id WHERE s.organization_id=?", (company_id,)).fetchone()[0]
    fingerprints = []
    for row in rows[:limit]:
        finding = dict(row)
        details = json.loads(finding.pop("evidence_details"))
        finding.update({key: details[key] for key in ("asset_id", *_HTTP_DETAILS) if key in details})
        fingerprints.append(finding)
    decisions = conn.execute("""SELECT * FROM evidence_resolution r WHERE organization_id=?
     OR EXISTS (SELECT 1 FROM json_each(r.candidates) WHERE value=?)
     ORDER BY updated_at DESC,source_entity_id LIMIT ?""", (company_id, company_id, limit + 1)).fetchall()
    resolution = {status: 0 for status in ("resolved", "candidate", "conflict", "unattributed")}
    for status, count in conn.execute("""SELECT status,count(*) FROM evidence_resolution r WHERE organization_id=?
     OR EXISTS (SELECT 1 FROM json_each(r.candidates) WHERE value=?) GROUP BY status""", (company_id, company_id)):
        resolution[status] = count
    # Decisions expose only identity/provenance, never another company's body.
    resolution["items"] = [{key: json.loads(row[key]) if key == "candidates" else row[key] for key in
                            ("source_entity_id", "organization_id", "status", "method", "reason", "candidates", "source_url", "matched_domain")}
                           for row in decisions[:limit]]
    resolution["truncated"] = len(decisions) > limit
    relationships = [{key: finding[key] for key in ("vendor", "vendor_name", "product", "product_name", "status", "evidence_snippet", "source_url", "organization_id", "method")}
                     for finding in fingerprints]
    return {"documents": documents, "fingerprints": fingerprints, "total": total, "truncated": len(rows) > limit,
            "resolution": resolution, "relationships": relationships}
