import asyncio
import csv
import hashlib
import html
import io
import json
import re
import time
import zipfile
from datetime import datetime, timezone
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from xml.etree import ElementTree

from bs4 import BeautifulSoup


SOURCE_DEFINITIONS = [
    {"id": provider, "name": name, "category": "corporate", "family": "corporate", "access": access,
     "description": description, "homepage": homepage, "required": required}
    for provider, name, access, description, homepage, required in [
        ("greenhouse", "Greenhouse public job boards", "public", "Published jobs from explicitly configured board IDs; hiring text is evidence, not verified deployment.", "https://docs.greenhouse.io/job-board", ["source_targets.greenhouse_board"]),
        ("lever", "Lever public postings", "public", "Published jobs from configured Lever sites, including the EU endpoint; no employment or deployment inference.", "https://github.com/lever/postings-api", ["source_targets.lever_site"]),
        ("sec_edgar", "SEC EDGAR submissions", "public", "Current filer metadata and bounded recent filing metadata for configured CIKs; older filing archives are not automatically followed.", "https://www.sec.gov/search-filings/edgar-application-programming-interfaces", ["source_targets.cik", "provider_settings.sec_edgar.user_agent"]),
        ("opencorporates", "OpenCorporates", "api_key", "Credentialed company-name search results remain registry evidence requiring identity review.", "https://api.opencorporates.com/documentation/API-Reference", ["provider_credentials.opencorporates", "source_targets.name"]),
        ("sam_gov", "SAM.gov public entity registrations", "api_key", "Credentialed public entity-registration search; no sensitive or FOUO sections are requested.", "https://open.gsa.gov/api/entity-api/", ["provider_credentials.sam_gov", "source_targets.name"]),
        ("company_documents", "Public company document metadata", "public", "Extract PDF and OOXML properties from explicitly configured document URLs; producer software does not establish deployed technology or OS.", "https://pypdf.readthedocs.io/en/stable/user/metadata.html", ["source_targets.document_urls"]),
        ("public_procurement", "Configured public procurement exports", "configured_url", "Fetch an explicitly configured public JSON, CSV, or text export as procurement evidence without inferring ownership or deployment.", "https://www.usaspending.gov/", ["provider_settings.public_procurement.url"]),
        ("freight_exports", "Configured public freight exports", "configured_url", "Fetch an explicitly configured public freight or trade export as evidence; supplier names do not assign infrastructure ownership.", "https://www.census.gov/foreign-trade/", ["provider_settings.freight_exports.url"]),
        ("indeed", "Indeed exports", "import", "Import an authorized export or supplied record; no unrestricted search API or working site scraper is claimed.", "https://docs.indeed.com/", ["import"]),
        ("linkedin_jobs", "LinkedIn job exports", "import", "Import an authorized export or supplied record; LinkedIn job APIs require platform access and are not used as an unrestricted scraper.", "https://learn.microsoft.com/en-us/linkedin/talent/", ["import"]),
        ("glassdoor", "Glassdoor exports", "import", "Import supplied or authorized job records; no unrestricted Glassdoor API or functioning site scraper is claimed.", "https://www.glassdoor.com/", ["import"]),
        ("importyeti", "ImportYeti exports", "import", "Import supplied freight or company exports; no unrestricted API or automated site scraping is claimed.", "https://www.importyeti.com/", ["import"]),
        ("enigma", "Enigma exports", "import", "Import supplied company-data exports; no unauthenticated Enigma API is claimed.", "https://www.enigma.com/", ["import"]),
    ]
]

_DEFINITIONS = {definition["id"]: definition for definition in SOURCE_DEFINITIONS}
_IMPORTS = {definition["id"] for definition in SOURCE_DEFINITIONS if definition["access"] == "import"}
_SLUG = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
_CIK = re.compile(r"\d{1,10}\Z")
_XML_MEMBERS = ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml")
_MAX_XML = 1024 * 1024


def _json(payload):
    try:
        return json.loads(payload.decode("utf-8-sig"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ValueError("Provider response is not valid UTF-8 JSON") from error


def _public_url(value):
    if not isinstance(value, str):
        raise ValueError("An HTTP(S) URL is required")
    parsed = urlsplit(value.strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("An HTTP(S) URL without embedded credentials is required")
    parsed.port
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))


def _bounded(value, limit=12000):
    encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) <= limit:
        return value
    return {"truncated": True, "preview": encoded.encode("utf-8")[:limit // 2].decode("utf-8", errors="replace")}


def _plain(value, limit=12000):
    return BeautifulSoup(html.unescape(str(value or "")), "html.parser").get_text(" ", strip=True)[:limit]


def _record(item, provider, identity, name, fields, *, kind="corporate_record", role="public_record", truncated=False):
    metadata = item.get("metadata") or {}
    target = metadata.get("target") or {}
    if not isinstance(target, dict):
        raise ValueError("Corporate target context must be an object")
    context = {key: target[key] for key in ("name", "domain", "company_id", "cik") if target.get(key)}
    source_url = item.get("source_url") or ""
    key = json.dumps([provider, source_url, context, identity], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    entity_id = kind + ":" + hashlib.sha256(key.encode("utf-8")).hexdigest()
    provenance = {"raw_reference": "staging:" + str(item["id"]), "payload_hash": item["payload_hash"],
                  "source": item.get("source") or provider, "provider": provider,
                  "observed_at": item.get("observed_at") or item.get("received_at")}
    compact_fields = _bounded(fields)
    entity = {"id": entity_id, "kind": kind, "name": str(name or identity)[:1000], "value": json.dumps(compact_fields, ensure_ascii=False)[:4096],
              "metadata": {"provider": provider, "evidence_role": role, "company_context": context,
                           "fields": compact_fields, "deployment_verified": False, "ownership_verified": False,
                           "coverage_truncated": bool(truncated), "staging": provenance},
              "source_url": source_url, "observed_at": provenance["observed_at"], "confidence": 1.0}
    edge = None
    if context.get("company_id"):
        edge = {"from_id": context["company_id"], "to_id": entity_id, "relation": "has_public_evidence",
                "source_url": source_url, "observed_at": provenance["observed_at"], "confidence": 1.0}
    return entity, edge


def _jobs(provider, payload, maximum):
    jobs = payload.get("jobs") if provider == "greenhouse" and isinstance(payload, dict) else payload
    if not isinstance(jobs, list):
        raise ValueError("Job board response lacks a jobs array")
    records = []
    for job in jobs[:maximum]:
        if not isinstance(job, dict) or job.get("id") is None or not isinstance(job.get("title", job.get("text")), str):
            raise ValueError("Job record lacks an ID or title")
        title = job.get("title", job.get("text"))
        if provider == "greenhouse":
            fields = {key: job.get(key) for key in ("id", "title", "absolute_url", "updated_at", "location", "departments", "offices")}
            fields["description"] = _plain(job.get("content"))
        else:
            fields = {key: job.get(key) for key in ("id", "text", "hostedUrl", "createdAt", "categories", "workplaceType", "country")}
            fields["description"] = _plain(job.get("descriptionPlain") or job.get("description"))
            fields["lists"] = _bounded(job.get("lists") or [], 6000)
        records.append((str(job["id"]), title, fields, "job_posting", "job_advertisement"))
    return records, len(jobs) > maximum or (provider == "lever" and len(jobs) == maximum)


def _sec(payload, target, maximum):
    if not isinstance(payload, dict) or not _CIK.fullmatch(str(payload.get("cik", ""))) or not payload.get("name"):
        raise ValueError("SEC submissions response lacks a filer CIK and name")
    cik = str(int(str(payload["cik"]))).zfill(10)
    if target.get("cik") is not None and cik != str(int(str(target["cik"]).removeprefix("CIK"))).zfill(10):
        raise ValueError("SEC response CIK differs from the configured target")
    fields = {key: payload.get(key) for key in ("cik", "name", "entityType", "sic", "sicDescription", "tickers", "exchanges", "formerNames", "stateOfIncorporation", "website", "investorWebsite", "addresses")}
    filings = payload.get("filings", {}).get("recent")
    if not isinstance(filings, dict):
        raise ValueError("SEC response lacks recent filing metadata")
    columns = ("accessionNumber", "filingDate", "form")
    if any(not isinstance(filings.get(key), list) for key in columns) or len({len(filings[key]) for key in columns}) != 1:
        raise ValueError("SEC recent filing columns are inconsistent")
    records = [("CIK" + cik, payload["name"], fields, "corporate_record", "sec_filer_metadata")]
    for index, accession in enumerate(filings["accessionNumber"][:max(0, maximum - 1)]):
        if not isinstance(accession, str) or not re.fullmatch(r"\d{10}-\d{2}-\d{6}", accession):
            raise ValueError("SEC filing accession number is invalid")
        fields = {key: values[index] for key, values in filings.items() if isinstance(values, list) and index < len(values)}
        records.append((accession, str(fields["form"]) + " · " + str(fields["filingDate"]), fields, "corporate_record", "sec_filing_metadata"))
    return records, len(filings["accessionNumber"]) + 1 > maximum or bool(payload.get("filings", {}).get("files"))


def _registry(provider, payload, maximum):
    if not isinstance(payload, dict):
        raise ValueError("Registry response must be an object")
    if provider == "opencorporates":
        results = payload.get("results")
        if not isinstance(results, dict) or not isinstance(results.get("companies"), list):
            raise ValueError("OpenCorporates response lacks companies results")
        rows = results["companies"]
        total = results.get("total_count", len(rows))
    else:
        rows = payload.get("entityData")
        if not isinstance(rows, list):
            raise ValueError("SAM.gov response lacks entityData")
        total = payload.get("totalRecords", len(rows))
    records = []
    for row in rows[:maximum]:
        if not isinstance(row, dict):
            raise ValueError("Registry result must be an object")
        if provider == "opencorporates":
            value = row.get("company")
            if not isinstance(value, dict) or not value.get("company_number") or not value.get("jurisdiction_code") or not value.get("name"):
                raise ValueError("OpenCorporates company result lacks a registry identity")
            fields = {key: value.get(key) for key in ("company_number", "jurisdiction_code", "name", "current_status", "incorporation_date", "dissolution_date", "company_type", "registered_address_in_full", "previous_names", "opencorporates_url", "registry_url", "source")}
            identity = str(value["jurisdiction_code"]) + "/" + str(value["company_number"])
            title = value["name"]
        else:
            value = row.get("entityRegistration")
            if not isinstance(value, dict) or not value.get("ueiSAM") or not value.get("legalBusinessName"):
                raise ValueError("SAM.gov registration lacks a UEI and legal business name")
            fields = {key: value.get(key) for key in ("ueiSAM", "cageCode", "legalBusinessName", "dbaName", "registrationStatus", "registrationDate", "lastUpdateDate", "registrationExpirationDate", "purposeOfRegistrationDesc", "samRegistered")}
            identity, title = str(value["ueiSAM"]), value["legalBusinessName"]
        records.append((identity, title, fields, "corporate_record", "registry_search_candidate"))
    return records, len(rows) > maximum or (isinstance(total, (int, float)) and total > len(rows))


def _document(payload):
    if payload.startswith(b"%PDF-"):
        try:
            from pypdf import PdfReader
        except ImportError as error:
            raise ValueError("PDF metadata extraction requires pypdf") from error
        try:
            reader = PdfReader(io.BytesIO(payload), strict=False)
            if reader.is_encrypted:
                raise ValueError("Encrypted PDF metadata is not supported")
            properties = {str(key).lstrip("/"): str(value)[:2000] for key, value in list((reader.metadata or {}).items())[:64]}
        except ValueError:
            raise
        except Exception as error:
            raise ValueError("PDF metadata could not be read") from error
        return {"format": "pdf", "properties": properties, "producer_is_deployment_evidence": False}
    if not payload.startswith(b"PK"):
        raise ValueError("Company document must be a PDF or OOXML ZIP document")
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            names = archive.namelist()
            if "[Content_Types].xml" not in names or not any(name.startswith(("word/", "xl/", "ppt/")) for name in names):
                raise ValueError("ZIP response is not a supported OOXML document")
            properties = {}
            for name in _XML_MEMBERS:
                if name not in names:
                    continue
                info = archive.getinfo(name)
                if info.file_size > _MAX_XML:
                    raise ValueError("OOXML metadata part exceeds 1 MiB")
                with archive.open(info) as stream:
                    body = stream.read(_MAX_XML + 1)
                if len(body) > _MAX_XML or b"<!DOCTYPE" in body.upper() or b"<!ENTITY" in body.upper():
                    raise ValueError("OOXML metadata XML is oversized or declares entities")
                root = ElementTree.fromstring(body)
                values = {}
                for node in list(root)[:64]:
                    key = node.attrib.get("name") or node.tag.rsplit("}", 1)[-1]
                    values[str(key)[:200]] = " ".join(node.itertext())[:2000]
                properties[name] = values
            if not properties:
                raise ValueError("OOXML document has no readable document properties")
            return {"format": "ooxml", "properties": properties, "producer_is_deployment_evidence": False}
    except (zipfile.BadZipFile, ElementTree.ParseError, RuntimeError, OSError) as error:
        raise ValueError("OOXML metadata could not be read") from error


def _exports(payload, content_type, maximum):
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeError as error:
        raise ValueError("Corporate export requires UTF-8 text, JSON, or CSV") from error
    if text.lstrip().startswith(("{", "[")):
        parsed = _json(payload)
        rows = parsed.get("records", [parsed]) if isinstance(parsed, dict) else parsed
        if not isinstance(rows, list):
            raise ValueError("Corporate export records must be an array")
        return rows[:maximum], len(rows) > maximum
    if "csv" in content_type.lower() or "," in text.split("\n", 1)[0]:
        reader = csv.DictReader(io.StringIO(text))
        rows = []
        for row in reader:
            if len(rows) == maximum:
                return rows, True
            rows.append(row)
        return rows, False
    if not text.strip():
        raise ValueError("Corporate export is empty")
    return [{"text": _plain(text)}], len(text) > 12000


def normalize_corporate(item, max_records=5000):
    if type(max_records) is not int or not 1 <= max_records <= 5000 or not isinstance(item.get("payload"), bytes):
        raise ValueError("Corporate normalization requires bytes and a record limit from 1 to 5000")
    metadata = item.get("metadata") or {}
    provider = metadata.get("provider")
    if provider not in _DEFINITIONS:
        raise ValueError("Unsupported corporate provider")
    target = metadata.get("target") or {}
    if not isinstance(target, dict):
        raise ValueError("Corporate target context must be an object")
    limit = metadata.get("record_limit", max_records)
    if type(limit) is not int or limit < 1:
        raise ValueError("Corporate record limit must be positive")
    maximum = min(max_records, limit)
    payload = item["payload"]
    if provider in {"greenhouse", "lever"}:
        records, truncated = _jobs(provider, _json(payload), maximum)
    elif provider == "sec_edgar":
        records, truncated = _sec(_json(payload), target, maximum)
    elif provider in {"opencorporates", "sam_gov"}:
        records, truncated = _registry(provider, _json(payload), maximum)
    elif provider == "company_documents":
        fields = _document(payload)
        records, truncated = [(item.get("source_url") or item["payload_hash"], "Document metadata", fields, "document", "document_properties")], False
    else:
        rows, truncated = _exports(payload, item.get("content_type") or "", maximum)
        kind = "procurement_record" if provider == "public_procurement" else "freight_record" if provider in {"freight_exports", "importyeti"} else "job_posting" if provider in {"indeed", "linkedin_jobs", "glassdoor"} else "corporate_record"
        records = []
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                raise ValueError("Corporate export entries must be objects")
            identity = row.get("id") or row.get("noticeId") or row.get("accessionNumber") or hashlib.sha256(json.dumps(row, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
            title = row.get("title") or row.get("name") or row.get("company") or row.get("description") or provider + " record " + str(index + 1)
            records.append((str(identity), str(title), row, kind, "imported_public_evidence"))
    entities, edges = [], []
    for identity, title, fields, kind, role in records:
        entity, edge = _record(item, provider, identity, title, fields, kind=kind, role=role, truncated=truncated)
        entities.append(entity)
        if edge:
            edges.append(edge)
    return {"entities": entities, "edges": edges}


def _requests(config):
    settings = config.get("provider_settings") or {}
    credentials = config.get("provider_credentials") or {}
    targets = config.get("source_targets") or []
    if not isinstance(targets, list) or any(not isinstance(target, dict) for target in targets):
        raise ValueError("source_targets must be a list of company target objects")
    maximum = int(config.get("public_source_records", 100))
    health, requests = {}, []
    for definition in SOURCE_DEFINITIONS:
        provider = definition["id"]
        options = settings.get(provider) or {}
        row = {"provider": provider, "name": definition["name"], "status": "unconfigured", "attempted": 0, "staged": 0, "records": 0, "successful": 0, "errors": []}
        health[provider] = row
        if options.get("enabled") is False:
            row["status"] = "disabled"
            continue
        if provider in _IMPORTS:
            row["reason"] = "Requires a supplied authorized export; no unrestricted scraper is configured"
            continue
        key = credentials.get(provider)
        if isinstance(key, dict):
            key = key.get("api_key") or key.get("token") or key.get("key")
        if isinstance(key, str):
            key = key.strip()
        if definition["access"] == "api_key" and (not isinstance(key, str) or not key.strip()):
            row["reason"] = "API credential is not configured"
            continue
        if provider == "sec_edgar" and not re.search(r"\S+@\S+\.\S+", str(options.get("user_agent") or "")):
            row["reason"] = "A descriptive SEC User-Agent with contact email is required"
            continue
        candidates = [{}] if provider in {"public_procurement", "freight_exports"} else targets
        for target in candidates:
            url, params, headers, private = None, {}, {}, False
            try:
                if provider in {"greenhouse", "lever"}:
                    slug = target.get("greenhouse_board" if provider == "greenhouse" else "lever_site")
                    if not slug:
                        continue
                    if not isinstance(slug, str) or not _SLUG.fullmatch(slug):
                        raise ValueError("Configured job board ID is invalid")
                    if provider == "greenhouse":
                        url, params = "https://boards-api.greenhouse.io/v1/boards/" + quote(slug, safe="") + "/jobs", {"content": "true"}
                    else:
                        host = "api.eu.lever.co" if options.get("region") == "eu" else "api.lever.co"
                        url, params = "https://" + host + "/v0/postings/" + quote(slug, safe=""), {"mode": "json", "limit": maximum}
                elif provider == "sec_edgar":
                    value = str(target.get("cik") or "").removeprefix("CIK")
                    if not value:
                        continue
                    if not _CIK.fullmatch(value) or int(value) == 0:
                        raise ValueError("Configured SEC CIK is invalid")
                    url = "https://data.sec.gov/submissions/CIK" + str(int(value)).zfill(10) + ".json"
                    headers = {"User-Agent": options["user_agent"]}
                elif provider in {"opencorporates", "sam_gov"}:
                    if not target.get("name"):
                        continue
                    if provider == "opencorporates":
                        url, params = "https://api.opencorporates.com/v0.4/companies/search", {"q": target["name"], "per_page": min(100, maximum)}
                        headers = {"X-API-TOKEN": key}
                    else:
                        url, params = "https://api.sam.gov/entity-information/v3/entities", {"api_key": key, "legalBusinessName": target["name"], "includeSections": "entityRegistration", "page": 0, "size": min(10, maximum)}
                        headers = {"Accept": "application/json"}
                    private = True
                elif provider == "company_documents":
                    documents = target.get("document_urls") or []
                    if not isinstance(documents, list):
                        raise ValueError("document_urls must be an array")
                    for document in documents:
                        document = _public_url(document)
                        requests.append((provider, document, {}, {}, target, False))
                    continue
                else:
                    if not options.get("url"):
                        continue
                    url = _public_url(options["url"])
                requests.append((provider, url, params, headers, target, private))
            except (TypeError, ValueError):
                row["status"] = "error"
                row["errors"].append("Invalid provider target configuration")
        if any(request[0] == provider for request in requests) and row["status"] != "error":
            row["status"] = "deferred"
        elif row["status"] == "unconfigured":
            row["reason"] = "Required company targets or public export URL are not configured"
    return requests, health


async def collect_corporate_sources(config, store, http):
    from .sourcehub import stage_payload
    requests, health = _requests(config)
    batch_limit = max(1, int(config.get("public_source_batch", 3)))
    record_limit = max(1, min(5000, int(config.get("public_source_records", 100))))
    concurrency = max(1, int(config.get("public_source_concurrency", 4)))
    state = await asyncio.to_thread(store.source_state, "corporate_sources")
    cursors = dict(state.get("cursors") or {})
    selected = []
    for provider in health:
        candidates = [request for request in requests if request[0] == provider]
        if not candidates:
            continue
        cursor = int(cursors.get(provider, 0)) % len(candidates)
        chosen = (candidates[cursor:] + candidates[:cursor])[:batch_limit]
        selected.extend(chosen)
        cursors[provider] = (cursor + len(chosen)) % len(candidates)
        health[provider]["pending_targets"] = len(candidates) - len(chosen)
    digests = dict(state.get("digests") or {})
    semaphore, sec_lock = asyncio.Semaphore(concurrency), asyncio.Lock()
    sec_last = 0.0
    maximum = int(float(config.get("staging_max_payload_mb", 8)) * 1024 * 1024)

    async def fetch(request):
        nonlocal sec_last
        provider, url, params, headers, target, private = request
        row = health[provider]
        row["attempted"] += 1
        public_params = {key: value for key, value in params.items() if key != "api_key"}
        source_url = url + ("&" if "?" in url else "?") + urlencode(public_params) if public_params else url
        metadata = {"provider": provider, "target": {key: target[key] for key in ("name", "domain", "company_id", "cik") if target.get(key)}, "record_limit": record_limit}
        identity = hashlib.sha256(json.dumps([provider, url, public_params, metadata], sort_keys=True).encode()).hexdigest()
        phase = "request"
        staged = 0
        try:
            async with semaphore:
                if provider == "sec_edgar":
                    async with sec_lock:
                        delay = sec_last + 0.11 - time.monotonic()
                        if delay > 0:
                            await asyncio.sleep(delay)
                        sec_last = time.monotonic()
                response = await http.get(url, params=params or None, headers=headers or None, max_bytes=maximum,
                                          cache=not private, allow_redirects=not private, max_attempts=1)
                if response.status not in (200, 304):
                    raise ValueError("Provider returned a non-success HTTP status")
                if getattr(response, "changed", True) is False and digests.get(identity) == response.digest:
                    return provider, {"unchanged": 1, "successful": 1}
                payload = await asyncio.to_thread(response.path.read_bytes)
                content_type = next((value for key, value in response.headers.items() if key.lower() == "content-type"), "application/octet-stream")
                phase = "durable staging"
                queued = await stage_payload(config, store, payload, provider=provider, source_url=source_url,
                                             content_type=content_type, stream_key=identity, metadata=metadata)
                staged = int(not queued.get("duplicate", False))
                phase = "provider payload validation"
                preview = normalize_corporate({"id": queued["id"], "source": provider, "source_url": source_url, "payload": payload,
                                               "payload_hash": hashlib.sha256(payload).hexdigest(), "metadata": metadata,
                                               "observed_at": queued.get("observed_at") or datetime.now(timezone.utc).isoformat()}, max_records=record_limit)
                digests[identity] = response.digest
                return provider, {"staged": staged, "records": len(preview["entities"]), "successful": 1,
                                  "truncated": any(entity["metadata"]["coverage_truncated"] for entity in preview["entities"])}
        except Exception as error:
            status = getattr(error, "status", None)
            message = "HTTP " + str(status) if isinstance(status, int) else phase.capitalize() + " failed (" + type(error).__name__ + ")"
            return provider, {"error": message, "staged": staged}

    results = await asyncio.gather(*(fetch(request) for request in selected))
    totals = {"requests": len(selected), "staged": 0, "records": 0, "unchanged": 0, "pending_targets": max(0, len(requests) - len(selected))}
    for provider, result in results:
        row = health[provider]
        for key in ("staged", "records", "unchanged", "successful"):
            row[key] = row.get(key, 0) + result.get(key, 0)
            if key in totals:
                totals[key] += result.get(key, 0)
        if result.get("error"):
            row["errors"].append(result["error"])
        else:
            row["coverage_truncated"] = row.get("coverage_truncated", False) or result.get("truncated", False)
        row["status"] = "partial" if row["errors"] and row["successful"] else "error" if row["errors"] else "ok"
    await asyncio.to_thread(store.update_source, "corporate_sources", cursors=cursors, digests=digests)
    errors = [provider + ": " + message for provider, row in health.items() for message in row["errors"]]
    return {**totals, "errors": errors, "provider_health": health}
