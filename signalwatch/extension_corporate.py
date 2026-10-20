import asyncio
import calendar
import csv
import hashlib
import html
import io
import json
import re
import time
import zipfile
from datetime import datetime, timezone
from urllib.parse import parse_qs, quote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.robotparser import RobotFileParser
from xml.etree import ElementTree

from bs4 import BeautifulSoup
import feedparser

from .async_utils import gather, to_thread


SOURCE_DEFINITIONS = [
    {"id": provider, "name": name, "category": "corporate", "family": "corporate", "access": access,
     "description": description, "homepage": homepage, "required": required}
    for provider, name, access, description, homepage, required in [
        ("corporate_discovery", "Company public evidence discovery", "public", "Discover linked public job boards, company RSS/Atom feeds, and document URLs from configured company domains, with bounded weekly rotation; links remain evidence rather than deployment claims.", "https://github.com/Dylrobar/signalwatch", ["source_targets.domain"]),
        ("gleif", "GLEIF legal entities and reported parents", "public", "Keyless LEI legal-name search and reported direct/ultimate parent relationships; name matches remain identity candidates.", "https://www.gleif.org/en/lei-data/gleif-api/", ["source_targets.name"]),
        ("importyeti_public", "ImportYeti public company tables", "public", "Visible public supplier, HTS, and recent shipment tables from company-name candidate pages; locked fields and search APIs are not requested and shipments do not establish installed infrastructure.", "https://www.importyeti.com/", ["source_targets.name"]),
        ("greenhouse", "Greenhouse public job boards", "public", "Published jobs from configured or company-linked board IDs; hiring text is evidence, not verified deployment.", "https://docs.greenhouse.io/job-board", ["source_targets.domain or greenhouse_board"]),
        ("lever", "Lever public postings", "public", "Published jobs from configured or company-linked Lever sites, including EU boards; no employment or deployment inference.", "https://github.com/lever/postings-api", ["source_targets.domain or lever_site"]),
        ("ashby", "Ashby public postings", "public", "Published jobs from configured or company-linked Ashby boards using the public Job Postings API; hiring text remains attributed evidence.", "https://developers.ashbyhq.com/docs/public-job-posting-api", ["source_targets.domain or ashby_board"]),
        ("company_feeds", "Company engineering and publication feeds", "public", "Company-linked RSS and Atom engineering, blog, and news publications; original article URLs and publication dates are preserved.", "https://www.rssboard.org/rss-specification", ["source_targets.domain or feed_urls"]),
        ("sec_edgar", "SEC EDGAR submissions", "public", "Current filer metadata and bounded recent filing metadata for configured CIKs; older filing archives are not automatically followed.", "https://www.sec.gov/search-filings/edgar-application-programming-interfaces", ["source_targets.cik", "provider_settings.sec_edgar.user_agent"]),
        ("opencorporates", "OpenCorporates", "api_key", "Credentialed company-name search results remain registry evidence requiring identity review.", "https://api.opencorporates.com/documentation/API-Reference", ["provider_credentials.opencorporates", "source_targets.name"]),
        ("sam_gov", "SAM.gov public entity registrations", "api_key", "Credentialed public entity-registration search; no sensitive or FOUO sections are requested.", "https://open.gsa.gov/api/entity-api/", ["provider_credentials.sam_gov", "source_targets.name"]),
        ("company_documents", "Public company document metadata", "public", "Extract PDF and OOXML properties from configured or company-linked document URLs; producer software does not establish deployed technology or OS.", "https://pypdf.readthedocs.io/en/stable/user/metadata.html", ["source_targets.domain or document_urls"]),
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
_LEI = re.compile(r"[A-Z0-9]{18}\d{2}\Z")
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


def _plain(value, limit=12000, paragraphs=False):
    soup = BeautifulSoup(html.unescape(str(value or "")), "html.parser")
    if not paragraphs:
        return soup.get_text(" ", strip=True)[:limit]
    for node in soup.find_all(["p", "li", "div", "section", "article", "h1", "h2", "h3", "h4", "h5", "h6"]):
        node.insert_before("\n")
        node.insert_after("\n")
    for node in soup.find_all("br"):
        node.replace_with("\n")
    return "\n".join(" ".join(line.split()) for line in soup.get_text(" ").splitlines() if line.strip())[:limit]


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
    if metadata.get("source_response_hash"):
        provenance["source_response_hash"] = metadata["source_response_hash"]
    compact_fields = _bounded(fields, 64000 if kind in {"job_posting", "company_article"} else 12000)
    entity = {"id": entity_id, "kind": kind, "name": str(name or identity)[:1000], "value": json.dumps(compact_fields, ensure_ascii=False)[:4096],
              "metadata": {"provider": provider, "evidence_role": role, "company_context": context,
                           "fields": compact_fields, "deployment_verified": False, "ownership_verified": False,
                           "coverage_truncated": bool(truncated or metadata.get("coverage_truncated")), "staging": provenance},
              "source_url": source_url, "observed_at": provenance["observed_at"], "confidence": 1.0}
    if metadata.get("discovered_from"):
        entity["metadata"]["discovered_from"] = metadata["discovered_from"]
    if isinstance(metadata.get("source_binding"), dict):
        entity["metadata"]["source_binding"] = metadata["source_binding"]
    if "source_record_offset" in metadata:
        entity["metadata"]["source_selection"] = {"offset": metadata["source_record_offset"], "total_records": metadata["source_total_records"]}
    edge = None
    if context.get("company_id"):
        edge = {"from_id": context["company_id"], "to_id": entity_id, "relation": "candidate_evidence",
                "source_url": source_url, "observed_at": provenance["observed_at"], "confidence": 1.0}
    return entity, edge


def _jobs(provider, payload, maximum, offset=0):
    jobs = payload.get("jobs") if provider in {"greenhouse", "ashby"} and isinstance(payload, dict) else payload
    if not isinstance(jobs, list):
        raise ValueError("Job board response lacks a jobs array")
    records = []
    for job in jobs[offset:offset + maximum]:
        if not isinstance(job, dict) or (job.get("jobUrl") if provider == "ashby" else job.get("id")) is None or not isinstance(job.get("title", job.get("text")), str):
            raise ValueError("Job record lacks an ID or title")
        title = job.get("title", job.get("text"))
        if provider == "greenhouse":
            fields = {key: job.get(key) for key in ("id", "title", "absolute_url", "first_published", "updated_at", "location", "departments", "offices")}
            fields["description"] = _plain(job.get("content"), paragraphs=True)
            fields.update(url=job.get("absolute_url"), published_at=job.get("first_published"))
        elif provider == "ashby":
            fields = {key: job.get(key) for key in ("title", "jobUrl", "publishedAt", "location", "department", "team", "workplaceType", "employmentType")}
            fields["description"] = _plain(job.get("descriptionPlain") or job.get("descriptionHtml"), paragraphs=True)
            fields.update(url=job["jobUrl"], published_at=job.get("publishedAt"))
        else:
            fields = {key: job.get(key) for key in ("id", "text", "hostedUrl", "createdAt", "categories", "workplaceType", "country")}
            text = [_plain(job.get("descriptionPlain") or job.get("description"), paragraphs=True)]
            text.extend(_plain(section.get("text")) + "\n" + _plain(section.get("content"), paragraphs=True)
                        for section in job.get("lists") or [] if isinstance(section, dict))
            fields["description"] = "\n".join(value.strip() for value in text if value.strip())[:12000]
            fields["lists"] = _bounded(job.get("lists") or [], 6000)
            published = job.get("createdAt")
            if isinstance(published, (int, float)) and not isinstance(published, bool):
                try:
                    published = datetime.fromtimestamp(published / 1000, timezone.utc).isoformat()
                except (ValueError, OverflowError, OSError):
                    published = None
            fields.update(title=title, url=job.get("hostedUrl"), published_at=published)
        records.append((str(job["jobUrl"] if provider == "ashby" else job["id"]), title, fields, "job_posting", "job_advertisement"))
    return records, offset > 0 or len(jobs) > maximum


def _company_feed(payload, source_url, maximum):
    parsed = feedparser.parse(payload)
    if parsed.get("bozo") or not str(parsed.get("version", "")).startswith(("rss", "atom")):
        raise ValueError("Company publication response is not valid RSS or Atom")
    records = []
    for entry in parsed.entries[:maximum]:
        location = entry.get("link") or entry.get("id")
        if not isinstance(location, str) or not location.strip():
            continue
        location = _public_url(urljoin(source_url, location))
        date = entry.get("published_parsed") or entry.get("updated_parsed")
        published = datetime.fromtimestamp(calendar.timegm(date), timezone.utc).isoformat() if date else None
        contents = entry.get("content") or []
        description = "\n".join(value.get("value", "") for value in contents if isinstance(value, dict)) or entry.get("summary") or entry.get("description") or ""
        title = _plain(entry.get("title"), 1000)
        fields = {"title": title, "url": location, "description": _plain(description, paragraphs=True), "published_at": published}
        records.append((str(entry.get("id") or location), title or location, fields, "company_article", "company_publication"))
    return records, len(parsed.entries) > maximum


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


def _gleif(item, payload, maximum):
    if not isinstance(payload, dict) or "data" not in payload:
        raise ValueError("GLEIF response lacks JSON API data")
    data = payload["data"]
    rows = data if isinstance(data, list) else [] if data is None else [data]
    meta, links = payload.get("meta") or {}, payload.get("links") or {}
    if not isinstance(meta, dict) or not isinstance(links, dict):
        raise ValueError("GLEIF response metadata and links must be objects")
    pagination = meta.get("pagination", {})
    truncated = bool(links.get("next")) or len(rows) > maximum
    if isinstance(pagination, dict) and isinstance(pagination.get("total"), int):
        truncated = truncated or pagination["total"] > len(rows)
    entities, edges = [], []
    metadata = item.get("metadata") or {}
    child, relation = metadata.get("gleif_child_lei"), metadata.get("gleif_relation")
    if child is not None and (not isinstance(child, str) or not _LEI.fullmatch(child) or relation not in {"direct-parent", "ultimate-parent"}):
        raise ValueError("GLEIF parent context is invalid")
    for row in rows[:maximum]:
        if not isinstance(row, dict) or row.get("type") != "lei-records" or not _LEI.fullmatch(str(row.get("id", ""))):
            raise ValueError("GLEIF result lacks a legal entity identifier")
        attributes = row.get("attributes")
        if not isinstance(attributes, dict) or not isinstance(attributes.get("entity"), dict):
            raise ValueError("GLEIF result lacks legal entity attributes")
        legal_name = attributes["entity"].get("legalName")
        if not isinstance(legal_name, dict) or not isinstance(legal_name.get("name"), str) or not legal_name["name"].strip():
            raise ValueError("GLEIF result lacks a legal name")
        if attributes.get("lei") != row["id"]:
            raise ValueError("GLEIF identifier differs from its attributes")
        fields = {key: attributes[key] for key in ("lei", "entity", "registration", "bic", "ocid") if key in attributes}
        entity, _ = _record(item, "gleif", row["id"], legal_name["name"], fields,
                            kind="legal_entity", role="registry_parent_record" if child else "registry_search_candidate", truncated=truncated)
        entity["id"] = "legal_entity:lei:" + row["id"]
        entities.append(entity)
        if child:
            if child == row["id"]:
                raise ValueError("GLEIF parent cannot be the child itself")
            edges.append({"from_id": "legal_entity:lei:" + child, "to_id": entity["id"],
                          "relation": "reported_" + relation.replace("-", "_"), "source_url": item.get("source_url") or "",
                          "observed_at": entity["observed_at"], "confidence": 1.0})
        elif entity["metadata"]["company_context"].get("company_id"):
            edges.append({"from_id": entity["metadata"]["company_context"]["company_id"], "to_id": entity["id"],
                          "relation": "registry_candidate", "source_url": item.get("source_url") or "",
                          "observed_at": entity["observed_at"], "confidence": 1.0})
    return {"entities": entities, "edges": edges}


def _importyeti(payload, maximum, target):
    soup = BeautifulSoup(payload.decode("utf-8", errors="replace"), "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    if "Import Yeti" not in title and "ImportYeti" not in title:
        raise ValueError("ImportYeti response lacks a public company report")
    title = " ".join(title.split())
    company_name = title.split(" - ", 1)[0].strip()
    normalized = lambda value: re.sub(r"[^a-z0-9]", "", str(value).lower())
    if not target.get("name") or normalized(company_name) != normalized(target["name"]):
        return [], False
    title_parts = title.split(" - ")
    address = title_parts[1] if len(title_parts) >= 4 and "company report" in title_parts[-2].lower() else None
    tables = []
    for table in soup.find_all("table", limit=20):
        headers = [_plain(cell.get_text(" ", strip=True), 200) for cell in table.find_all("th", limit=20)]
        kind = "shipments" if "Bill of Lading" in headers else "hts_products" if "HTS Code" in headers else "suppliers" if any(header.startswith("Suppliers Country") for header in headers) else None
        if not kind:
            continue
        rows = []
        for row in table.find_all("tr", limit=maximum + 2):
            values = [re.sub(r"[\u200b-\u200f\ufeff]", "", cell.get_text(" ", strip=True)).strip()[:2000] for cell in row.find_all("td", recursive=False)]
            if values:
                rows.append(values)
        tables.append((kind, headers, rows))
    if not tables:
        raise ValueError("ImportYeti company report lacks visible trade tables")
    records = []
    total = sum(len(rows) for _, _, rows in tables)
    for kind, headers, rows in tables:
        for values in rows:
            record_key = re.sub(r"\s*\(free\)\s*", " ", values[1]).strip() if kind == "shipments" and len(values) > 1 else values[0]
            identity = hashlib.sha256(json.dumps([kind, normalized(company_name), record_key], ensure_ascii=False).encode()).hexdigest()
            fields = {"company_report": title[:500], "company_name": company_name, "reported_address": address,
                      "table": kind, "columns": headers, "values": values,
                      "visible_public_fields_only": True, "identity_match": "name_candidate", "installed_infrastructure": False}
            records.append((identity, kind.replace("_", " ") + " · " + values[0], fields, "freight_record", "freight_search_candidate"))
            if len(records) >= maximum:
                return records, total > maximum
    return records, total > maximum


def _discovered_links(payload, page_url, domain):
    soup = BeautifulSoup(payload.decode("utf-8", errors="replace"), "html.parser")
    found = {"boards": [], "document_urls": [], "feed_urls": [], "pages": [], "ciks": []}
    for link in soup.find_all("link", href=True, limit=100):
        if "alternate" not in link.get("rel", []) or str(link.get("type", "")).lower().split(";", 1)[0].strip() not in {"application/rss+xml", "application/atom+xml"}:
            continue
        try:
            location = _public_url(urljoin(page_url, link["href"]))
        except (TypeError, ValueError):
            continue
        host = (urlsplit(location).hostname or "").lower()
        if host != domain and not host.endswith("." + domain):
            continue
        if location not in found["feed_urls"]:
            found["feed_urls"].append(location)
        if len(found["feed_urls"]) == 4:
            break
    seen = set()
    for link in soup.find_all(["a", "iframe"], limit=3000):
        value = link.get("href") if link.name == "a" else link.get("src")
        if not isinstance(value, str):
            continue
        try:
            location = _public_url(urljoin(page_url, value))
        except (TypeError, ValueError):
            continue
        if location in seen:
            continue
        seen.add(location)
        parsed = urlsplit(location)
        host, parts = (parsed.hostname or "").lower(), parsed.path.strip("/").split("/")
        slug = None
        provider, region = None, "global"
        if host in {"boards.greenhouse.io", "job-boards.greenhouse.io", "boards.eu.greenhouse.io"}:
            provider, slug = "greenhouse", parts[0]
            if parts[0] == "embed":
                slug = parse_qs(parsed.query).get("for", [None])[0]
        elif host in {"jobs.lever.co", "jobs.eu.lever.co"}:
            provider, slug = "lever", parts[0]
            region = "eu" if host == "jobs.eu.lever.co" else "global"
        elif host == "jobs.ashbyhq.com":
            provider, slug = "ashby", parts[0]
        if host in {"www.sec.gov", "sec.gov"}:
            cik = parse_qs(parsed.query).get("CIK", parse_qs(parsed.query).get("cik", [None]))[0]
            archive = re.match(r"/Archives/edgar/data/(\d{1,10})(?:/|$)", parsed.path)
            cik = cik or (archive.group(1) if archive else None)
            if isinstance(cik, str) and _CIK.fullmatch(cik) and int(cik) and str(int(cik)).zfill(10) not in found["ciks"]:
                found["ciks"].append(str(int(cik)).zfill(10))
        if provider and isinstance(slug, str) and _SLUG.fullmatch(slug):
            board = {"provider": provider, "slug": slug, "region": region, "url": location, "linked_from": page_url}
            if not any(row["provider"] == provider and row["slug"] == slug and row["region"] == region for row in found["boards"]):
                found["boards"].append(board)
        if host == domain or host.endswith("." + domain):
            if parsed.path.lower().endswith((".pdf", ".docx", ".xlsx", ".pptx")) and len(found["document_urls"]) < 4:
                found["document_urls"].append(location)
            elif re.search(r"careers?|jobs|engineering|developers?|blogs?|news|about|investor|reports?", parsed.path + " " + host.removesuffix(domain), re.I) and len(found["pages"]) < 24 and location != page_url:
                found["pages"].append(location)
    found["pages"].sort(key=lambda value: 0 if re.search(r"careers?|jobs", value, re.I) else 1 if re.search(r"engineering|developers?|blogs?|news", value, re.I) else 2)
    priority = [next((value for value in found["pages"] if re.search(pattern, value, re.I)), None)
                for pattern in (r"careers?|jobs", r"engineering|developers?|blogs?|news")]
    found["pages"] = list(dict.fromkeys([value for value in priority if value] + found["pages"]))[:8]
    found["boards"] = found["boards"][:4]
    return found


async def _discover(config, store, http, state):
    from .http import HTTPError
    from .sourcehub import stage_payload
    options = (config.get("provider_settings") or {}).get("corporate_discovery") or {}
    targets = config.get("source_targets") or []
    if not isinstance(targets, list) or any(not isinstance(target, dict) for target in targets):
        raise ValueError("source_targets must be a list of company target objects")
    derived, errors, attempted, staged = [], [], 0, 0
    cache = dict(state.get("discovery") or {})
    candidates = []
    for target in targets:
        domain = target.get("domain")
        if isinstance(domain, str) and re.fullmatch(r"(?=.{1,253}\Z)[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", domain):
            candidates.append((target, domain.lower().rstrip(".")))
    if options.get("enabled") is False or not candidates:
        return targets, state, None
    now, maximum = time.time(), max(1, min(50, int(options.get("batch", 12))))
    cursor = int(state.get("discovery_cursor", 0)) % len(candidates)
    selected = (candidates[cursor:] + candidates[:cursor])[:maximum]
    semaphore = asyncio.Semaphore(max(1, min(8, int(config.get("public_source_concurrency", 4)))))

    async def discover_target(target, domain):
        nonlocal attempted, staged
        cached = cache.get(domain) or {}
        if cached.get("version") == 2 and now - float(cached.get("checked_at", 0)) < 7 * 86400:
            return
        attempted += 1
        found = {"boards": [], "document_urls": [], "feed_urls": [], "pages": [], "ciks": []}
        pages, robots = ["https://" + domain + "/"], {}
        try:
            for index in range(3):
                if index >= len(pages):
                    break
                url = pages[index]
                origin = urlunsplit((*urlsplit(url)[:2], "", "", ""))
                if origin not in robots:
                    parser = RobotFileParser(origin + "/robots.txt")
                    try:
                        response = await http.get(origin + "/robots.txt", max_bytes=128 * 1024, max_attempts=1)
                        parser.parse((await asyncio.to_thread(response.path.read_text, errors="replace")).splitlines())
                    except HTTPError as error:
                        if error.status == 404:
                            parser.parse([])
                        else:
                            raise
                    robots[origin] = parser
                parser = robots[origin]
                agent = config.get("user_agent", "SignalWatch").split("/", 1)[0]
                if not parser.can_fetch(agent, url):
                    raise ValueError("Company robots.txt disallows discovery")
                if index:
                    delay = min(30, parser.crawl_delay(agent) or 0)
                    if delay:
                        await asyncio.sleep(delay)
                response = await http.get(url, max_bytes=2 * 1024 * 1024, max_attempts=1)
                final_url = _public_url(getattr(response, "url", url))
                final_host = (urlsplit(final_url).hostname or "").lower()
                if final_host != domain and not final_host.endswith("." + domain):
                    raise ValueError("Company page redirects outside its configured domain")
                payload = await asyncio.to_thread(response.path.read_bytes)
                content_type = next((value for key, value in response.headers.items() if key.lower() == "content-type"), "")
                if "html" not in content_type.lower() and b"<html" not in payload[:1000].lower():
                    raise ValueError("Company discovery response is not HTML")
                links = _discovered_links(payload, final_url, domain)
                for key in found:
                    found[key].extend(value for value in links[key] if value not in found[key])
                pages.extend(value for value in links["pages"] if value not in pages)
                body = json.dumps({"records": [{"id": final_url, "name": "Company-linked public sources", "links": links}]}, sort_keys=True).encode()
                queued = await stage_payload(config, store, body, provider="corporate_discovery", source_url=final_url,
                                             metadata={"target": {key: target[key] for key in ("name", "domain", "company_id") if target.get(key)}})
                staged += int(not queued.get("duplicate", False))
            cache[domain] = {"checked_at": now, "version": 2, **found}
        except Exception as error:
            status = getattr(error, "status", None)
            errors.append(domain + ": " + ("HTTP " + str(status) if isinstance(status, int) else type(error).__name__))
            cache[domain] = {"checked_at": now - 6 * 86400, "version": 2, **found}

    async def discover_bounded(target, domain):
        async with semaphore:
            await discover_target(target, domain)

    await gather(*(discover_bounded(target, domain) for target, domain in selected))
    for target in targets:
        cached = cache.get(str(target.get("domain", "")).lower()) or {}
        merged = dict(target)
        merged["document_urls"] = list(dict.fromkeys((target.get("document_urls") or []) + cached.get("document_urls", [])))[:20]
        merged["feed_urls"] = list(dict.fromkeys((target.get("feed_urls") or []) + cached.get("feed_urls", [])))[:8]
        if not target.get("cik") and len(cached.get("ciks", [])) == 1:
            merged["cik"] = cached["ciks"][0]
        derived.append(merged)
        for board in cached.get("boards", [])[:4]:
            field = {"greenhouse": "greenhouse_board", "lever": "lever_site", "ashby": "ashby_board"}[board["provider"]]
            if target.get(field) == board["slug"]:
                continue
            derived.append({key: value for key, value in {**target, "document_urls": [], "feed_urls": [], "greenhouse_board": None, "lever_site": None, "ashby_board": None,
                                                        field: board["slug"], "_lever_region": board["region"],
                                                        "_discovered_from": board["linked_from"]}.items() if value is not None})
    valid_domains = {domain for _, domain in candidates}
    state = {**state, "discovery": {key: value for key, value in cache.items() if key in valid_domains},
             "discovery_cursor": (cursor + len(selected)) % len(candidates)}
    return derived, state, {"provider": "corporate_discovery", "name": "Company public evidence discovery",
                           "status": "partial" if errors and staged else "error" if errors else "ok", "attempted": attempted,
                           "staged": staged, "records": staged, "successful": attempted - len(errors), "errors": errors,
                           "cached_targets": len(candidates) - attempted, "pending_targets": max(0, len(candidates) - len(selected))}


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
    offset = metadata.get("record_offset", 0)
    if type(offset) is not int or offset < 0:
        raise ValueError("Corporate record offset must be nonnegative")
    maximum = min(max_records, limit)
    payload = item["payload"]
    if provider == "gleif":
        return _gleif(item, _json(payload), maximum)
    if provider == "importyeti_public":
        records, truncated = _importyeti(payload, maximum, target)
    elif provider in {"greenhouse", "lever", "ashby"}:
        records, truncated = _jobs(provider, _json(payload), maximum, offset)
    elif provider == "company_feeds":
        records, truncated = _company_feed(payload, item.get("source_url") or "", maximum)
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
            if provider == "importyeti_public":
                edge["relation"] = "freight_candidate"
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
        if provider == "corporate_discovery":
            row["reason"] = "No configured company domains to discover"
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
            if target.get("_discovered_from") and provider not in {"greenhouse", "lever", "ashby"}:
                continue
            url, params, headers, private = None, {}, {}, False
            try:
                if provider in {"greenhouse", "lever", "ashby"}:
                    slug = target.get({"greenhouse": "greenhouse_board", "lever": "lever_site", "ashby": "ashby_board"}[provider])
                    if not slug:
                        continue
                    if not isinstance(slug, str) or not _SLUG.fullmatch(slug):
                        raise ValueError("Configured job board ID is invalid")
                    if provider == "greenhouse":
                        url, params = "https://boards-api.greenhouse.io/v1/boards/" + quote(slug, safe="") + "/jobs", {"content": "true"}
                    elif provider == "ashby":
                        url = "https://api.ashbyhq.com/posting-api/job-board/" + quote(slug, safe="")
                    else:
                        host = "api.eu.lever.co" if target.get("_lever_region", options.get("region")) == "eu" else "api.lever.co"
                        url, params = "https://" + host + "/v0/postings/" + quote(slug, safe=""), {"mode": "json"}
                elif provider == "gleif":
                    if not isinstance(target.get("name"), str) or not target["name"].strip():
                        continue
                    url, params = "https://api.gleif.org/api/v1/lei-records", {"filter[entity.legalName]": target["name"].strip()[:300], "page[size]": min(10, maximum)}
                elif provider == "importyeti_public":
                    name = target.get("name")
                    if not isinstance(name, str) or not name.strip():
                        continue
                    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:150]
                    if not slug:
                        continue
                    url = "https://www.importyeti.com/company/" + slug
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
                elif provider in {"company_documents", "company_feeds"}:
                    field = "document_urls" if provider == "company_documents" else "feed_urls"
                    locations = target.get(field) or []
                    if not isinstance(locations, list):
                        raise ValueError(field + " must be an array")
                    for location in locations:
                        requests.append((provider, _public_url(location), {}, {}, target, False))
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
    state = await to_thread(store.source_state, "corporate_sources")
    targets, state, discovery = await _discover(config, store, http, state)
    requests, health = _requests({**config, "source_targets": targets})
    if discovery is not None:
        health["corporate_discovery"] = discovery
    batch_limit = max(1, int(config.get("public_source_batch", 3)))
    record_limit = max(1, min(5000, int(config.get("public_source_records", 100))))
    concurrency = max(1, int(config.get("public_source_concurrency", 4)))
    cursors = dict(state.get("cursors") or {})
    gleif_pages = dict(state.get("gleif_pages") or {})
    for provider, url, params, headers, target, private in requests:
        if provider == "gleif":
            params["page[number]"] = max(1, int(gleif_pages.get(str(target.get("name")), 1)))
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
    job_pages = dict(state.get("job_pages") or {})
    semaphore, sec_lock, trade_lock = asyncio.Semaphore(concurrency), asyncio.Lock(), asyncio.Lock()
    trade_robots = None
    sec_last = 0.0
    maximum = int(float(config.get("staging_max_payload_mb", 8)) * 1024 * 1024)

    async def fetch(request):
        nonlocal sec_last, trade_robots
        provider, url, params, headers, target, private = request
        row = health[provider]
        row["attempted"] += 1
        public_params = {key: value for key, value in params.items() if key != "api_key"}
        source_url = url + ("&" if "?" in url else "?") + urlencode(public_params) if public_params else url
        metadata = {"provider": provider, "target": {key: target[key] for key in ("name", "domain", "company_id", "cik") if target.get(key)}, "record_limit": record_limit}
        if target.get("_discovered_from"):
            metadata["discovered_from"] = target["_discovered_from"]
        if target.get("_gleif_child_lei"):
            metadata.update(gleif_child_lei=target["_gleif_child_lei"], gleif_relation=target["_gleif_relation"])
        job_provider = provider in {"greenhouse", "lever", "ashby"}
        if job_provider:
            metadata["source_binding"] = {"kind": "discovered" if target.get("_discovered_from") else "configured",
                                          "provider": provider, "endpoint_url": url,
                                          "discovered_from": target.get("_discovered_from") or ""}
        identity = hashlib.sha256(json.dumps([provider, url, public_params, metadata], sort_keys=True).encode()).hexdigest()
        phase = "request"
        staged = 0
        try:
            async with semaphore:
                if provider == "importyeti_public":
                    async with trade_lock:
                        if trade_robots is None:
                            parser = RobotFileParser("https://www.importyeti.com/robots.txt")
                            response = await http.get(parser.url, max_bytes=128 * 1024, max_attempts=1)
                            parser.parse((await asyncio.to_thread(response.path.read_text, errors="replace")).splitlines())
                            trade_robots = parser
                    if not trade_robots.can_fetch(config.get("user_agent", "SignalWatch"), url):
                        raise ValueError("ImportYeti robots.txt disallows company-page access")
                if provider == "sec_edgar":
                    async with sec_lock:
                        delay = sec_last + 0.11 - time.monotonic()
                        if delay > 0:
                            await asyncio.sleep(delay)
                        sec_last = time.monotonic()
                response_limit = int(float(config.get("max_response_mb", 32)) * 1024 * 1024) if job_provider else maximum
                response = await http.get(url, params=params or None, headers=headers or None, max_bytes=response_limit,
                                          cache=not private, allow_redirects=not private, max_attempts=1)
                if response.status not in (200, 304):
                    raise ValueError("Provider returned a non-success HTTP status")
                source_url = _public_url(getattr(response, "url", source_url))
                if provider == "importyeti_public":
                    final = urlsplit(source_url)
                    if final.scheme != "https" or final.hostname != "www.importyeti.com" or not re.fullmatch(r"/company/[a-z0-9-]+/?", final.path):
                        raise ValueError("ImportYeti response redirects outside a public company report")
                page = job_pages.get(identity) or {}
                same_jobs = job_provider and page.get("digest") == response.digest
                offset = int(page.get("next_offset", 0)) if same_jobs else 0
                unchanged = same_jobs and page.get("complete") if job_provider else getattr(response, "changed", True) is False and digests.get(identity) == response.digest
                if unchanged and (provider not in {"gleif", "importyeti_public"} or target.get("_gleif_child_lei")):
                    if provider in {"greenhouse", "lever", "ashby", "company_feeds"} and hasattr(store, "touch_technographic_source"):
                        await to_thread(store.touch_technographic_source, source_url, metadata["target"], datetime.now(timezone.utc).isoformat())
                    return provider, {"unchanged": 1, "successful": 1}
                payload = await asyncio.to_thread(response.path.read_bytes)
                content_type = next((value for key, value in response.headers.items() if key.lower() == "content-type"), "application/octet-stream")
                if job_provider:
                    phase = "job board selection"
                    try:
                        parsed = _json(payload)
                        jobs = parsed.get("jobs") if isinstance(parsed, dict) else parsed
                        if not isinstance(jobs, list):
                            raise ValueError("Job board response lacks a jobs array")
                    except ValueError:
                        queued = await stage_payload(config, store, payload, provider=provider, source_url=source_url,
                                                     content_type=content_type, stream_key=identity, metadata=metadata)
                        staged = int(not queued.get("duplicate", False))
                        raise
                    selection = jobs[offset:offset + record_limit]
                    while True:
                        payload = json.dumps({"jobs": selection} if provider != "lever" else selection, ensure_ascii=False, separators=(",", ":")).encode()
                        if len(payload) <= maximum or len(selection) <= 1:
                            break
                        selection = selection[:max(1, len(selection) // 2)]
                    metadata.update(record_offset=0, source_record_offset=offset, source_total_records=len(jobs),
                                    source_response_hash=response.digest, coverage_truncated=offset > 0 or offset + len(selection) < len(jobs))
                phase = "durable staging"
                queued = await stage_payload(config, store, payload, provider=provider, source_url=source_url,
                                             content_type=content_type, stream_key=identity, metadata=metadata)
                staged = int(not queued.get("duplicate", False))
                phase = "provider payload validation"
                preview = normalize_corporate({"id": queued["id"], "source": provider, "source_url": source_url, "payload": payload,
                                               "payload_hash": hashlib.sha256(payload).hexdigest(), "metadata": metadata,
                                               "observed_at": queued.get("observed_at") or datetime.now(timezone.utc).isoformat()}, max_records=record_limit)
                if queued.get("duplicate") and provider in {"greenhouse", "lever", "ashby", "company_feeds"} and hasattr(store, "touch_technographic_source"):
                    await to_thread(store.touch_technographic_source, source_url, metadata["target"], datetime.now(timezone.utc).isoformat())
                if job_provider:
                    next_offset = offset + len(preview["entities"])
                    complete = next_offset >= len(jobs)
                    job_pages[identity] = {"digest": response.digest, "next_offset": 0 if complete else next_offset, "complete": complete}
                digests[identity] = response.digest
                followups = []
                if provider == "gleif" and not target.get("_gleif_child_lei"):
                    parsed = _json(payload)
                    pagination = (parsed.get("meta") or {}).get("pagination", {})
                    if isinstance(pagination, dict):
                        current, last = pagination.get("currentPage", 1), pagination.get("lastPage", 1)
                        if type(current) is int and type(last) is int:
                            gleif_pages[str(target.get("name"))] = current + 1 if current < last else 1
                    for candidate in parsed["data"] if isinstance(parsed["data"], list) else []:
                        if len(followups) == 2:
                            break
                        for relation in ("direct-parent", "ultimate-parent"):
                            links = candidate.get("relationships", {}).get(relation, {}).get("links", {})
                            related = links.get("lei-record") or links.get("related")
                            expected = "https://api.gleif.org/api/v1/lei-records/" + candidate["id"] + "/" + relation
                            if related == expected and len(followups) < 2:
                                followups.append((provider, expected, {}, {}, {**target, "_gleif_child_lei": candidate["id"], "_gleif_relation": relation}, False))
                return provider, {"staged": staged, "records": len(preview["entities"]), "successful": 1,
                                  "truncated": any(entity["metadata"]["coverage_truncated"] for entity in preview["entities"]), "followups": followups,
                                  "unavailable_targets": int(provider == "importyeti_public" and not preview["entities"])}
        except Exception as error:
            status = getattr(error, "status", None)
            if provider == "importyeti_public" and status == 404:
                return provider, {"successful": 1, "unavailable_targets": 1}
            message = "HTTP " + str(status) if isinstance(status, int) else phase.capitalize() + " failed (" + type(error).__name__ + ")"
            return provider, {"error": message, "staged": staged}

    results = await gather(*(fetch(request) for request in selected))
    followups = [request for _, result in results for request in result.get("followups", [])]
    results.extend(await gather(*(fetch(request) for request in followups)))
    totals = {"requests": len(selected) + len(followups) + (discovery or {}).get("attempted", 0),
              "staged": (discovery or {}).get("staged", 0), "records": (discovery or {}).get("records", 0),
              "unchanged": 0, "pending_targets": max(0, len(requests) - len(selected))}
    for provider, result in results:
        row = health[provider]
        for key in ("staged", "records", "unchanged", "successful", "unavailable_targets"):
            row[key] = row.get(key, 0) + result.get(key, 0)
            if key in totals:
                totals[key] += result.get(key, 0)
        if result.get("error"):
            row["errors"].append(result["error"])
        else:
            row["coverage_truncated"] = row.get("coverage_truncated", False) or result.get("truncated", False)
        row["status"] = "partial" if row["errors"] and row["successful"] else "error" if row["errors"] else "ok"
    await to_thread(store.update_source, "corporate_sources", cursors=cursors, digests=digests,
                            gleif_pages=gleif_pages, job_pages=job_pages, discovery=state.get("discovery", {}), discovery_cursor=state.get("discovery_cursor", 0))
    errors = [provider + ": " + message for provider, row in health.items() for message in row["errors"]]
    return {**totals, "errors": errors, "provider_health": health}
