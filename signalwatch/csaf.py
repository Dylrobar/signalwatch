import asyncio
import hashlib
import json
import math
import re
from datetime import datetime, timezone
from urllib.parse import quote, unquote, urljoin, urlsplit

from .async_utils import gather, to_thread
from .extract import canonical_url, cpe_parts, read_json


DEFAULT_CSAF_FEEDS = [
    {"name": "CISA OT", "url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/OT/white/cisa-csaf-ot-feed-tlp-white.json"},
    {"name": "CISA IT", "url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/IT/white/cisa-csaf-it-feed-tlp-white.json"},
    {"name": "CISA vendor advisories", "url": "https://raw.githubusercontent.com/cisagov/CSAF/develop/csaf_files/VA/white/cisa-csaf-va-feed-tlp-white.json"},
    {"name": "Siemens ProductCERT", "url": "https://productcert.siemens.com/productcert/csaf/ssa-feed-tlp-white.json"},
]
PURL_ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI", "maven": "Maven", "golang": "Go", "cargo": "crates.io", "nuget": "NuGet", "gem": "RubyGems", "composer": "Packagist", "hex": "Hex", "pub": "Pub"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def cpe_identity(cpe):
    fields = cpe_parts(cpe) if isinstance(cpe, str) else None
    if not fields and isinstance(cpe, str) and cpe.startswith("cpe:/"):
        parts = cpe[5:].split(":")
        if len(parts) >= 3:
            fields = {"part": parts[0], "vendor": unquote(parts[1]), "product": unquote(parts[2]), "version": unquote(parts[3]) if len(parts) > 3 and parts[3] else "*"}
    if fields and fields.get("part") in {"a", "h", "o"} and fields.get("vendor") not in {None, "", "*", "-"} and fields.get("product") not in {None, "", "*", "-"}:
        return {**fields, "criteria": cpe, "identity_status": "cpe"}
    return None


def purl_identity(purl):
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    parsed = urlsplit(purl)
    path = parsed.path
    if "/" not in path or parsed.query or parsed.fragment:
        return None
    package_type, package_path = path.split("/", 1)
    ecosystem = PURL_ECOSYSTEMS.get(package_type)
    if not ecosystem or not package_path:
        return None
    if package_path.rfind("@") > package_path.rfind("/"):
        package_path, separator, version = package_path.rpartition("@")
    else:
        separator, version = "", ""
    if not package_path:
        return None
    package = unquote(package_path)
    if package_type == "maven":
        if "/" not in package:
            return None
        namespace, name = package.rsplit("/", 1)
        package = f"{namespace}:{name}"
    elif package_type not in {"npm", "golang", "composer"} and "/" in package:
        return None
    identity = {"ecosystem": ecosystem, "package": package, "purl": purl, "identity_status": "purl"}
    if separator and version:
        identity["versions"] = [unquote(version)]
    return identity


def product_identities(product):
    helper = product.get("product_identification_helper") or {}
    if not isinstance(helper, dict):
        return []
    return [identity for identity in (cpe_identity(helper.get("cpe")), purl_identity(helper.get("purl"))) if identity]


def product_catalog(tree):
    products = {}
    def visit(value):
        if isinstance(value, dict):
            if isinstance(value.get("product_id"), str):
                products[value["product_id"]] = value
            for child in value.values():
                if isinstance(child, (dict, list)):
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(tree)
    return products


def parse_csaf(record, source_url):
    document = record.get("document")
    if not isinstance(document, dict) or str(document.get("csaf_version", "")) not in {"2.0", "2.1"}:
        raise ValueError("Unsupported or missing CSAF version")
    tracking = document.get("tracking") or {}
    document_id = tracking.get("id")
    if not isinstance(document_id, str) or not document_id:
        raise ValueError("CSAF document lacks a tracking id")
    publisher = document.get("publisher") or {}
    namespace = publisher.get("namespace") or publisher.get("name") or urlsplit(source_url).netloc
    publisher_name = publisher.get("name") or namespace
    prefix = "CSAF:" + quote(namespace, safe="") + ":" + quote(document_id, safe="") + ":"
    tree = record.get("product_tree") or {}
    products = product_catalog(tree)
    vulnerabilities = record.get("vulnerabilities", [])
    if not isinstance(vulnerabilities, list):
        raise ValueError("CSAF vulnerabilities must be a list")
    advisories = []
    for index, vulnerability in enumerate(vulnerabilities):
        if not isinstance(vulnerability, dict):
            raise ValueError("CSAF vulnerability must be an object")
        cve = vulnerability.get("cve")
        cve = cve.upper() if isinstance(cve, str) and re.fullmatch(r"CVE-\d{4}-\d{4,}", cve, re.I) else None
        identifier = prefix + (cve or "entry-" + str(index))
        status = vulnerability.get("product_status") or {}
        known_affected = status.get("known_affected", [])
        if not isinstance(known_affected, list):
            raise ValueError("CSAF known_affected status must be a list")
        affected = []
        unverified = []
        for product_id in dict.fromkeys(known_affected):
            product = products.get(product_id, {"product_id": product_id})
            identities = product_identities(product)
            if identities:
                affected.extend({**identity, "csaf_product_id": product_id, "csaf_product_name": product.get("name", product_id)} for identity in identities)
            else:
                unverified.append({"product_id": product_id, "name": product.get("name", product_id), "identity_status": "unverified", "product_identification_helper": product.get("product_identification_helper", {})})
        scores = []
        for score in vulnerability.get("scores", []):
            for metric in ("cvss_v4", "cvss_v3", "cvss_v2"):
                value = (score.get(metric) or {}).get("baseScore")
                if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 10:
                    scores.append(float(value))
        notes = [note.get("text", "") for note in vulnerability.get("notes", []) if isinstance(note, dict) and note.get("category") in {"description", "summary", "details"}]
        references = [item["url"] for item in [*document.get("references", []), *vulnerability.get("references", []), *vulnerability.get("remediations", [])] if isinstance(item, dict) and isinstance(item.get("url"), str)]
        advisories.append({
            "id": identifier, "aliases": [cve] if cve else [],
            "title": vulnerability.get("title") or document.get("title") or cve or document_id,
            "summary": "\n\n".join(notes), "published": vulnerability.get("release_date") or tracking.get("initial_release_date"),
            "modified": tracking.get("current_release_date"), "severity": max(scores) if scores else None,
            "source": "CSAF: " + publisher_name, "url": source_url, "affected": affected,
            "references": list(dict.fromkeys([source_url, *references])), "rejected": False,
            "configurations": {"csaf_product_tree": tree, "product_status": status, "remediations": vulnerability.get("remediations", []), "unverified_products": unverified},
            "raw": {"document": document, "vulnerability": vulnerability},
        })
    return {"advisories": advisories}


def parse_feed(record, feed_url, name):
    feed = record.get("feed")
    if not isinstance(feed, dict) or not isinstance(feed.get("entry", []), list):
        raise ValueError("CSAF ROLIE response lacks a feed/entry list")
    documents = []
    for entry in feed.get("entry", []):
        content = entry.get("content") or {}
        url = canonical_url(urljoin(feed_url, content.get("src", ""))) if content.get("src") else ""
        if not url:
            for link in entry.get("link", []):
                href = link.get("href", "")
                if link.get("rel") in {"self", "alternate"} and urlsplit(href).path.lower().endswith(".json"):
                    url = canonical_url(urljoin(feed_url, href))
                    break
        if not url:
            continue
        documents.append({"url": url, "revision": digest(entry), "updated": entry.get("updated") or entry.get("published") or "", "feed_url": feed_url, "feed_name": name})
    pages = [canonical_url(urljoin(feed_url, link.get("href", ""))) for link in feed.get("link", []) if link.get("rel") == "next" and link.get("href")]
    return documents, [url for url in pages if url]


def order_document(item):
    try:
        parsed = datetime.fromisoformat(item.get("updated", "").replace("Z", "+00:00"))
        value = parsed.replace(tzinfo=timezone.utc).timestamp() if parsed.tzinfo is None else parsed.timestamp()
    except (ValueError, AttributeError):
        value = 0
    return bool(item.get("failures")), -value, item["url"]


async def collect_csaf(config, store, http):
    limit = int(config.get("csaf_max_records", 100))
    if limit < 1:
        raise ValueError("csaf_max_records must be positive")
    state = await to_thread(store.source_state, "csaf")
    revisions = dict(state.get("documents", {}))
    pending = {item["url"]: item for item in state.get("pending_documents", [])}
    feed_digests = dict(state.get("feed_digests", {}))
    health = dict(state.get("feed_health", {}))
    configured = config.get("csaf_feeds", DEFAULT_CSAF_FEEDS)
    feeds = [{"name": item, "url": item} if isinstance(item, str) else item for item in configured]
    queue = [(item["url"], item.get("name", item["url"])) for item in feeds]
    queue.extend((item["url"], item.get("name", item["url"])) for item in state.get("pending_feed_pages", []))
    page_limit = len(feeds) + max(1, int(config.get("csaf_feed_pages", 4)))
    visited = set()
    errors = []
    successful_feeds = 0
    processed_pages = 0
    failed_pages = []
    root_urls = {item["url"] for item in feeds}
    while queue and processed_pages < page_limit:
        feed_url, name = queue.pop(0)
        if feed_url in visited:
            continue
        visited.add(feed_url)
        processed_pages += 1
        attempted = datetime.now(timezone.utc).isoformat()
        previous_health = health.get(feed_url, {})
        try:
            response = await http.get(feed_url, max_bytes=16 * 1024 * 1024)
            # A later page can change independently of its parent. Revisit its
            # links even when this page's cached body is unchanged.
            payload = await asyncio.to_thread(read_json, response.path)
            entries, pages = parse_feed(payload, feed_url, name)
            if feed_digests.get(feed_url) != response.digest:
                for entry in entries:
                    if revisions.get(entry["url"], {}).get("revision") != entry["revision"] and pending.get(entry["url"], {}).get("revision") != entry["revision"]:
                        pending[entry["url"]] = entry
                feed_digests[feed_url] = response.digest
            queue.extend((url, name) for url in pages if url not in visited)
            entry_count = len(entries)
            successful_feeds += 1
            health[feed_url] = {**previous_health, "name": name, "url": feed_url, "status": "ok", "ok": True, "last_attempt": attempted, "last_success": datetime.now(timezone.utc).isoformat(), "entries": entry_count, "error": None}
        except Exception as error:
            message = f"{name}: {type(error).__name__}: {error}"
            errors.append(message)
            if feed_url not in root_urls:
                failed_pages.append((feed_url, name))
            health[feed_url] = {**previous_health, "name": name, "url": feed_url, "status": "error", "ok": False, "error": message, "last_attempt": attempted}
    selected = sorted(pending.values(), key=order_document)[:limit]
    semaphore = asyncio.Semaphore(min(8, int(config.get("concurrency", 32))))
    async def fetch(entry):
        async with semaphore:
            try:
                response = await http.get(entry["url"], max_bytes=8 * 1024 * 1024)
                payload = await asyncio.to_thread(read_json, response.path)
                batch = parse_csaf(payload, entry["url"])
                previous = revisions.get(entry["url"], {}).get("records", [])
                identifiers = {item["id"] for item in batch["advisories"]}
                deleted = [{"id": item["id"], "aliases": item.get("aliases", []), "title": item["id"], "summary": "Removed from the publisher's current CSAF document.", "source": "CSAF", "url": entry["url"], "affected": [], "rejected": True, "withdrawn": True} for item in previous if item["id"] not in identifiers]
                await to_thread(store.ingest, {"advisories": [*batch["advisories"], *deleted]})
                return entry, response.digest, batch["advisories"], None
            except Exception as error:
                return entry, None, [], f"{entry['url']}: {type(error).__name__}: {error}"
    results = await gather(*(fetch(entry) for entry in selected))
    records = 0
    advisories = 0
    affected_products = 0
    unverified_products = 0
    for entry, body_digest, items, error in results:
        if error:
            errors.append(error)
            pending[entry["url"]] = {**entry, "failures": int(entry.get("failures", 0)) + 1}
            continue
        revisions[entry["url"]] = {"revision": entry["revision"], "digest": body_digest, "records": [{"id": item["id"], "aliases": item["aliases"]} for item in items]}
        pending.pop(entry["url"], None)
        records += 1
        advisories += len(items)
        affected_products += sum(len(item["affected"]) for item in items)
        unverified_products += sum(len(item["configurations"]["unverified_products"]) for item in items)
    next_pages = [{"url": url, "name": name} for url, name in dict([*(item for item in queue if item[0] not in visited), *failed_pages]).items()]
    await to_thread(store.update_source, "csaf", documents=revisions, pending_documents=sorted(pending.values(), key=order_document), pending_feed_pages=next_pages, feed_digests=feed_digests, feed_health=health)
    if not successful_feeds and not records and errors:
        raise RuntimeError("; ".join(errors)[:2000])
    if selected and not records and errors:
        raise RuntimeError("All selected CSAF documents failed: " + "; ".join(errors)[:2000])
    return {"records": records, "advisories": advisories, "affected_products": affected_products, "unverified_products": unverified_products, "pending": len(pending), "feeds": successful_feeds, "feed_pages_pending": len(next_pages), "feed_health": list(health.values()), "errors": errors, "coverage": "feed_history"}
