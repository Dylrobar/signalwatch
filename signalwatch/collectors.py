import asyncio
import csv
import hashlib
import io
import itertools
import json
import re
import socket
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import ijson
from bs4 import BeautifulSoup

from .async_utils import gather, to_thread
from .companies import asset_identity
from .extract import canonical_url, open_payload, parse_feed, parse_nvd, product_entities, read_json, utcnow
from .http import HTTPError, PublicHTTP, PublicRequestError, display_url
from .web_fingerprints import analyze_http_response
from .web_fingerprint_catalog import load_catalog


NVD_BASE = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MIRROR_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
GITHUB_URL = "https://api.github.com/advisories"
WIKIDATA_URL = "https://query.wikidata.org/sparql"
WEB_RESPONSE_BYTES = 1024 * 1024
WEB_HTML_SAMPLE_BYTES = 250 * 1024


def _html_sample(path):
    with path.open("rb") as stream:
        return stream.read(WEB_HTML_SAMPLE_BYTES).decode("utf-8", errors="replace")


def _web_fingerprints(url, headers, html, cookie_names=(), catalog=None):
    """Keep direct product observations separate from integration/inference labels."""
    findings = analyze_http_response(url, headers, html, cookie_names=cookie_names)
    diagnostics = []
    if catalog is not None:
        catalog_findings, diagnostics = catalog.match(url, headers, html, cookie_names=cookie_names)
        curated = {(finding["product_name"].casefold(), finding["status"]) for finding in findings}
        findings.extend(finding for finding in catalog_findings
                        if (finding["product_name"].casefold(), finding["status"]) not in curated)
        direct_names = {finding["product_name"].casefold() for finding in findings if finding["status"] == "http_detected"}
        findings = [finding for finding in findings if finding["status"] != "implied_dependency"
                    or finding["product_name"].casefold() not in direct_names]
    if len(findings) > 100:
        diagnostics.append("Combined web fingerprint findings capped at 100 per response.")
        findings = findings[:100]
    asset_id, _ = asset_identity(url)
    observed_at = utcnow()
    direct = [
        {**finding, "asset_id": asset_id, "source_url": url,
         "evidence": finding["evidence_snippet"], "observed_at": observed_at}
        for finding in findings if finding["status"] == "http_detected" and finding.get("cpe")
    ]
    # Keep the historical nginx vendor alias used by older NVD records. The
    # curated parser is authoritative for actual evidence and safe snippets.
    for observation in list(direct):
        if observation["vendor"] == "f5" and observation["product"] == "nginx":
            direct.append({**observation, "vendor": "nginx",
                           "cpe": observation["cpe"].replace(":f5:nginx:", ":nginx:nginx:", 1)})
    observations = {}
    for observation in direct:
        part = observation.get("part") or "a"
        key = observation["vendor"], observation["product"], part
        previous = observations.get(key)
        rank = bool(observation.get("version")), observation.get("confidence", 0)
        if previous and rank < (bool(previous.get("version")), previous.get("confidence", 0)):
            continue
        observations[key] = {**observation, "asset_id": asset_id, "part": part, "origin": "web"}
    return findings, list(observations.values()), diagnostics


def _web_evidence_entity(url, findings, observed_at):
    _, host = asset_identity(url)
    return {"id": "web_fingerprint:" + hashlib.sha256(url.encode()).hexdigest(),
            "kind": "web_fingerprint", "name": "HTTP technology evidence: " + host,
            "value": url, "source_url": url, "observed_at": observed_at, "confidence": 1.0,
            "metadata": {"provider": "http_fingerprint", "company_context": {"domain": host},
                         "fingerprints": findings}}


def parse_github(item):
    identifier = item["ghsa_id"]
    aliases = [identifier]
    if item.get("cve_id"):
        aliases.append(item["cve_id"])
    for alias in item.get("identifiers", []):
        if alias.get("value"):
            aliases.append(alias["value"])
    affected = []
    for vulnerability in item.get("vulnerabilities", []):
        package = vulnerability.get("package", {})
        name = package.get("name", "")
        if not name:
            continue
        ecosystem = {"pip": "PyPI", "rust": "crates.io", "composer": "Packagist", "go": "Go", "maven": "Maven", "nuget": "NuGet", "rubygems": "RubyGems", "pub": "Pub", "swift": "SwiftURL", "erlang": "Hex", "actions": "GitHub Actions"}.get(package.get("ecosystem", ""), package.get("ecosystem", ""))
        affected.append({
            "vendor": ecosystem, "product": name,
            "part": "package", "ecosystem": ecosystem,
            "version_range": vulnerability.get("vulnerable_version_range", ""),
            "first_patched_version": vulnerability.get("first_patched_version"),
        })
    score = item.get("cvss", {}).get("score") if item.get("cvss") else None
    if score is None:
        for metric in (item.get("cvss_severities") or {}).values():
            if metric and metric.get("score") is not None:
                score = metric["score"]
                break
    return {
        "id": identifier, "aliases": sorted(set(aliases)), "title": item.get("summary", identifier),
        "summary": item.get("description", ""), "published": item.get("published_at"),
        "modified": item.get("updated_at"), "severity": float(score) if score is not None else None,
        "source": "GitHub Advisory Database", "url": item.get("html_url", f"https://github.com/advisories/{identifier}"),
        "affected": affected, "references": item.get("references", []),
        "rejected": bool(item.get("withdrawn_at")),
    }


def github_timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def next_link(header):
    for part in header.split(","):
        match = re.search(r'<([^>]+)>;\s*rel="next"', part)
        if match:
            return match.group(1)
    return None


def crawl_link_url(base_url, href):
    try:
        url = canonical_url(urljoin(base_url, href.strip()))
    except (ValueError, UnicodeError):
        return ""
    if not url:
        return ""
    # Cloudflare email-obfuscation anchors are decoded by browser JavaScript;
    # they are not pages and commonly return 404 when fetched by a crawler.
    path = urlsplit(url).path
    if path == "/cdn-cgi/l/email-protection" or path.startswith("/cdn-cgi/l/email-protection/"):
        return ""
    return url


class Collector:
    def __init__(self, config, store):
        self.config = config
        self.store = store
        self.http = PublicHTTP(config)
        from .dns import DNSResolver
        self.dns_resolver = DNSResolver(config, self.http)
        self.dns_errors = self.dns_resolver.errors
        self.dns_results = self.dns_resolver.results
        self.robots = {}
        self.robot_errors = {}
        self.robot_locks = {}
        self.discovery_lock = threading.Lock()
        self.discovered_hosts = set()
        self.nvd_next_request = 0
        self.discovery_dirty = 0
        self.web_catalog = None
        self.web_catalog_diagnostics = []

    async def __aenter__(self):
        await self.http.__aenter__()
        state = await self.state("discovery")
        self.discovered_hosts = set(state.get("hosts", []))
        return self

    async def __aexit__(self, *exc):
        try:
            await to_thread(self._save_discovery)
        finally:
            await self.http.__aexit__(*exc)

    def _save_discovery(self):
        with self.discovery_lock:
            self.store.update_source("discovery", hosts=sorted(self.discovered_hosts))
            self.discovery_dirty = 0

    def _enqueue(self, url, source_url="", company_id=None):
        host = urlsplit(url).hostname
        with self.discovery_lock:
            if host not in self.discovered_hosts and len(self.discovered_hosts) >= int(self.config.get("max_discovered_domains", 10000)):
                return False
            new_host = host not in self.discovered_hosts
            self.discovered_hosts.add(host)
            self.store.enqueue_url(url, source_url=source_url, company_id=company_id)
            self.discovery_dirty += int(new_host)
            if self.discovery_dirty >= 100:
                self.store.update_source("discovery", hosts=sorted(self.discovered_hosts))
                self.discovery_dirty = 0
        return True

    async def emit(self, batch):
        return await to_thread(self.store.ingest, batch)

    async def state(self, name):
        return await to_thread(self.store.source_state, name)

    async def checkpoint(self, name, **fields):
        await to_thread(self.store.update_source, name, **fields)

    async def run_source(self, name):
        handler = getattr(self, f"collect_{name}", None)
        if handler is None:
            raise ValueError(f"Unknown source: {name}")
        result = await handler()
        await to_thread(self._save_discovery)
        return {"source": name, **result}

    def _ingest_nvd_path(self, path):
        batch = {"advisories": [], "entities": []}
        count = 0
        entity_count = 0
        queued = 0
        queue_rejected = 0
        reference_hosts = set()
        with open_payload(path) as stream:
            for cve in ijson.items(stream, "vulnerabilities.item.cve", use_float=True):
                record = parse_nvd(cve)
                for reference in cve.get("references", []):
                    if "Vendor Advisory" in reference.get("tags", []):
                        reference_url = canonical_url(reference.get("url", ""))
                        if reference_url:
                            parts = urlsplit(reference_url)
                            if parts.hostname not in reference_hosts:
                                accepted = self._enqueue(f"{parts.scheme}://{parts.netloc}/", reference_url)
                                queued += bool(accepted)
                                queue_rejected += not accepted
                                reference_hosts.add(parts.hostname)
                entities = product_entities(record["affected"], record["url"])
                batch["advisories"].append(record)
                batch["entities"].extend(entities)
                count += 1
                entity_count += len(entities)
                if len(batch["advisories"]) >= 500:
                    self.store.ingest(batch)
                    batch = {"advisories": [], "entities": []}
        if batch["advisories"]:
            self.store.ingest(batch)
        return {"advisories": count, "entities": entity_count, "queued": queued, "queue_rejected": queue_rejected}

    async def _nvd_feed(self, label, previous_hash):
        metadata = await self.http.get(f"{NVD_BASE}{label}.meta")
        meta = dict(line.split(":", 1) for line in metadata.path.read_text().splitlines() if ":" in line)
        digest = meta.get("sha256", "").strip()
        if digest and digest == previous_hash:
            return {"advisories": 0, "entities": 0}, digest
        result = await self.http.get(f"{NVD_BASE}{label}.json.gz", max_bytes=1024 ** 3)
        counts = await to_thread(self._ingest_nvd_path, result.path)
        if counts["advisories"] == 0:
            raise ValueError(f"NVD {label} feed has no CVE records")
        return counts, digest or result.digest

    async def collect_nvd(self):
        totals = await self._collect_nvd_updates()
        if int(self.config.get("nvd_inventory_requests", 4)):
            inventory = await self._nvd_inventory()
            if inventory["requests"]:
                totals["advisories"] = totals.get("advisories", 0) + inventory["advisories"]
                totals["inventory_lookup"] = inventory
                if inventory["errors"]:
                    totals.setdefault("errors", []).extend(inventory["errors"])
        return totals

    async def _collect_nvd_updates(self):
        state = await self.state("nvd")
        hashes = dict(state.get("feed_hashes", {}))
        totals = {"advisories": 0, "entities": 0, "queued": 0, "queue_rejected": 0}
        watermark = state.get("watermark")
        if watermark and datetime.now(timezone.utc) - datetime.fromisoformat(watermark.replace("Z", "+00:00")) > timedelta(days=7):
            backfill = await self._nvd_api(state)
            totals["advisories"] += backfill["advisories"]
            totals["backfill_advisories"] = backfill["advisories"]
            totals["catch_up"] = True
            state = await self.state("nvd")
        feeds = ["modified"] if state.get("initialized") else ["recent", "modified"]
        for feed in feeds:
            try:
                counts, digest = await self._nvd_feed(feed, hashes.get(feed))
            except HTTPError as error:
                if (error.status not in (403, 404)
                        or error.retry_after is not None and error.retry_after > 0):
                    raise
                return await self._nvd_api(state)
            hashes[feed] = digest
            for key, count in counts.items():
                totals[key] += count
            await self.checkpoint("nvd", feed_hashes=hashes)
        await self.checkpoint("nvd", initialized=True, watermark=utcnow())
        return totals

    async def _nvd_api(self, state):
        now = datetime.now(timezone.utc)
        previous = state.get("watermark")
        start = datetime.fromisoformat(previous.replace("Z", "+00:00")) - timedelta(minutes=10) if previous else now - timedelta(days=int(self.config.get("bootstrap_days", 30)))
        headers = {"apiKey": self.config["nvd_api_key"]} if self.config.get("nvd_api_key") else {}
        total = 0
        while start < now:
            end = min(start + timedelta(days=119), now)
            index = 0
            while True:
                params = {"lastModStartDate": start.isoformat(timespec="milliseconds"), "lastModEndDate": end.isoformat(timespec="milliseconds"), "resultsPerPage": 2000, "startIndex": index}
                payload = await self._nvd_page(params, headers)
                rows = payload["vulnerabilities"]
                total_results = payload["totalResults"]
                records = [parse_nvd(row["cve"]) for row in rows]
                await self.emit({"advisories": records, "entities": [entity for record in records for entity in product_entities(record["affected"], record["url"])]})
                total += len(records)
                index += len(records)
                if index >= total_results:
                    break
            await self.checkpoint("nvd", initialized=True, watermark=end.isoformat())
            start = end
        await self.checkpoint("nvd", initialized=True, watermark=now.isoformat())
        return {"advisories": total, "mode": "api_fallback"}

    async def _nvd_page(self, params, headers):
        wait = self.nvd_next_request - time.monotonic()
        if wait > 0:
            await asyncio.sleep(wait)
        self.nvd_next_request = time.monotonic() + (0.7 if headers else 6.1)
        response = await self.http.get("https://services.nvd.nist.gov/rest/json/cves/2.0", params=params, headers=headers, cache=False)
        payload = await asyncio.to_thread(read_json, response.path)
        if (not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list)
                or any(type(payload.get(key)) is not int or payload[key] < 0
                       for key in ("totalResults", "startIndex", "resultsPerPage"))):
            raise ValueError("NVD API response lacks valid records and pagination metadata")
        rows, index = payload["vulnerabilities"], params["startIndex"]
        if (payload["startIndex"] != index or payload["resultsPerPage"] != len(rows)
                or index + len(rows) > payload["totalResults"] or not rows and index < payload["totalResults"]):
            raise ValueError("NVD API returned an incomplete or inconsistent page; the current collection window was not completed")
        return payload

    async def _nvd_inventory(self):
        # Page through historical CVEs for observed products, independently of
        # the recent-update watermark. Keep the request budget and payload small.
        get_targets = getattr(self.store, "nvd_product_targets", lambda: [])
        targets = await to_thread(get_targets)
        state = await self.state("nvd")
        progress = {key: value for key, value in state.get("inventory_lookup", {}).items() if key in targets}
        now = datetime.now(timezone.utc)
        result = {"requests": 0, "advisories": 0, "completed_products": 0, "errors": []}
        headers = {"apiKey": self.config["nvd_api_key"]} if self.config.get("nvd_api_key") else {}
        budget = min(20, max(0, int(self.config.get("nvd_inventory_requests", 4))))
        for cpe in sorted(targets, key=lambda key: (progress.get(key, {}).get("checked_at", ""), key)):
            previous = progress.get(cpe, {})
            checked = previous.get("checked_at")
            if checked and now - datetime.fromisoformat(checked) < timedelta(days=7):
                continue
            if result["requests"] >= budget:
                break
            index = int(previous.get("next_index", 0))
            result["requests"] += 1
            try:
                payload = await self._nvd_page({"virtualMatchString": cpe, "resultsPerPage": 200, "startIndex": index}, headers)
                records = [parse_nvd(row["cve"]) for row in payload["vulnerabilities"]]
                if records:
                    await self.emit({"advisories": records, "entities": [entity for record in records for entity in product_entities(record["affected"], record["url"])]})
                result["advisories"] += len(records)
                next_index = index + len(records)
                complete = next_index >= payload["totalResults"]
                progress[cpe] = {"next_index": 0 if complete else next_index,
                                 "checked_at": now.isoformat() if complete else ""}
                await self.checkpoint("nvd", inventory_lookup=progress)
                result["completed_products"] += int(complete)
            except Exception as error:
                result["errors"].append("NVD inventory lookup: " + str(error)[:500])
                if isinstance(error, HTTPError) and error.status in {401, 403, 429}:
                    break
        return result

    async def bootstrap_year(self, year):
        year = int(year)
        if year < 2002 or year > datetime.now(timezone.utc).year:
            raise ValueError("NVD bootstrap year is outside the available range")
        state = await self.state("nvd")
        hashes = dict(state.get("feed_hashes", {}))
        result, digest = await self._nvd_feed(str(year), hashes.get(str(year)))
        hashes[str(year)] = digest
        await self.checkpoint("nvd", feed_hashes=hashes)
        return {"source": "nvd", "year": year, **result}

    async def collect_kev(self):
        state = await self.state("kev")
        try:
            result = await self.http.get(KEV_URL)
        except (HTTPError, PublicRequestError) as error:
            # CISA maintains the same catalog on GitHub. Transport failures
            # (including a proxy's CONNECT denial) can use that official copy,
            # but an active server or gateway cooldown must still be observed.
            if error.retry_after is not None and error.retry_after > 0:
                raise
            result = await self.http.get(KEV_MIRROR_URL)
        if state.get("digest") == result.digest:
            return {"kev": 0}
        payload = await asyncio.to_thread(read_json, result.path)
        records = payload.get("vulnerabilities")
        if not isinstance(records, list):
            raise ValueError("CISA KEV response has no vulnerabilities list")
        if payload.get("count", len(records)) != len(records) or any(not isinstance(item, dict) or not re.fullmatch(r"CVE-\d{4}-\d{4,}", item.get("cveID", "")) for item in records):
            raise ValueError("CISA KEV snapshot failed count/CVE validation")
        await self.emit({"kev_snapshot": records})
        await self.checkpoint("kev", digest=result.digest, catalog_version=payload.get("catalogVersion"))
        return {"kev": len(records)}

    def _ingest_epss(self, path):
        count = 0
        batch = []
        date = None
        with open_payload(path) as payload:
            stream = io.TextIOWrapper(payload, encoding="utf-8-sig")
            first = next(stream, "")
            if first.startswith("#"):
                match = re.search(r"score_date:([^,\s]+)", first)
                date = match.group(1) if match else None
                rows = csv.DictReader(line for line in stream if not line.startswith("#"))
            else:
                rows = csv.DictReader(itertools.chain([first], stream))
            for row in rows:
                batch.append({"cve": row["cve"], "epss": float(row["epss"]), "percentile": float(row["percentile"]), "date": date or row.get("date")})
                count += 1
                if len(batch) >= 5000:
                    self.store.ingest({"epss": batch})
                    batch = []
        if batch:
            self.store.ingest({"epss": batch})
        if not count:
            raise ValueError("EPSS response contains no score rows")
        return count, date

    async def collect_epss(self):
        state = await self.state("epss")
        result = await self.http.get(EPSS_URL, max_bytes=256 * 1024 * 1024)
        if state.get("digest") == result.digest:
            return {"epss": 0}
        count, date = await to_thread(self._ingest_epss, result.path)
        await self.checkpoint("epss", digest=result.digest, score_date=date)
        return {"epss": count, "date": date}

    async def collect_github(self):
        state = await self.state("github")
        now = datetime.now(timezone.utc)
        start = state.get("watermark") or (now - timedelta(days=int(self.config.get("bootstrap_days", 30)))).isoformat()
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
        token = self.config.get("github_token")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        cursor = state.get("next_url")
        url = cursor or GITHUB_URL
        params = None if cursor else {"per_page": 100, "sort": "updated", "direction": "asc", "modified": f">={github_timestamp(start)}"}
        count = 0
        pages = 0
        page_limit = int(self.config.get("github_pages", 20 if token else 4))
        while url and pages < page_limit:
            result = await self.http.get(url, params=params, headers=headers, cache=False)
            payload = await asyncio.to_thread(read_json, result.path)
            if not isinstance(payload, list):
                raise ValueError("GitHub advisory response is not a list")
            records = [parse_github(item) for item in payload]
            await self.emit({"advisories": records})
            count += len(records)
            pages += 1
            url = next_link(result.headers.get("Link", ""))
            params = None
            await self.checkpoint("github", next_url=url, scan_started=state.get("scan_started") or now.isoformat())
            remaining = int(result.headers.get("X-RateLimit-Remaining", "60"))
            if remaining < 3:
                break
        if not url:
            await self.checkpoint("github", watermark=state.get("scan_started") or now.isoformat(), next_url=None, scan_started=None)
        return {"advisories": count, "pages": pages, "more": bool(url)}

    async def collect_wikidata(self):
        state = await self.state("wikidata")
        retry_at = state.get("retry_at")
        if retry_at:
            remaining = (datetime.fromisoformat(retry_at) - datetime.now(timezone.utc)).total_seconds()
            if remaining > 0:
                raise HTTPError(state.get("retry_status") or 429, WIKIDATA_URL, retry_after=remaining)
        last = state.get("cursor", "")
        last_website = state.get("cursor_website", "")
        batch_size = int(self.config.get("wikidata_batch", 50))
        since = state.get("cycle_completed")
        if since and (datetime.now(timezone.utc) - datetime.fromisoformat(since)).total_seconds() < 7 * 86400:
            return {"companies": 0, "domains": 0}
        type_index = int(state.get("type_index", 0))
        company_types = ("Q783794", "Q4830453", "Q891723")
        filter_clause = ""
        if last:
            company_literal, website_literal = json.dumps(last), json.dumps(last_website)
            filter_clause = f'FILTER(STR(?company) > {company_literal} || (STR(?company) = {company_literal} && STR(?website) > {website_literal}))'
        query = f'''SELECT ?company ?website ?companyLabel WHERE {{
          ?company wdt:P31 wd:{company_types[type_index]} ; wdt:P856 ?website .
          {filter_clause}
          OPTIONAL {{ ?company rdfs:label ?companyLabel . FILTER(LANG(?companyLabel) = "en") }}
        }} ORDER BY STR(?company) STR(?website) LIMIT {batch_size}'''
        try:
            # WDQS has a per-client query-time budget. A throttled query should
            # resume from its current cursor later, rather than consume the
            # remaining budget through immediate retries.
            result = await self.http.get(WIKIDATA_URL, params={"query": query, "format": "json"}, headers={"Accept": "application/sparql-results+json"}, cache=False, max_attempts=1)
        except HTTPError as error:
            if error.status in (429, 503):
                failures = min(int(state.get("retry_failures") or 0) + 1, 6)
                wait = max(error.retry_after or 0, min(24 * 3600, 3600 * 2 ** (failures - 1)))
                retry_at = datetime.fromtimestamp(min(time.time() + wait, 253402300799), timezone.utc).isoformat()
                await self.checkpoint("wikidata", retry_at=retry_at, retry_failures=failures, retry_status=error.status)
            raise
        payload = await asyncio.to_thread(read_json, result.path)
        rows = payload.get("results", {}).get("bindings")
        if not isinstance(rows, list):
            raise ValueError("Wikidata response has no bindings")
        entities = {}
        edges = []
        urls = set()
        now = utcnow()
        for row in rows:
            company_url = row["company"]["value"]
            qid = company_url.rsplit("/", 1)[-1]
            company_id = f"company:wikidata:{qid}"
            label = row.get("companyLabel", {}).get("value", qid)
            entities[company_id] = {"id": company_id, "kind": "company", "name": label, "value": qid, "metadata": {"wikidata": qid}, "source_url": company_url, "observed_at": now, "confidence": 1.0}
            url = canonical_url(row.get("website", {}).get("value", ""))
            if not url:
                continue
            host = urlsplit(url).hostname
            domain_id = f"domain:{host}"
            entities[domain_id] = {"id": domain_id, "kind": "domain", "name": host, "value": host, "metadata": {"official_website": url}, "source_url": company_url, "observed_at": now, "confidence": 1.0}
            edges.append({"from_id": company_id, "to_id": domain_id, "relation": "official_website", "source_url": company_url, "observed_at": now, "confidence": 1.0})
            urls.add((url, company_url, company_id))
        await self.emit({"entities": list(entities.values()), "edges": edges})
        queued = 0
        for url, source_url, company_id in sorted(urls):
            queued += bool(await to_thread(self._enqueue, url, source_url=source_url, company_id=company_id))
        companies = sum(entity["kind"] == "company" for entity in entities.values())
        if rows:
            cursor, website = max((row["company"]["value"], row["website"]["value"]) for row in rows)
            await self.checkpoint("wikidata", cursor=cursor, cursor_website=website, type_index=type_index, cycle_completed=None, retry_at=None, retry_failures=0, retry_status=None)
        elif type_index + 1 < len(company_types):
            await self.checkpoint("wikidata", cursor="", cursor_website="", type_index=type_index + 1, cycle_completed=None, retry_at=None, retry_failures=0, retry_status=None)
        else:
            await self.checkpoint("wikidata", cursor="", cursor_website="", type_index=0, cycle_completed=now, retry_at=None, retry_failures=0, retry_status=None)
        return {"companies": companies, "domains": len(urls), "queued": queued, "queue_rejected": len(urls) - queued,
                "pending": bool(rows) or type_index + 1 < len(company_types), "coverage": "official_company_sites"}

    async def collect_news(self):
        state = await self.state("news")
        feeds = list({feed["url"]: feed for feed in self.config.get("feeds", [])}.values())
        digests = {feed["url"]: state.get("feed_digests", {}).get(feed["url"]) for feed in feeds}
        health = {feed["url"]: dict(state.get("feed_health", {}).get(feed["url"], {})) for feed in feeds}
        started = utcnow()
        outcomes = [None] * len(feeds)
        async def collect(feed):
            name, url = feed["name"], feed["url"]
            previous = health[url]
            health[url] = {**previous, "name": name, "url": url, "last_attempt": utcnow(),
                           "last_success": previous.get("last_success"), "articles": previous.get("articles", 0)}
            try:
                result = await self.http.get(url)
                if digests.get(url) == result.digest and previous.get("validated"):
                    health[url].update(status="unchanged", last_success=utcnow(), error=None)
                    return [], None, True
                articles = await asyncio.to_thread(parse_feed, result.path, name, url)
                digests[url] = result.digest
                health[url].update(status="ok", last_success=utcnow(), error=None, articles=len(articles), validated=True)
                return articles, None, False
            except Exception as error:
                message = str(error) or type(error).__name__
                health[url].update(status="error", error=message[:1000], validated=False)
                return [], f"{name}: {message}", False
        pending = iter(enumerate(feeds))
        async def worker():
            for index, feed in pending:
                outcomes[index] = await collect(feed)
        workers = min(len(feeds), max(1, min(int(self.config["concurrency"]), int(self.config.get("news_concurrency", 8)))))
        await gather(*(worker() for _ in range(workers)))
        merged = {}
        for articles, _, _ in outcomes:
            for article in articles:
                url = article["url"]
                contribution = {key: article.get(key) for key in ("source", "title", "summary", "published", "cves", "guid")}
                previous = merged.get(url)
                if previous is None:
                    merged[url] = {**article, "feed_records": {article["feed_url"]: contribution}}
                else:
                    records = {**previous["feed_records"], article["feed_url"]: contribution}
                    preferred = max((previous, article), key=lambda row: (len(row.get("summary") or ""), len(row.get("title") or "")))
                    merged[url] = {**preferred, "feed_records": records}
        for article in merged.values():
            records = article["feed_records"]
            article["cves"] = sorted({cve for record in records.values() for cve in record.get("cves") or []})
            article["feed_urls"] = sorted(records)
            article["feed_sources"] = sorted({record["source"] for record in records.values() if record.get("source")})
        if merged:
            await self.emit({"articles": list(merged.values())})
        errors = [error for _, error, _ in outcomes if error]
        coverage = {"configured": len(feeds), "attempted": len(outcomes), "successful": len(outcomes) - len(errors),
                    "unchanged": sum(unchanged for _, _, unchanged in outcomes), "failed": len(errors),
                    "started_at": started, "finished_at": utcnow()}
        await self.checkpoint("news", feed_digests=digests, feed_health=health, coverage=coverage)
        if errors and len(errors) == len(outcomes):
            raise RuntimeError("; ".join(errors))
        return {"articles": len(merged), "errors": errors, **{key: coverage[key] for key in ("configured", "attempted", "successful", "unchanged", "failed")}}

    async def _can_fetch(self, url):
        parts = urlsplit(url)
        origin = f"{parts.scheme}://{parts.netloc}"
        lock = self.robot_locks.setdefault(origin, asyncio.Lock())
        async with lock:
            if origin in self.robot_errors:
                raise self.robot_errors[origin]
            if origin not in self.robots or time.time() - self.robots[origin].mtime() > 3600:
                parser = RobotFileParser()
                try:
                    result = await self.http.get(origin + "/robots.txt", max_bytes=2 * 1024 * 1024)
                    parser.parse(result.path.read_text(errors="replace").splitlines())
                except HTTPError as error:
                    if error.status in (401, 403):
                        parser.parse(["User-agent: *", "Disallow: /"])
                    elif error.status == 404:
                        parser.parse([])
                    else:
                        self.robot_errors[origin] = error
                        raise
                except Exception as error:
                    self.robot_errors[origin] = error
                    raise
                self.robots[origin] = parser
        return self.robots[origin].can_fetch(self.config["user_agent"].split("/", 1)[0], url)

    async def _resolve(self, host, source_url):
        result = await self.dns_resolver.resolve(host)
        return result.graph(host, source_url)

    async def _crawl(self, target):
        manage_queue = target.get("_manage_queue", True)
        seed = canonical_url(target["url"])
        if not seed:
            if manage_queue:
                await to_thread(self.store.finish_url, target["url"], error="Invalid HTTP URL")
            return {"pages": 0, "observations": 0, "error": "Invalid HTTP URL"}
        asset_id, host = asset_identity(seed)
        touched_assets = {asset_id}
        queue = [(seed, 0)]
        seen = set()
        pages = 0
        observed = 0
        fingerprint_count = 0
        errors = []
        max_pages = int(self.config["crawl_pages"])
        max_depth = int(self.config.get("crawl_depth", 1))
        domain = {"id": asset_id, "kind": "domain", "name": host, "value": host, "metadata": {}, "source_url": target.get("source_url") or seed, "observed_at": utcnow(), "confidence": 1.0}
        ips, edges = await self._resolve(host, seed)
        await self.emit({"entities": [domain, *ips], "edges": edges})
        while queue and pages < max_pages:
            url, depth = queue.pop(0)
            if url in seen:
                continue
            seen.add(url)
            visited = [url]
            try:
                for redirect in range(6):
                    if not await self._can_fetch(url):
                        raise ValueError(f"robots.txt disallows {display_url(url)}")
                    response = await self.http.get(url, allow_redirects=False, max_bytes=WEB_RESPONSE_BYTES)
                    if response.status not in (301, 302, 303, 307, 308):
                        break
                    url = canonical_url(urljoin(url, response.headers.get("Location", "")))
                    if not url:
                        raise ValueError("Invalid HTTP redirect")
                    visited.append(url)
                else:
                    raise ValueError("Too many HTTP redirects")
                content_type = response.headers.get("Content-Type", "").lower()
                is_html = not content_type or any(kind in content_type for kind in ("text/html", "application/xhtml"))
                final_url = canonical_url(response.url)
                final_asset_id, final_host = asset_identity(final_url)
                html = await asyncio.to_thread(_html_sample, response.path) if is_html else ""
                unchanged = response.status == 304
                if unchanged:
                    # Cached bytes remain useful for following links, but a
                    # revalidation is not another direct technology observation.
                    findings, observations, diagnostics = [], [], []
                else:
                    findings, observations, diagnostics = await asyncio.to_thread(_web_fingerprints, final_url, response.headers, html, getattr(response, "cookie_names", ()), self.web_catalog)
                self.web_catalog_diagnostics = list(dict.fromkeys([*self.web_catalog_diagnostics, *diagnostics]))[:20]
                timestamp = utcnow()
                if unchanged:
                    await to_thread(self.store.touch_technographic_source, final_url, {"domain": final_host}, timestamp)
                batch = {"observations": [{**item, "observed_at": timestamp} for item in observations],
                         "observation_pages": [], "entities": [], "edges": []}
                for page in sorted(set([*visited, final_url])):
                    page_asset_id, page_host = asset_identity(page)
                    touched_assets.add(page_asset_id)
                    if unchanged and page == final_url:
                        batch["entities"].append({"id": page_asset_id, "kind": "domain", "name": page_host,
                                                  "value": page_host, "source_url": page, "observed_at": timestamp})
                        continue
                    # A redirect is also a replacement of any previous evidence
                    # at that URL. Only the actual response host gets findings.
                    evidence = _web_evidence_entity(page, findings if page == final_url else [], timestamp)
                    batch["observation_pages"].append({"asset_id": page_asset_id, "source_url": page})
                    batch["entities"].extend([
                        {"id": page_asset_id, "kind": "domain", "name": page_host, "value": page_host,
                         "metadata": {}, "source_url": page, "observed_at": timestamp, "confidence": 1.0},
                        evidence,
                    ])
                    batch["edges"].append({"from_id": page_asset_id, "to_id": evidence["id"],
                                           "relation": "has_public_evidence", "source_url": page,
                                           "observed_at": timestamp, "confidence": 1.0})
                if final_asset_id != asset_id:
                    batch["edges"].append({"from_id": asset_id, "to_id": final_asset_id, "relation": "redirects_to", "source_url": url, "observed_at": timestamp, "confidence": 1.0})
                await self.emit(batch)
                pages += 1
                observed += len(observations)
                fingerprint_count += len(findings)
                if is_html and depth < max_depth:
                    soup = await asyncio.to_thread(BeautifulSoup, html, "html.parser")
                    links = []
                    for link in soup.find_all("a", href=True, limit=1000):
                        href = crawl_link_url(final_url, str(link["href"]))
                        if not href or urlsplit(href).hostname != final_host or href in seen:
                            continue
                        if re.search(r"\.(?:pdf|zip|gz|tar|png|jpg|jpeg|gif|svg|mp4|webm|woff2?|css|js)(?:$|\?)", href, re.I):
                            continue
                        links.append(href)
                    queue.extend((href, depth + 1) for href in sorted(set(links))[:max_pages])
            except Exception as error:
                errors.append(str(error))
        error = "; ".join(dict.fromkeys(errors))[:2000] if errors else None
        if manage_queue:
            await to_thread(self.store.finish_url, target["url"], error=error)
        return {"pages": pages, "observations": observed, "fingerprints": fingerprint_count,
                "asset_ids": sorted(touched_assets), "error": error}

    async def collect_web(self, *, targets=None, progress=None):
        scoped = targets is not None
        self.robot_errors.clear()
        self.dns_errors.clear()
        self.dns_results.clear()
        self.web_catalog = None
        self.web_catalog_diagnostics = []
        if self.config.get("web_fingerprint_catalog", True):
            self.web_catalog, self.web_catalog_diagnostics = await load_catalog(self.http, self.config["cache_dir"])
        candidates = []
        if not scoped:
            for url in self.config.get("seed_urls", []):
                url = canonical_url(url)
                if url:
                    await to_thread(self._enqueue, url, source_url=url)
            candidates = await to_thread(self.store.company_crawl_candidates,
                                                [target.get("domain") for target in self.config.get("source_targets", [])],
                                                int(self.config["crawl_batch"]))
        discovered = 0
        scope_edges = []
        scope_domains = {}
        for candidate in candidates:
            accepted = await to_thread(self._enqueue, "https://" + candidate["domain"] + "/", source_url=candidate["source_url"])
            if accepted:
                discovered += 1
                scope_domains[candidate["scope"]] = {"id": "domain:" + candidate["scope"], "kind": "domain",
                    "name": candidate["scope"], "value": candidate["scope"], "_reference_only": True,
                    "source_url": candidate["source_url"], "observed_at": candidate["observed_at"]}
                scope_edges.append({"from_id": candidate["record_id"], "to_id": "domain:" + candidate["scope"],
                                    "relation": "certificate_lookup_scope", "source_url": candidate["source_url"],
                                    "observed_at": candidate["observed_at"], "confidence": 1.0})
        if scope_edges:
            await self.emit({"entities": list(scope_domains.values()), "edges": scope_edges})
        if scoped:
            if not isinstance(targets, (list, tuple)) or len(targets) > min(100, int(self.config["crawl_batch"])):
                raise ValueError("Explicit web targets exceed the configured collection batch")
            selected = []
            for target in targets:
                if not isinstance(target, dict) or not isinstance(target.get("url"), str) or not canonical_url(target["url"]):
                    raise ValueError("Explicit web targets require valid HTTP(S) URLs")
                selected.append({**target, "_manage_queue": False})
            targets = selected
        else:
            targets = await to_thread(self.store.crawl_targets, int(self.config["crawl_batch"]), float(self.config["crawl_interval_hours"]))
        semaphore = asyncio.Semaphore(int(self.config["concurrency"]))
        completed = 0
        progress_lock = asyncio.Lock()
        if progress is not None:
            await progress("collecting", completed=0, total=len(targets), unit="targets")
        async def crawl(target):
            nonlocal completed
            async with semaphore:
                result = await self._crawl(target)
                if progress is not None:
                    async with progress_lock:
                        completed += 1
                        await progress("collecting", completed=completed, total=len(targets), unit="targets")
                return result
        results = await gather(*(crawl(target) for target in targets))
        errors = [row["error"] for row in results if row["error"]]
        if results and not any(row["pages"] for row in results) and errors:
            raise RuntimeError("All crawl targets failed: " + "; ".join(errors)[:2000])
        dns_errors = [message for host in sorted(self.dns_errors) for message in self.dns_errors[host]]
        return {"targets": len(targets), "pages": sum(row["pages"] for row in results), "observations": sum(row["observations"] for row in results),
                "asset_ids": sorted({asset_id for row in results for asset_id in row.get("asset_ids", [])}),
                "fingerprints": sum(row.get("fingerprints", 0) for row in results),
                "fingerprint_catalog": {"enabled": bool(self.config.get("web_fingerprint_catalog", True)),
                                        "loaded": self.web_catalog is not None,
                                        **(self.web_catalog.metadata if self.web_catalog is not None else {}),
                                        "diagnostics": list(dict.fromkeys(self.web_catalog_diagnostics))[:20]},
                "company_hosts_considered": len(candidates), "company_hosts_queued": discovered,
                "dns_hosts": len(self.dns_results), "dns_records": sum(record["type"] in {"A", "AAAA"} for result in self.dns_results.values() for record in result.records),
                "dns_failed": len(self.dns_errors), "dns_fallbacks": sum(result.mode == "doh" and bool(result.system_error) for result in self.dns_results.values()), "errors": [*errors, *dns_errors]}
