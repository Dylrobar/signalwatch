import asyncio
import base64
import csv
import hashlib
import io
import ipaddress
import json
import math
import re
import time
from datetime import datetime, timezone
from urllib.parse import urlencode, urlsplit, urlunsplit

from .async_utils import gather, to_thread
from .normalization import NormalizationError
from .http import HTTPError, public_error, retry_delay


SOURCE_DEFINITIONS = [
    {"id": "certspotter", "name": "Cert Spotter certificate transparency", "access": "public", "homepage": "https://sslmate.com/help/reference/ct_search_api_v1", "required": [], "description": "Incremental unexpired certificate issuances; limited keyless personal/evaluation access (10 queries/hour observed). Production access requires an account. Names remain provider evidence."},
    {"id": "ctlogs", "name": "ctlogs.dev certificate hostnames", "access": "public", "homepage": "https://api.ctlogs.dev/", "required": [], "description": "Public no-key hostname index, one request at a time and 100 requests/hour shared pool. Certificates valid now or expired within 90 days; anonymous pagination stops at 10 pages."},
    {"id": "crtsh", "name": "crt.sh certificate transparency", "access": "public", "homepage": "https://crt.sh/", "required": [], "description": "Certificate names from the public CT index; certificate presence does not establish a live host or corporate ownership."},
    {"id": "passive_dns", "name": "HackerTarget passive host search", "access": "public", "homepage": "https://hackertarget.com/find-dns-host-records/", "required": [], "description": "Indexed hostname/IP pairs; free endpoint is limited to 20 queries/day and 50 results/request."},
    {"id": "dns_txt", "name": "Public DNS TXT / SPF / DMARC / DKIM", "access": "public", "homepage": "https://developers.google.com/speed/public-dns/docs/doh/json", "required": [], "description": "Google DNS JSON TXT answers; DKIM selectors must be explicitly configured per target."},
    {"id": "shodan", "name": "Shodan indexed banners", "access": "api_key", "homepage": "https://developer.shodan.io/api", "required": ["api_key"], "description": "Read-only indexed host search; filtered queries require account query credits."},
    {"id": "censys", "name": "Censys Platform search", "access": "api_key", "homepage": "https://docs.censys.com/reference/v3-globaldata-search-query", "required": ["api_key", "query"], "description": "Current Platform POST search requires a Personal Access Token, API access, and explicit CenQL query."},
    {"id": "fofa", "name": "FOFA indexed assets", "access": "api_key", "homepage": "https://fofapro.github.io/fofa-py/fofa.html", "required": ["api_key"], "description": "Read-only indexed asset search using base64 queries and explicit result fields; account limits apply."},
    {"id": "zoomeye", "name": "ZoomEye indexed assets", "access": "api_key", "homepage": "https://github.com/zoomeye-ai/ZoomEye-python/blob/master/api.md", "required": ["api_key"], "description": "Current v2 POST search with API-KEY authentication; subscription and point limits apply."},
    {"id": "netlas", "name": "Netlas indexed responses", "access": "api_key", "homepage": "https://docs.netlas.io/api-reference/", "required": ["api_key"], "description": "Read-only Responses Search with Bearer authentication; first result page is bounded by the provider to 20 records."},
]
for _provider, _name, _homepage, _description in [
    ("dnsdumpster", "DNSDumpster", "https://dnsdumpster.com/", "Configured public export URL; no automated form or challenge bypass."),
    ("securitytrails", "SecurityTrails", "https://docs.securitytrails.com/", "Configured authorized DNS history export URL; subscription feeds are not assumed public."),
    ("rapiddns", "RapidDNS", "https://rapiddns.io/", "Configured public export URL; source records retain the provider report without ownership inference."),
    ("bgpview", "BGPView", "https://bgpview.io/", "Configured routing export URL. Existing RIPEstat collection already supplies announcing ASN and prefix context."),
    ("he_bgp", "Hurricane Electric BGP Toolkit", "https://bgp.he.net/", "Configured public routing export URL; existing RIPEstat collection supplies routing context."),
    ("arin", "ARIN registry", "https://www.arin.net/resources/registry/whois/rdap/", "Configured public RDAP/registry export URL; registration is distinct from deployment attribution."),
]:
    SOURCE_DEFINITIONS.append({"id": _provider, "name": _name, "access": "configured_url", "homepage": _homepage, "required": ["url"], "description": _description})
for _definition in SOURCE_DEFINITIONS:
    _definition.update(category="network", family="exposure")

ENDPOINTS = {"certspotter": "https://api.certspotter.com/v1/issuances", "ctlogs": "https://api.ctlogs.dev/v1/hosts/", "crtsh": "https://crt.sh/", "passive_dns": "https://api.hackertarget.com/hostsearch/", "dns_txt": "https://dns.google/resolve", "shodan": "https://api.shodan.io/shodan/host/search", "censys": "https://api.platform.censys.io/v3/global/search/query", "fofa": "https://fofa.info/api/v1/search/all", "zoomeye": "https://api.zoomeye.ai/v2/search", "netlas": "https://app.netlas.io/api/responses/"}
FOFA_FIELDS = ("ip", "port", "host", "protocol", "title", "domain", "server", "os")
CT_PROVIDERS = ("certspotter", "ctlogs", "crtsh")


def _passive_dns_budget(store, clock, *, reserve=False, retry_at=0):
    """Reserve before sending so retries, restarts and concurrent runs share one quota."""
    key = "exposure_passive_dns_budget"
    with store.connection(write=True) as conn:
        row = conn.execute("SELECT state FROM sources WHERE name=?", (key,)).fetchone()
        state = json.loads(row[0]) if row else {}
        stamps = sorted(stamp for stamp in state.get("request_times", [])
                        if isinstance(stamp, (int, float)) and math.isfinite(stamp) and stamp > clock - 86400)
        deadline = max(float(state.get("retry_at") or 0), retry_at)
        if len(stamps) >= 20:
            deadline = max(deadline, stamps[-20] + 86400)
        allowed = deadline <= clock and len(stamps) < 20
        if reserve and allowed:
            stamps.append(clock)
        state.update(request_times=stamps, retry_at=deadline if deadline > clock else 0)
        conn.execute("INSERT INTO sources(name,state) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET state=excluded.state",
                     (key, json.dumps(state, separators=(",", ":"))))
    return {"allowed": allowed, "retry_at": deadline if deadline > clock else 0,
            "remaining": max(0, 20 - len(stamps))}


def _passive_dns_quota(payload):
    text = " ".join(payload[:512].decode("utf-8-sig", errors="replace").lower().split())
    return bool(re.match(r"^(?:error\s*:\s*)?(?:api (?:count|limit) exceeded|daily (?:api |query )?limit exceeded|rate limit exceeded)", text))


def _domain(value):
    if not isinstance(value, str):
        raise NormalizationError("Network record requires a domain name")
    try:
        name = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise NormalizationError("Invalid network domain name") from exc
    if len(name) > 253 or not name or any(not re.fullmatch(r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?", label) for label in name.split(".")):
        raise NormalizationError("Invalid network domain name")
    return name


def _json(item):
    try:
        return json.loads(item["payload"].decode("utf-8-sig"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise NormalizationError("Network provider returned invalid JSON") from exc


def _records(item, provider):
    if provider not in ENDPOINTS:
        if item["payload"].lstrip().startswith((b"{", b"[")):
            value = _json(item)
            return value if isinstance(value, list) else [value]
        return [{"text": item["payload"].decode("utf-8", errors="replace")[:12000]}]
    if provider == "passive_dns":
        try:
            text = item["payload"].decode("utf-8-sig")
        except UnicodeError as exc:
            raise NormalizationError("Passive DNS response must be UTF-8") from exc
        if text.lstrip().startswith(("{", "[")):
            value = _json(item)
            rows = value.get("records") if isinstance(value, dict) else value
            if not isinstance(rows, list):
                raise NormalizationError("Passive DNS JSON requires a records array")
            return rows
        if text.strip().lower() in ("", "no records found", "no results found"):
            return []
        rows = []
        for fields in csv.reader(io.StringIO(text)):
            if len(fields) != 2:
                raise NormalizationError("Passive DNS response is not hostname/IP CSV")
            name, address = fields
            rows.append({"domain": _domain(name), "ip": str(ipaddress.ip_address(address.strip()))})
        return rows
    value = _json(item)
    if provider == "certspotter":
        rows = value
        if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("id"), str) or not row["id"] or not isinstance(row.get("dns_names"), list) or any(not isinstance(name, str) for name in row["dns_names"]) for row in rows):
            raise NormalizationError("Cert Spotter response lacks issuance IDs and DNS names")
    elif provider == "ctlogs":
        if not isinstance(value, dict) or type(value.get("has_next")) is not bool or not isinstance(value.get("next_cursor"), str) or value["has_next"] and not value["next_cursor"]:
            raise NormalizationError("ctlogs.dev response lacks pagination metadata")
        rows = value.get("hosts")
        if not isinstance(rows, list) or any(not isinstance(row, dict) or not isinstance(row.get("host"), str) for row in rows):
            raise NormalizationError("ctlogs.dev response lacks hostname records")
    elif provider == "crtsh":
        rows = value
    elif provider == "dns_txt":
        if not isinstance(value, dict) or type(value.get("Status")) is not int or value["Status"] not in (0, 3):
            raise NormalizationError("DNS resolver returned a failed response")
        rows = value.get("Answer", [])
    elif not isinstance(value, dict):
        raise NormalizationError("Network indexer response must be an object")
    elif provider == "shodan":
        if value.get("error"):
            raise NormalizationError("Shodan rejected the query")
        rows = value.get("matches")
    elif provider == "censys":
        result = value.get("result")
        if not isinstance(result, dict):
            raise NormalizationError("Censys response lacks its result envelope")
        rows = result.get("hits")
        if rows is None and result.get("total_hits") == 0:
            rows = []
    elif provider == "fofa":
        if value.get("error") is not False:
            raise NormalizationError("FOFA rejected the query")
        fields = (item.get("metadata") or {}).get("fields", FOFA_FIELDS)
        rows = value.get("results")
        if isinstance(rows, list):
            if any(not isinstance(row, list) or len(row) != len(fields) for row in rows):
                raise NormalizationError("FOFA results do not match the requested field order")
            rows = [dict(zip(fields, row)) for row in rows]
    elif provider == "zoomeye":
        if value.get("code") != 60000:
            raise NormalizationError("ZoomEye export is not a successful v2 response")
        rows = value.get("data")
    elif provider == "netlas":
        rows = value.get("items")
        if isinstance(rows, list):
            rows = [row.get("data") if isinstance(row, dict) else None for row in rows]
    else:
        raise NormalizationError("Unknown network provider")
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise NormalizationError("Network provider response lacks a record array")
    return rows


def normalize_network(item, max_records=5000):
    metadata = item.get("metadata") or {}
    provider = metadata.get("provider")
    if provider not in {definition["id"] for definition in SOURCE_DEFINITIONS}:
        raise NormalizationError("Unknown network provider")
    if max_records < 1:
        raise NormalizationError("Network normalization record limit must be positive")
    limit = min(max_records, max(1, int(metadata.get("record_limit", 100))))
    target = _domain(metadata["target_domain"]) if metadata.get("target_domain") else ""
    records = _records(item, provider)
    entities, edges, anchors = [], [], set()
    stamp = item.get("observed_at") or item.get("received_at")
    provenance = {"id": item.get("id"), "source": item.get("source", provider), "payload_hash": item.get("payload_hash"), "raw_reference": "staging:" + str(item.get("id")), "observed_at": stamp}

    def anchor(kind, value, record_id, relation="reports_on"):
        entity_id = kind + ":" + value
        if entity_id not in anchors:
            anchors.add(entity_id)
            entities.append({"id": entity_id, "kind": kind, "name": value, "value": value, "metadata": {}, "source_url": "", "observed_at": stamp})
        edges.append({"from_id": record_id, "to_id": entity_id, "relation": relation, "source_url": item.get("source_url", ""), "observed_at": stamp, "confidence": 1.0})

    for record in records[:limit]:
        if not isinstance(record, dict):
            raise NormalizationError("Network provider record must be an object")
        names, addresses = [], []
        record_type = "indexed_service"
        if provider in CT_PROVIDERS:
            record_type = "certificate_name"
            raw_names = record["dns_names"] if provider == "certspotter" else [record["host"]] if provider == "ctlogs" else str(record.get("name_value") or record.get("common_name") or "").splitlines()
            for name in raw_names[:100]:
                try:
                    domain = _domain(name.removeprefix("*."))
                except (NormalizationError, UnicodeError):
                    continue
                if not target or domain == target or domain.endswith("." + target):
                    names.append(domain)
            if not names:
                continue
        elif provider == "dns_txt":
            if record.get("type") != 16:
                continue
            if not isinstance(record.get("data"), str):
                raise NormalizationError("DNS TXT record lacks string data")
            names = [_domain(record.get("name"))]
            record_type = "dns_txt"
        else:
            if provider == "passive_dns":
                record_type = "passive_dns"
            host_v1 = record.get("host_v1") if isinstance(record.get("host_v1"), dict) else {}
            host = host_v1.get("resource") if isinstance(host_v1.get("resource"), dict) else {}
            address = record.get("ip_str") or record.get("ip") or host.get("ip")
            if address is not None:
                try:
                    if isinstance(address, bool):
                        raise ValueError("Boolean address")
                    addresses = [str(ipaddress.ip_address(address))]
                except ValueError as exc:
                    raise NormalizationError("Network indexer record has an invalid IP address") from exc
            candidates = record.get("hostnames") or record.get("domains") or record.get("domain") or []
            if provider == "censys":
                web_asset = record.get("webproperty_v1") or {}
                certificate_asset = record.get("certificate_v1") or {}
                if not isinstance(web_asset, dict) or not isinstance(certificate_asset, dict):
                    raise NormalizationError("Censys asset must be an object")
                web = web_asset.get("resource") or {}
                certificate = certificate_asset.get("resource") or {}
                if not isinstance(web, dict) or not isinstance(certificate, dict):
                    raise NormalizationError("Censys resource must be an object")
                candidates = ([web["hostname"]] if web.get("hostname") else []) + (certificate.get("names") or [])
            if isinstance(candidates, str):
                candidates = [candidates]
            if not isinstance(candidates, list):
                raise NormalizationError("Network hostnames must be an array or string")
            for candidate in candidates[:100]:
                try:
                    name = _domain(candidate)
                except (NormalizationError, UnicodeError):
                    continue
                names.append(name)
            if provider == "passive_dns" and (not names or not addresses):
                raise NormalizationError("Passive DNS record requires a hostname and IP address")
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        identity = hashlib.sha256(json.dumps([provider, item.get("stream_key", ""), raw], separators=(",", ":")).encode()).hexdigest()
        record_id = "source_record:" + provider + ":" + identity
        remaining = max_records - len(entities) - len(edges) - 1
        if remaining < 0:
            break
        names, addresses = sorted(set(names)), sorted(set(addresses))
        reports = [("domain", name) for name in names] + [("ip", address) for address in addresses]
        selected = []
        for kind, value in reports:
            cost = 1 + int(kind + ":" + value not in anchors)
            if cost > remaining:
                break
            selected.append((kind, value))
            remaining -= cost
        fields = record if len(raw.encode("utf-8")) <= 12000 else {"truncated": True, "preview": raw[:6000]}
        label = (names or addresses or [provider])[0]
        entities.append({"id": record_id, "kind": "source_record", "name": provider + ": " + label, "value": label, "source_url": item.get("source_url", ""), "observed_at": stamp, "confidence": 1.0, "metadata": {"provider": provider, "record_type": record_type, "target_domain": target, "provider_fields": fields, "staging": provenance, "attribution": "provider_report_only", **({"coverage": metadata["coverage"]} if metadata.get("coverage") else {})}})
        for kind, value in selected:
            anchor(kind, value, record_id)
        if provider in CT_PROVIDERS and target and target not in names and remaining >= 1 + int("domain:" + target not in anchors):
            anchor("domain", target, record_id, relation="certificate_lookup_scope")
    return {"entities": entities, "edges": edges}


def _credential(config, provider):
    value = config.get("provider_credentials", {}).get(provider, {})
    return {"api_key": value} if isinstance(value, str) else value if isinstance(value, dict) else {}


def _public_url(url):
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Provider URL must be HTTP(S) without embedded credentials")
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))


async def collect_network_sources(config, store, http):
    from .sourcehub import stage_payload

    batch_size = max(1, min(100, int(config.get("public_source_batch", 3))))
    record_limit = max(1, min(1000, int(config.get("public_source_records", 100))))
    targets = [target for target in config.get("source_targets", []) if isinstance(target, dict) and target.get("domain")]
    semaphore = asyncio.Semaphore(max(1, min(32, int(config.get("public_source_concurrency", 4)))))
    health, errors = {}, []
    payload_limit = int(float(config.get("staging_max_payload_mb", 8)) * 1024 * 1024)
    ct_state = await to_thread(store.source_state, "exposure_ct") if store is not None else {}
    ct_covered = set()

    async def collect_provider(definition):
        provider = definition["id"]
        settings = config.get("provider_settings", {}).get(provider, {})
        credentials = _credential(config, provider)
        status = {"status": "unconfigured", "staged": 0, "unchanged": 0, "records": 0, "requests": 0, "pending_targets": 0, "requirements": definition["required"], "error": ""}
        health[provider] = status
        if settings.get("enabled") is False:
            status["status"] = "disabled"
            return
        requirements = [field for field in definition["required"] if not (settings.get(field) if field in {"query", "url"} else credentials.get(field))]
        if requirements:
            status["requirements"] = requirements
            return
        if not targets:
            status["requirements"] = ["source_targets"]
            return
        if provider == "passive_dns" and store is None:
            status["requirements"] = ["persistent_store"]
            return
        status["requirements"] = []
        failures, successful = [], 0
        incremental = provider in {"certspotter", "ctlogs"}
        progress = ct_state.get(provider, {}) if incremental else {}
        domain_states = dict(progress.get("targets") or {})
        request_times = [stamp for stamp in progress.get("request_times", []) if isinstance(stamp, (int, float)) and stamp > time.time() - 3600]
        status.update({"skipped_targets": 0, "deferred_targets": 0})
        if incremental:
            status["coverage"] = "unexpired_issuances" if provider == "certspotter" else "valid_or_expired_within_90_days;maximum_10_pages"
            status["page_limit"] = 1
        provider_targets = targets[:1] if settings.get("query") and "{domain}" not in str(settings["query"]) or provider not in ENDPOINTS else targets
        state = await to_thread(store.source_state, "exposure_cursors") if store is not None else {}
        cursor = int(state.get(provider, 0)) % len(provider_targets)
        selected = (provider_targets[cursor:] + provider_targets[:cursor])[:batch_size]
        if incremental:
            available = max(0, (6 if provider == "certspotter" else 30) - len(request_times))
            status["deferred_targets"] = max(0, len(selected) - available)
            selected = selected[:available]
        status["pending_targets"] = max(0, len(provider_targets) - len(selected))
        traversed, budget_deferred = 0, False
        for target in selected:
            try:
                domain = _domain(target["domain"])
                if provider in CT_PROVIDERS and domain in ct_covered:
                    status["skipped_targets"] += 1
                    continue
                domain_state = dict(domain_states.get(domain) or {}) if incremental else {}
                if incremental and (float(progress.get("retry_at", 0)) > time.time() or float(domain_state.get("retry_at", 0)) > time.time() or len(request_times) >= (6 if provider == "certspotter" else 30)):
                    status["deferred_targets"] += 1
                    if domain_state.get("last_success") and float(domain_state.get("retry_at", 0)) > time.time():
                        ct_covered.add(domain)
                    continue
                names = [domain, "_dmarc." + domain] if provider == "dns_txt" else [domain]
                if provider == "dns_txt":
                    selectors = target.get("dkim_selectors", settings.get("dkim_selectors", []))
                    if not isinstance(selectors, list):
                        raise ValueError("DKIM selectors must be an array")
                    names.extend(_domain(str(selector) + "._domainkey." + domain) for selector in selectors[:10])
                for name in names:
                    params, headers, body = {}, {}, None
                    url = settings.get("url") or ENDPOINTS.get(provider)
                    safe_url = _public_url(url)
                    query = str(settings.get("query") or "").replace("{domain}", domain)
                    metadata = {"provider": provider, "target_domain": domain, "record_limit": record_limit}
                    if provider == "certspotter":
                        params = {"domain": domain, "include_subdomains": "true", "expand": "dns_names"}
                        if domain_state.get("after"):
                            params["after"] = domain_state["after"]
                        metadata["coverage"] = "unexpired_issuances"
                    elif provider == "ctlogs":
                        url += domain
                        safe_url = _public_url(url)
                        if domain_state.get("after"):
                            params["after"] = domain_state["after"]
                        metadata["coverage"] = "valid_or_expired_within_90_days;maximum_10_pages"
                    elif provider == "crtsh":
                        params = {"q": "%." + domain, "output": "json"}
                    elif provider == "passive_dns":
                        params = {"q": domain}
                    elif provider == "dns_txt":
                        params = {"name": name, "type": "TXT"}
                        metadata["query_name"] = name
                    elif provider == "shodan":
                        params = {"key": credentials["api_key"], "query": query or "hostname:" + domain, "page": 1, "minify": "true"}
                    elif provider == "censys":
                        headers = {"Authorization": "Bearer " + credentials["api_key"]}
                        if settings.get("organization_id"):
                            headers["X-Organization-ID"] = str(settings["organization_id"])
                        body = {"query": query, "page_size": min(record_limit, 100)}
                    elif provider == "fofa":
                        params = {"key": credentials["api_key"], "qbase64": base64.b64encode((query or 'domain="' + domain + '"').encode()).decode(), "fields": ",".join(FOFA_FIELDS), "size": record_limit, "page": 1}
                        metadata["fields"] = list(FOFA_FIELDS)
                    elif provider == "netlas":
                        params = {"q": query or "host:" + domain, "start": 0}
                        headers = {"Authorization": "Bearer " + credentials["api_key"]}
                    elif provider == "zoomeye":
                        body = {"qbase64": base64.b64encode((query or 'domain="' + domain + '"').encode()).decode(), "page": 1, "pagesize": record_limit}
                        headers = {"API-KEY": credentials["api_key"]}
                    public_params = {key: value for key, value in params.items() if key != "key"}
                    provenance_url = safe_url + ("?" + urlencode(public_params) if public_params else "")
                    async with semaphore:
                        if provider == "passive_dns":
                            budget = await to_thread(_passive_dns_budget, store, time.time(), reserve=True)
                            status["daily_requests_remaining"] = budget["remaining"]
                            if not budget["allowed"]:
                                budget_deferred = True
                                status["deferred_targets"] += len(selected) - traversed
                                status["reason"] = "HackerTarget daily query budget or provider cooldown is active"
                                status["retry_at"] = datetime.fromtimestamp(min(budget["retry_at"], 253402300799), timezone.utc).isoformat()
                                break
                        status["requests"] += 1
                        if incremental:
                            request_times.append(time.time())
                        if body is not None:
                            fetched = await http.post(url, json=body, headers=headers, max_bytes=payload_limit, max_attempts=1, allow_redirects=False)
                        else:
                            fetched = await http.get(url, params=params, headers=headers, max_bytes=payload_limit, cache=provider not in {"shodan", "fofa", "censys", "netlas", "passive_dns"}, max_attempts=2 if provider == "crtsh" else 1, allow_redirects=not bool(credentials) and provider != "passive_dns")
                        payload = await asyncio.to_thread(fetched.path.read_bytes)
                        if provider == "passive_dns" and _passive_dns_quota(payload):
                            header = next((value for key, value in fetched.headers.items() if key.lower() == "retry-after"), None)
                            delay = max(86400, retry_delay(header, 0) if header else 0)
                            raise HTTPError(429, safe_url, "HackerTarget daily query quota reached", retry_after=delay)
                        rows = _records({"payload": payload, "metadata": metadata}, provider)
                        if incremental:
                            if len(rows) > 1000:
                                raise NormalizationError("Certificate page exceeds the bounded record limit")
                            metadata["record_limit"] = max(record_limit, len(rows))
                            if provider == "ctlogs":
                                page = _json({"payload": payload})
                                if page["has_next"] and page["next_cursor"] == domain_state.get("after"):
                                    raise NormalizationError("ctlogs.dev pagination did not advance")
                            elif rows and rows[-1]["id"] == domain_state.get("after"):
                                raise NormalizationError("Cert Spotter pagination did not advance")
                        content_type = fetched.headers.get("Content-Type", "text/plain" if provider == "passive_dns" else "application/json").split(";", 1)[0]
                        queued = await stage_payload(config, store, payload, provider=provider, source_url=provenance_url, content_type=content_type, stream_key=provider + ":" + name, metadata=metadata)
                    duplicate = isinstance(queued, dict) and queued.get("duplicate", False)
                    status["staged"] += int(not duplicate)
                    status["unchanged"] += int(bool(duplicate))
                    status["records"] += min(len(rows), metadata["record_limit"])
                    if incremental:
                        current = time.time()
                        retry_after = next((value for key, value in fetched.headers.items() if key.lower() == "retry-after"), None)
                        domain_state.update(last_success=current, retry_at=current + max(3600, retry_delay(retry_after, 0) if retry_after else 0))
                        if provider == "certspotter":
                            if rows:
                                domain_state["after"] = rows[-1]["id"]
                        else:
                            pages = int(domain_state.get("pages", 0)) + 1
                            more = page["has_next"] and pages < 10
                            domain_state.update(after=page["next_cursor"] if more else "", pages=pages if more else 0)
                            status["history_truncated"] = status.get("history_truncated", False) or bool(page["has_next"] and not more)
                        domain_states[domain] = domain_state
                    if provider in CT_PROVIDERS:
                        ct_covered.add(domain)
                    successful += 1
            except Exception as exc:
                if provider == "passive_dns" and isinstance(exc, HTTPError) and exc.status == 429:
                    delay = exc.retry_after if exc.retry_after is not None else 86400
                    budget = await to_thread(_passive_dns_budget, store, time.time(),
                                                     retry_at=time.time() + max(1, delay))
                    status.update(reason="HackerTarget query quota reached; collection is deferred",
                                  retry_at=datetime.fromtimestamp(min(budget["retry_at"], 253402300799), timezone.utc).isoformat())
                    status["deferred_targets"] += 1
                    continue
                if incremental:
                    delay = max(3600, exc.retry_after or 0) if isinstance(exc, HTTPError) and exc.status in {429, 503} else 900
                    progress["retry_at"] = time.time() + delay
                reason = public_error(exc)
                for value in credentials.values():
                    if isinstance(value, str) and value:
                        reason = reason.replace(value, "[redacted]")
                failures.append(provider + ": " + reason)
            finally:
                if not budget_deferred:
                    traversed += 1
            if budget_deferred:
                break
        if store is not None:
            advanced = traversed if provider == "passive_dns" else len(selected)
            if provider != "passive_dns" or advanced:
                await to_thread(store.update_source, "exposure_cursors", **{provider: (cursor + advanced) % len(provider_targets)})
            if incremental:
                await to_thread(store.update_source, "exposure_ct", **{provider: {**progress, "targets": domain_states, "request_times": request_times}})
        if provider == "ctlogs":
            status["pending_pages"] = sum(bool(value.get("after")) for value in domain_states.values())
        if provider == "passive_dns":
            status["pending_targets"] = max(0, len(provider_targets) - traversed)
        status["status"] = "partial" if failures and successful else "error" if failures else "deferred" if status["deferred_targets"] and not successful else "healthy"
        status["error"] = "; ".join(failures)[:1000]
        errors.extend(failures)

    for provider in CT_PROVIDERS:
        await collect_provider(next(row for row in SOURCE_DEFINITIONS if row["id"] == provider))
    await gather(*(collect_provider(definition) for definition in SOURCE_DEFINITIONS if definition["id"] not in CT_PROVIDERS))
    return {key: sum(row[key] for row in health.values()) for key in ("staged", "unchanged", "records", "requests", "pending_targets")} | {"provider_health": health, "errors": errors}
