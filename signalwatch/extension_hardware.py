import asyncio
import base64
import csv
import hashlib
import io
import json
import math
from urllib.parse import urlencode, urlsplit

from bs4 import BeautifulSoup

from .async_utils import gather, to_thread
from .extension_network import ENDPOINTS, normalize_network
from .normalization import NormalizationError, _mac, wireless


WIGLE_URL = "https://api.wigle.net/api/v2/network/search"
SOURCE_DEFINITIONS = [
    {"id": "wigle", "name": "WiGLE wireless observations", "access": "api_key", "required": ["api_name", "api_token", "netid, ssid, or bounded coordinates"], "homepage": "https://api.wigle.net/swagger", "description": "Credentialed indexed Wi-Fi search with explicit BSSID, SSID, or coordinate bounds; results do not establish ownership, router model, or physical presence."},
    {"id": "fcc_uls", "name": "FCC ULS license exports", "access": "configured_url", "required": ["url"], "homepage": "https://www.fcc.gov/wireless/universal-licensing-system", "description": "Configured public JSON/CSV/HTML license exports and staging imports; no current live query API is assumed."},
    {"id": "fcc_equipment", "name": "FCC equipment authorization exports", "access": "configured_url", "required": ["url"], "homepage": "https://www.fcc.gov/engineering-technology/laboratory-division/general/equipment-authorization", "description": "Configured public grantee/equipment JSON/CSV/HTML exports; authorization identifies an approved product, not corporate deployment."},
    {"id": "shodan_ics", "name": "Shodan industrial protocol index", "access": "api_key", "credential_provider": "shodan", "required": ["api_key", "query"], "homepage": "https://developer.shodan.io/api", "description": "Explicit indexed ICS/IoT query using Shodan credentials; protocol and software reports remain attributed to the indexer."},
    {"id": "censys_devices", "name": "Censys indexed devices", "access": "api_key", "credential_provider": "censys", "required": ["api_key", "query"], "homepage": "https://docs.censys.com/reference/v3-globaldata-search-query", "description": "Explicit Platform CenQL device query using a Personal Access Token; reported devices do not establish company ownership."},
]
for _definition in SOURCE_DEFINITIONS:
    _definition.update(category="hardware", family="hardware")


def _json(payload):
    try:
        return json.loads(payload.decode("utf-8-sig"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise NormalizationError("Hardware source returned invalid JSON") from exc


def _coordinate(value, bound):
    if isinstance(value, bool):
        raise NormalizationError("Coordinate must be a finite number")
    try:
        number = float(value)
    except (ValueError, TypeError, OverflowError) as exc:
        raise NormalizationError("Coordinate must be a finite number") from exc
    if not math.isfinite(number) or not -bound <= number <= bound:
        raise NormalizationError("Coordinate is outside its geographic bounds")
    return number


def _wigle_records(item, limit):
    value = _json(item["payload"])
    if not isinstance(value, dict) or value.get("success") is not True or not isinstance(value.get("results"), list):
        raise NormalizationError("WiGLE response is not a successful result array")
    rows = []
    for record in value["results"][:limit]:
        if not isinstance(record, dict):
            raise NormalizationError("WiGLE records must be objects")
        address = _mac(record.get("netid"))
        if any(key in record and record[key] is not None for key in ("trilat", "trilong")):
            if record.get("trilat") is None or record.get("trilong") is None:
                raise NormalizationError("WiGLE coordinates require both latitude and longitude")
            _coordinate(record["trilat"], 90)
            _coordinate(record["trilong"], 180)
        rows.append({**record, "mac": address})
    return rows


def _export_records(item, limit):
    try:
        text = item["payload"].decode("utf-8-sig")
    except UnicodeError as exc:
        raise NormalizationError("FCC export must be UTF-8 JSON, CSV, or HTML") from exc
    if text.lstrip().startswith(("{", "[")):
        value = _json(item["payload"])
        if isinstance(value, dict):
            value = next((value[key] for key in ("records", "results", "data") if isinstance(value.get(key), list)), [value])
        if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
            raise NormalizationError("FCC JSON export must contain objects")
        return value[:limit]
    if text.lstrip().startswith("<"):
        document = BeautifulSoup(text, "html.parser")
        rows = []
        for table in document.find_all("table"):
            headings = None
            for row in table.find_all("tr"):
                cells = row.find_all(["th", "td"], recursive=False)
                values = [cell.get_text(" ", strip=True)[:4000] for cell in cells]
                if not values:
                    continue
                if headings is None:
                    headings = values
                else:
                    rows.append(dict(zip(headings, values)))
                    if len(rows) >= limit:
                        return rows
        return rows or [{"text": document.get_text(" ", strip=True)[:12000]}]
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or len(reader.fieldnames) < 2:
        if not text.strip():
            raise NormalizationError("FCC export is empty")
        return [{"text": text[:12000]}]
    rows = []
    for record in reader:
        if None in record:
            raise NormalizationError("FCC CSV row exceeds its header columns")
        rows.append(record)
        if len(rows) >= limit:
            break
    return rows


def normalize_hardware(item, max_records=5000):
    metadata = item.get("metadata") or {}
    provider = metadata.get("provider")
    if max_records < 1:
        raise NormalizationError("Hardware record limit must be positive")
    limit = min(max_records, max(1, int(metadata.get("record_limit", 100))))
    if provider == "wigle":
        rows = _wigle_records(item, limit)
        if not rows:
            return {"entities": []}
        adapted = {**item, "payload": json.dumps(rows, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()}
        batch = wireless(adapted, limit)
        for entity in batch["entities"]:
            entity["metadata"].update(provider=provider, attribution="provider_report_only", randomization_possible=entity["metadata"]["locally_administered"])
        return batch
    if provider in {"shodan_ics", "censys_devices"}:
        base_provider = "shodan" if provider == "shodan_ics" else "censys"
        batch = normalize_network({**item, "metadata": {**metadata, "provider": base_provider}}, max_records=max_records)
        replacements = {}
        for entity in batch["entities"]:
            if entity["kind"] == "source_record":
                previous = entity["id"]
                entity["id"] = previous.replace("source_record:" + base_provider + ":", "source_record:" + provider + ":", 1)
                replacements[previous] = entity["id"]
                entity["name"] = entity["name"].replace(base_provider + ":", provider + ":", 1)
                entity["metadata"].update(provider=provider, record_type="industrial_indexer")
        for edge in batch["edges"]:
            edge["from_id"] = replacements.get(edge["from_id"], edge["from_id"])
        return batch
    if provider not in {"fcc_uls", "fcc_equipment"}:
        raise NormalizationError("Unknown hardware provider")
    entities = []
    for record in _export_records(item, limit):
        raw = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        identity = hashlib.sha256(json.dumps([provider, item.get("source_url", ""), item.get("stream_key", ""), raw], separators=(",", ":")).encode()).hexdigest()
        fields = record if len(raw.encode()) <= 12000 else {"truncated": True, "preview": raw[:6000]}
        label = str(next((record[key] for key in ("call_sign", "callsign", "u_call_sign", "fcc_id", "grantee_name", "name") if record.get(key)), "FCC public record"))[:500]
        entities.append({"id": "source_record:" + provider + ":" + identity, "kind": "source_record", "name": label, "value": label, "source_url": item.get("source_url", ""), "observed_at": item.get("observed_at") or item.get("received_at"), "confidence": 1.0, "metadata": {"provider": provider, "provider_fields": fields, "attribution": "regulatory_record_only", "staging": {"id": item.get("id"), "source": item.get("source"), "payload_hash": item.get("payload_hash"), "raw_reference": "staging:" + str(item.get("id"))}}})
    return {"entities": entities}


def _wigle_queries(config, settings):
    configured = settings.get("queries")
    if configured is not None and (not isinstance(configured, list) or any(not isinstance(row, dict) for row in configured)):
        raise ValueError("WiGLE queries must be an array of objects")
    candidates = configured if configured is not None else [settings] if any(key in settings for key in ("netid", "ssid", "latrange1", "latrange2", "longrange1", "longrange2")) else []
    if not candidates:
        candidates = [{"netid": address} for target in config.get("source_targets", []) if isinstance(target, dict) for address in target.get("bssids", [])]
    result = []
    for candidate in candidates:
        query = {}
        if candidate.get("netid"):
            query["netid"] = _mac(candidate["netid"])
        if candidate.get("ssid"):
            if not isinstance(candidate["ssid"], str) or len(candidate["ssid"].encode("utf-8")) > 32:
                raise ValueError("WiGLE SSID must contain at most 32 UTF-8 bytes")
            query["ssid"] = candidate["ssid"]
        bounds = ("latrange1", "latrange2", "longrange1", "longrange2")
        if any(key in candidate for key in bounds):
            if not all(key in candidate for key in bounds):
                raise ValueError("WiGLE geographic search requires all four coordinate bounds")
            query.update({key: _coordinate(candidate[key], 90 if key.startswith("lat") else 180) for key in bounds})
            if query["latrange1"] > query["latrange2"] or query["longrange1"] > query["longrange2"]:
                raise ValueError("WiGLE geographic bounds must be ordered minimum to maximum")
        if not query:
            raise ValueError("WiGLE search requires a BSSID, SSID, or coordinate bounds")
        query["resultsPerPage"] = min(100, max(1, int(config.get("public_source_records", 100))))
        result.append(query)
    return result


async def collect_hardware_sources(config, store, http):
    from .sourcehub import scrub_source_url, stage_payload

    request_limit = max(1, min(100, int(config.get("public_source_batch", 3))))
    record_limit = max(1, min(1000, int(config.get("public_source_records", 100))))
    payload_limit = int(float(config.get("staging_max_payload_mb", 8)) * 1024 * 1024)
    semaphore = asyncio.Semaphore(max(1, min(32, int(config.get("public_source_concurrency", 4)))))
    health, errors = {}, []

    async def collect_provider(definition):
        provider = definition["id"]
        options = config.get("provider_settings", {}).get(provider, {})
        credential = config.get("provider_credentials", {}).get(provider) or config.get("provider_credentials", {}).get(definition.get("credential_provider"), {})
        credential = {"api_key": credential} if isinstance(credential, str) else credential if isinstance(credential, dict) else {}
        status = {"status": "unconfigured", "staged": 0, "unchanged": 0, "records": 0, "requests": 0, "pending_targets": 0, "requirements": [], "error": ""}
        health[provider] = status
        if options.get("enabled") is False:
            status["status"] = "disabled"
            return
        required = ("api_name", "api_token") if provider == "wigle" else ("api_key",) if definition["access"] == "api_key" else ()
        missing = [field for field in required if not credential.get(field)]
        if provider in {"shodan_ics", "censys_devices"} and not options.get("query"):
            missing.append("query")
        if definition["access"] == "configured_url" and not (options.get("url") or options.get("urls")):
            missing.append("url")
        if missing:
            status["requirements"] = missing
            return
        successful, failures = 0, []
        try:
            if provider == "wigle":
                queries = _wigle_queries(config, options)
                if not queries:
                    status["requirements"] = ["netid, ssid, or bounded coordinates"]
                    return
                requests = [(WIGLE_URL, query) for query in queries]
            elif definition["access"] == "configured_url":
                urls = options.get("urls") or [options.get("url")]
                if not isinstance(urls, list) or any(not isinstance(url, str) for url in urls):
                    raise ValueError("FCC export URLs must be an array of HTTP(S) URLs")
                requests = [(url, {}) for url in urls]
            else:
                base = "shodan" if provider == "shodan_ics" else "censys"
                requests = [(ENDPOINTS[base], {"query": str(options["query"])})]
            state = await to_thread(store.source_state, "hardware_cursors") if store is not None else {}
            cursor = int(state.get(provider, 0)) % max(1, len(requests))
            selected = (requests[cursor:] + requests[:cursor])[:request_limit]
            status["pending_targets"] = max(0, len(requests) - len(selected))
            for url, query in selected:
                try:
                    status["requests"] += 1
                    parsed = urlsplit(url)
                    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
                        raise ValueError("Hardware source URL must use HTTP(S) without embedded credentials")
                    params, headers, body = query, {}, None
                    if provider == "wigle":
                        token = base64.b64encode((credential["api_name"] + ":" + credential["api_token"]).encode()).decode()
                        headers = {"Authorization": "Basic " + token}
                    elif provider == "shodan_ics":
                        params = {"key": credential["api_key"], "query": query["query"], "page": 1, "minify": "true"}
                    elif provider == "censys_devices":
                        params = {}
                        body = {"query": query["query"], "page_size": min(100, record_limit)}
                        headers = {"Authorization": "Bearer " + credential["api_key"]}
                        if options.get("organization_id"):
                            headers["X-Organization-ID"] = str(options["organization_id"])
                    metadata = {"provider": provider, "record_limit": record_limit}
                    public_query = {key: value for key, value in params.items() if key != "key"}
                    source_url = scrub_source_url(url) if not public_query else url.split("?", 1)[0] + "?" + urlencode(public_query)
                    stream_key = provider + ":" + hashlib.sha256(json.dumps([source_url, query], sort_keys=True, separators=(",", ":")).encode()).hexdigest()
                    async with semaphore:
                        if body is not None:
                            fetched = await http.post(url, json=body, headers=headers, max_bytes=payload_limit, allow_redirects=False, max_attempts=1)
                        else:
                            fetched = await http.get(url, params=params, headers=headers, max_bytes=payload_limit, cache=definition["access"] != "api_key", allow_redirects=definition["access"] != "api_key", max_attempts=1)
                        payload = await asyncio.to_thread(fetched.path.read_bytes)
                        content_type = fetched.headers.get("Content-Type", "application/json").split(";", 1)[0]
                        queued = await stage_payload(config, store, payload, provider=provider, source_url=source_url, content_type=content_type, stream_key=stream_key, metadata=metadata)
                    duplicate = isinstance(queued, dict) and queued.get("duplicate", False)
                    status["staged"] += int(not duplicate)
                    status["unchanged"] += int(bool(duplicate))
                    batch = normalize_hardware({"id": 1, "source": "public:" + provider, "source_url": source_url, "stream_key": stream_key, "payload": payload, "payload_hash": fetched.digest, "observed_at": "", "metadata": metadata})
                    status["records"] += sum(row["kind"] in {"source_record", "wireless"} for row in batch["entities"])
                    successful += 1
                except Exception as exc:
                    failures.append(str(exc))
            if store is not None:
                await to_thread(store.update_source, "hardware_cursors", **{provider: (cursor + len(selected)) % max(1, len(requests))})
        except Exception as exc:
            failures.append(str(exc))
        failures = [" ".join(message.split())[:300] for message in failures]
        redactions = [value for value in credential.values() if isinstance(value, str) and value]
        if provider == "wigle" and credential.get("api_name") and credential.get("api_token"):
            redactions.append(base64.b64encode((credential["api_name"] + ":" + credential["api_token"]).encode()).decode())
        for secret in redactions:
            failures = [message.replace(secret, "[redacted]") for message in failures]
        status["status"] = "partial" if successful and failures else "error" if failures else "healthy"
        status["error"] = "; ".join(failures)[:1000]
        errors.extend(provider + ": " + message for message in failures)

    await gather(*(collect_provider(definition) for definition in SOURCE_DEFINITIONS))
    return {key: sum(row[key] for row in health.values()) for key in ("staged", "unchanged", "records", "requests", "pending_targets")} | {"provider_health": health, "errors": errors}
