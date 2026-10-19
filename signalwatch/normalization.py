import base64
import calendar
import copy
import csv
import hashlib
import io
import ipaddress
import json
import re
from datetime import datetime, timezone

import feedparser
from bs4 import BeautifulSoup

from .collectors import parse_github
from .extract import CVE_RE, canonical_url, parse_nvd
from .osv import parse_osv


class NormalizationError(ValueError):
    pass


BATCH_KEYS = frozenset({"entities", "edges", "advisories", "observations", "articles", "kev", "kev_snapshot", "epss", "observation_snapshots", "observation_pages"})
MARKER_KEYS = frozenset({"observation_snapshots", "observation_pages"})
MAC_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}(?::|-)){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])|(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}(?![0-9A-Fa-f])|(?<![0-9A-Fa-f])[0-9A-Fa-f]{12}(?![0-9A-Fa-f])")
DNS_TYPES = frozenset({"TXT", "A", "AAAA", "CNAME", "MX", "NS"})
DNS_LINE = re.compile(r"^(\S+)\s+(?:(\d+)\s+)?(?:IN\s+)?(TXT|AAAA|A|CNAME|MX|NS)\s+(.+)$", re.I)


def _json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _text(item):
    try:
        return item["payload"].decode("utf-8-sig")
    except UnicodeDecodeError as error:
        raise NormalizationError("Adapter requires UTF-8 text") from error


def _json(item):
    try:
        return json.loads(_text(item), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    except (json.JSONDecodeError, ValueError, RecursionError) as error:
        raise NormalizationError("Invalid JSON payload") from error


def _stamp(item):
    return item.get("observed_at") or item.get("received_at")


def _provenance(item):
    return {"id": item["id"], "source": item["source"], "source_url": item.get("source_url") or "", "stream_key": item.get("stream_key") or "", "adapter": item.get("adapter") or "auto", "content_type": item.get("content_type") or "", "payload_hash": item["payload_hash"], "raw_reference": "staging:" + str(item["id"]), "observed_at": _stamp(item)}


def _bounded(value):
    encoded = _json_bytes(value)
    if len(encoded) <= 16384:
        return copy.deepcopy(value)
    return {"truncated": True, "preview": encoded[:8192].decode("utf-8", errors="replace"), "original_bytes": len(encoded)}


def _identity(item, value):
    context = item.get("metadata") or {}
    origin = [item["source"], item.get("source_url") or "", item.get("stream_key") or "", context.get("context"), context.get("dataset"), context.get("log_id"), value]
    return hashlib.sha256(_json_bytes(origin)).hexdigest()


def _entity(item, kind, value, metadata, name=None):
    return {"id": kind + ":" + _identity(item, value), "kind": kind, "name": str(name or value)[:1000], "value": str(value)[:4096], "metadata": {**metadata, "staging": _provenance(item)}, "source_url": item.get("source_url") or "", "observed_at": _stamp(item), "confidence": 1.0}


def _limit(size, maximum):
    if size > maximum:
        raise NormalizationError(f"Normalized input exceeds the {maximum} record limit")


def _annotate(batch, item):
    provenance = _provenance(item)
    for key, records in batch.items():
        if key in MARKER_KEYS:
            continue
        for record in records:
            if key == "entities":
                record["metadata"] = {**(record.get("metadata") or {}), "staging": provenance}
            else:
                record["_staging"] = provenance
            if key in {"entities", "edges", "observations"}:
                record.setdefault("source_url", item.get("source_url") or "")
                record.setdefault("observed_at", _stamp(item))
    return batch


def normalized_batch(item, maximum):
    batch = _json(item)
    if not isinstance(batch, dict) or not batch or set(batch) - BATCH_KEYS:
        raise NormalizationError("Normalized batch must contain only supported record arrays")
    for key, records in batch.items():
        if not isinstance(records, list) or any(not isinstance(record, dict) for record in records):
            raise NormalizationError(f"{key} must be an array of objects")
    _limit(sum(map(len, batch.values())), maximum)
    required = {"entities": ("id",), "edges": ("from_id", "to_id", "relation"), "advisories": ("id",), "observations": ("asset_id",), "articles": ("url",), "kev": ("cveID",), "kev_snapshot": ("cveID",), "epss": ("cve",), "observation_snapshots": ("asset_id", "origin"), "observation_pages": ("asset_id", "source_url")}
    for key, records in batch.items():
        for record in records:
            if any(not isinstance(record.get(field), str) or not record[field] for field in required[key]):
                raise NormalizationError(f"{key} record lacks required text fields")
            if key == "entities" and not isinstance(record.get("metadata", {}), dict):
                raise NormalizationError("Entity metadata must be an object")
            if key == "advisories":
                for field in ("aliases", "affected", "references"):
                    if field in record and not isinstance(record[field], list):
                        raise NormalizationError(f"Advisory {field} must be an array")
    return _annotate(batch, item)


def _advisory_format(record):
    if not isinstance(record, dict):
        return None
    if isinstance(record.get("ghsa_id"), str) and any(key in record for key in ("vulnerabilities", "description", "summary")):
        return "github"
    if isinstance(record.get("id"), str) and any(key in record for key in ("descriptions", "configurations", "vulnStatus")):
        return "nvd"
    if isinstance(record.get("id"), str) and "modified" in record and isinstance(record.get("affected"), list) and any(key in record for key in ("details", "summary")):
        if any(isinstance(value, dict) and "package" in value for value in record["affected"]) or "details" in record:
            return "osv"
    if isinstance(record.get("id"), str) and isinstance(record.get("affected"), list) and any(key in record for key in ("title", "summary")):
        return "canonical"
    return None


def vulnerability_json(item, maximum):
    value = _json(item)
    if isinstance(value, dict) and "vulnerabilities" in value and "ghsa_id" not in value:
        records = value["vulnerabilities"]
    elif isinstance(value, dict) and "advisories" in value:
        records = value["advisories"]
    else:
        records = value if isinstance(value, list) else [value]
    if not isinstance(records, list) or not records:
        raise NormalizationError("Vulnerability JSON requires advisory records")
    _limit(len(records), maximum)
    advisories = []
    for record in records:
        if isinstance(record, dict) and "cve" in record:
            record = record["cve"]
        adapter = _advisory_format(record)
        if adapter is None:
            raise NormalizationError("Unrecognized vulnerability record; use an explicit canonical advisory object")
        if adapter == "nvd":
            advisory = parse_nvd(record)
        elif adapter == "github":
            advisory = parse_github(record)
        elif adapter == "osv":
            advisory = parse_osv(record)["advisories"][0]
            advisory.pop("raw", None)
        else:
            advisory = copy.deepcopy(record)
        if not advisory.get("id"):
            raise NormalizationError("Vulnerability record lacks an identifier")
        advisory.setdefault("source", item["source"])
        advisory.setdefault("url", item.get("source_url") or "")
        advisories.append(advisory)
    return _annotate({"advisories": advisories}, item)


def news(item, maximum):
    text = _text(item)
    metadata = item.get("metadata") or {}
    if text.lstrip().startswith("<"):
        parsed = feedparser.parse(text)
        if not str(parsed.get("version", "")).startswith(("rss", "atom")) or parsed.get("bozo"):
            raise NormalizationError("News XML is not a valid RSS or Atom feed")
        _limit(len(parsed.entries), maximum)
        articles = []
        evidence = []
        for index, entry in enumerate(parsed.entries):
            title = BeautifulSoup(entry.get("title", ""), "html.parser").get_text(" ", strip=True)
            summary = BeautifulSoup(entry.get("summary", ""), "html.parser").get_text(" ", strip=True)[:12000]
            url = canonical_url(entry.get("link") or entry.get("id", ""))
            if not url:
                evidence.append(_entity(item, "evidence", {"entry": index, "title": title, "summary": summary}, {"record_type": "news", "title": title[:1000], "preview": summary[:4096]}, title or "News entry without URL"))
                continue
            date = entry.get("published_parsed") or entry.get("updated_parsed")
            published = datetime.fromtimestamp(calendar.timegm(date), timezone.utc).isoformat() if date else None
            articles.append({"url": url, "title": title[:1000], "summary": summary, "published": published, "source": item["source"], "feed_url": metadata.get("feed_url") or item.get("source_url") or "", "guid": entry.get("id", url), "cves": sorted(set(value.upper() for value in CVE_RE.findall(title + " " + summary)))})
        return _annotate({"articles": articles, "entities": evidence}, item)
    if not text.strip():
        raise NormalizationError("News payload is empty")
    url = canonical_url(metadata.get("article_url") or "")
    if not url:
        return opaque(item, maximum, record_type="news")
    title = str(metadata.get("title") or text.splitlines()[0])[:1000]
    article = {"url": url, "title": title, "summary": text[:12000], "published": metadata.get("published"), "source": item["source"], "feed_url": metadata.get("feed_url") or "", "cves": sorted(set(value.upper() for value in CVE_RE.findall(title + " " + text)))}
    return _annotate({"articles": [article]}, item)


def _domain(value):
    if not isinstance(value, str) or not value or any(character.isspace() for character in value):
        raise NormalizationError("DNS record requires an owner name")
    if value == ".":
        return value
    try:
        result = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise NormalizationError("Invalid DNS owner name") from error
    if not result or len(result) > 253 or any(not label or len(label) > 63 for label in result.split(".")):
        raise NormalizationError("Invalid DNS owner name")
    return result


def dns(item, maximum):
    text = _text(item)
    if text.lstrip().startswith(("{", "[")):
        value = _json(item)
        records = value.get("records") if isinstance(value, dict) else value
        if not isinstance(records, list):
            raise NormalizationError("DNS JSON requires a records array")
    else:
        records = []
        for line in text.splitlines():
            if not line.strip() or line.lstrip().startswith((";", "#")):
                continue
            match = DNS_LINE.fullmatch(line.strip())
            if not match:
                raise NormalizationError("Unsupported DNS record line")
            owner, ttl, record_type, value = match.groups()
            records.append({"owner": owner, "ttl": int(ttl) if ttl is not None else None, "type": record_type.upper(), "value": value})
            _limit(len(records), maximum)
    if not records:
        raise NormalizationError("DNS payload contains no records")
    _limit(len(records), maximum)
    entities, edges, domains = [], [], set()
    for record in records:
        if not isinstance(record, dict):
            raise NormalizationError("DNS records must be objects")
        owner = record.get("owner", record.get("name"))
        name = _domain(owner)
        record_type = str(record.get("type") or "").upper()
        value = record.get("value", record.get("data"))
        ttl = record.get("ttl", record.get("TTL"))
        if record_type not in DNS_TYPES or not isinstance(value, str) or not value:
            raise NormalizationError("DNS record has an unsupported type or missing string value")
        if len(value.encode("utf-8")) > 65535:
            raise NormalizationError("DNS record value exceeds 65535 bytes")
        if ttl is not None and (type(ttl) is not int or not 0 <= ttl <= 4294967295):
            raise NormalizationError("DNS TTL must be an unsigned 32-bit integer")
        if record_type in {"A", "AAAA"}:
            address = ipaddress.ip_address(value)
            if address.version != (4 if record_type == "A" else 6):
                raise NormalizationError("DNS address family differs from record type")
        payload = {"owner": owner, "name": name, "type": record_type, "value": value, "ttl": ttl}
        entity = _entity(item, "dns_record", payload, {"dns": payload}, f"{name} {record_type}")
        entity["value"] = value[:4096]
        entities.append(entity)
        domain_id = "domain:" + name
        if domain_id not in domains:
            entities.append({"id": domain_id, "kind": "domain", "name": name, "value": name, "metadata": {"staging_sources": {_identity(item, "domain"): _provenance(item)}}, "observed_at": _stamp(item), "source_url": ""})
            domains.add(domain_id)
        edges.append({"from_id": domain_id, "to_id": entity["id"], "relation": "has_dns_record", "source_url": item.get("source_url") or "", "observed_at": _stamp(item)})
    return {"entities": entities, "edges": edges}


def pdf_metadata(item, maximum):
    text = _text(item)
    if text.startswith("%PDF-"):
        raise NormalizationError("PDF metadata adapter accepts extracted metadata, not PDF binary content")
    if text.lstrip().startswith(("{", "[")):
        value = _json(item)
        if not isinstance(value, dict):
            raise NormalizationError("PDF metadata JSON must be an object")
    else:
        if not text.strip():
            raise NormalizationError("PDF metadata text is empty")
        value = {"text": text}
    entity = _entity(item, "document", value, {"extracted": _bounded(value)}, value.get("title") or value.get("Title") or "Document metadata")
    entity["value"] = item.get("source_url") or item["payload_hash"]
    return {"entities": [entity]}


def _mac(value):
    if not isinstance(value, str) or not MAC_RE.fullmatch(value.strip()):
        raise NormalizationError("Wireless record requires a valid 48-bit MAC address")
    compact = re.sub(r"[:.\-]", "", value.strip()).lower()
    if len(compact) != 12 or ":" in value and "-" in value:
        raise NormalizationError("Wireless record requires a valid 48-bit MAC address")
    return ":".join(compact[index:index + 2] for index in range(0, 12, 2))


def wireless(item, maximum):
    text = _text(item)
    if text.lstrip().startswith(("{", "[")):
        value = _json(item)
        records = value.get("records") if isinstance(value, dict) and "records" in value else value
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            raise NormalizationError("Wireless JSON requires records")
    else:
        lines = [line for line in text.splitlines() if line.strip()]
        _limit(len(lines), maximum + 1)
        if not lines:
            raise NormalizationError("Wireless payload contains no records")
        fields = {field.strip().lower() for field in next(csv.reader([lines[0]]))}
        if fields & {"mac", "bssid", "address"}:
            records = list(csv.DictReader(io.StringIO(text)))
        else:
            records = []
            for line in lines:
                matches = list(MAC_RE.finditer(line))
                if len(matches) != 1:
                    raise NormalizationError("Wireless text line must contain one 48-bit MAC address")
                records.append({"mac": matches[0].group(), "line": line})
    if not records:
        raise NormalizationError("Wireless payload contains no records")
    _limit(len(records), maximum)
    entities = []
    for record in records:
        if isinstance(record, str):
            record = {"mac": record}
        if not isinstance(record, dict):
            raise NormalizationError("Wireless records must be addresses or objects")
        keys = {str(key).strip().lower(): value for key, value in record.items()}
        address = _mac(next((keys[key] for key in ("mac", "bssid", "address") if key in keys), None))
        first = int(address[:2], 16)
        details = {"mac": address, "locally_administered": bool(first & 2), "multicast": bool(first & 1), "fields": _bounded(record)}
        entity = _entity(item, "wireless", {"mac": address, "fields": record}, details, address)
        entity["value"] = address
        if isinstance(keys.get("observed_at"), str) and keys["observed_at"]:
            entity["observed_at"] = keys["observed_at"]
        entities.append(entity)
    return {"entities": entities}


def opaque(item, maximum, record_type="opaque"):
    payload = item["payload"]
    try:
        preview = {"preview": payload[:4096].decode("utf-8")}
    except UnicodeDecodeError:
        preview = {"preview_base64": base64.b64encode(payload[:1024]).decode("ascii")}
    metadata = {"record_type": record_type, "input_metadata": _bounded(item.get("metadata") or {}), "payload_bytes": len(payload), **preview}
    try:
        identity = _json_bytes(json.loads(payload)).decode("utf-8") if (item.get("content_type") or "").split(";", 1)[0].lower().endswith("json") else item["payload_hash"]
    except (ValueError, UnicodeDecodeError, RecursionError):
        identity = item["payload_hash"]
    return {"entities": [_entity(item, "evidence", identity, metadata, (item.get("metadata") or {}).get("title") or "Unclassified evidence")]}


def _auto_adapter(item):
    metadata = item.get("metadata") or {}
    declared = metadata.get("record_type")
    if declared:
        if declared not in ADAPTERS or declared == "auto":
            raise NormalizationError("Unknown declared record_type")
        return declared
    content_type = (item.get("content_type") or "").split(";", 1)[0].strip().lower()
    if content_type in {"application/rss+xml", "application/atom+xml"}:
        return "news"
    if content_type in {"text/dns", "application/dns-json"}:
        return "dns"
    if content_type == "application/vnd.signalwatch.pdf-metadata+json":
        return "pdf_metadata"
    if content_type == "application/json" or content_type.endswith("+json"):
        value = _json(item)
        if isinstance(value, dict):
            if value and not set(value) - BATCH_KEYS:
                return "normalized_batch"
            if _advisory_format(value) or isinstance(value.get("cve"), dict) and _advisory_format(value["cve"]):
                return "vulnerability_json"
            for key in ("vulnerabilities", "advisories"):
                records = value.get(key)
                if isinstance(records, list) and records and all(_advisory_format(record.get("cve", record) if isinstance(record, dict) else record) for record in records):
                    return "vulnerability_json"
        if isinstance(value, list) and value and all(_advisory_format(record) for record in value):
            return "vulnerability_json"
    return "opaque"


def auto(item, maximum):
    return ADAPTERS[_auto_adapter(item)](item, maximum)


def public_source(item, maximum):
    from .sourcehub import normalize_public_source
    return normalize_public_source(item, max_records=maximum)


def wigle_csv(item, maximum):
    from .wireless import normalize_wigle
    return normalize_wigle(item, max_records=maximum)


ADAPTERS = {"auto": auto, "normalized_batch": normalized_batch, "vulnerability_json": vulnerability_json, "news": news, "dns": dns, "pdf_metadata": pdf_metadata, "wireless": wireless, "opaque": opaque, "public_source": public_source, "wigle_csv": wigle_csv}


def normalize(item, max_records=5000):
    if type(max_records) is not int or not 1 <= max_records <= 5000:
        raise NormalizationError("Record limit must be between 1 and 5000")
    if not isinstance(item, dict) or not isinstance(item.get("payload"), bytes) or not isinstance(item.get("metadata", {}), dict):
        raise NormalizationError("Staging item requires bytes payload and object metadata")
    if not all(item.get(key) for key in ("id", "source", "payload_hash")) or not _stamp(item):
        raise NormalizationError("Staging item lacks provenance or received/observed time")
    adapter = item.get("adapter") or "auto"
    try:
        if adapter == "auto":
            adapter = _auto_adapter(item)
        if adapter not in ADAPTERS:
            raise NormalizationError(f"Unsupported adapter: {adapter}")
        return ADAPTERS[adapter](item, max_records)
    except NormalizationError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, IndexError, OverflowError, RecursionError) as error:
        raise NormalizationError(f"Malformed {adapter} payload: {str(error)[:200]}") from error
