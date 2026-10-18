import asyncio
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from urllib.parse import urlencode

from .extract import read_json


RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


def dns_name(value):
    return value.strip().rstrip(".").encode("idna").decode().lower() if isinstance(value, str) else ""


def observed_time():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def remaining_ttl(value, age):
    return max(0, value - age) if type(value) is int and 0 <= value <= 4294967295 else None


def parse_answer(payload, host, query_type, resolver, source_url, observed_at, headers=None):
    if not isinstance(payload, dict) or type(payload.get("Status")) is not int:
        raise ValueError("DNS JSON response lacks an integer Status")
    host = dns_name(host)
    question = payload.get("Question")
    if not isinstance(question, list) or not any(isinstance(item, dict) and dns_name(item.get("name", "")) == host and type(item.get("type")) is int and item["type"] == query_type for item in question):
        raise ValueError("DNS response question differs from the requested name/type")
    status = RCODES.get(payload["Status"], f"RCODE_{payload['Status']}")
    errors = []
    if payload["Status"] not in (0, 3):
        comment = str(payload.get("Comment", ""))[:300]
        return {"records": [], "errors": [f"{status}: {comment}".rstrip(": ")], "status": status, "next_name": None, "ttl": None}
    if payload.get("TC"):
        return {"records": [], "errors": ["Truncated DNS response"], "status": status, "next_name": None, "ttl": None}
    headers = {key.lower(): value for key, value in (headers or {}).items()}
    try:
        age = max(0, int(headers.get("age", "0")))
    except (TypeError, ValueError):
        age = 0
    records = []
    chain = [host]
    answers = payload.get("Answer") or []
    if not isinstance(answers, list):
        raise ValueError("DNS Answer must be a list")
    if payload["Status"] == 0:
        aliases = {}
        for item in answers:
            if not isinstance(item, dict) or type(item.get("type")) is not int or item["type"] != 5:
                continue
            owner = dns_name(item.get("name", ""))
            target = dns_name(item.get("data", ""))
            if not owner or not target:
                errors.append("Invalid CNAME answer")
                continue
            if owner in aliases and aliases[owner]["data"] != target:
                errors.append("Conflicting CNAME answers")
                continue
            aliases[owner] = {**item, "data": target}
        current = host
        while current in aliases:
            item = aliases[current]
            target = item["data"]
            records.append({"name": current, "type": "CNAME", "value": target, "ttl": item.get("TTL"), "remaining_ttl": remaining_ttl(item.get("TTL"), age), "resolver": resolver, "source_url": source_url, "observed_at": observed_at, "http_age": age})
            if target in chain:
                errors.append("CNAME loop in DNS answers")
                break
            chain.append(target)
            current = target
            if len(chain) > 16:
                errors.append("CNAME chain exceeds 16 names")
                break
        for item in answers:
            if not isinstance(item, dict) or type(item.get("type")) is not int or item["type"] != query_type:
                continue
            owner = dns_name(item.get("name", ""))
            if owner != chain[-1] or errors:
                continue
            try:
                if not isinstance(item.get("data"), str) or "%" in item["data"]:
                    raise ValueError("address data is not a DNS address string")
                address = ipaddress.ip_address(item["data"])
                if address.version != (4 if query_type == 1 else 6):
                    raise ValueError("address family differs from record type")
            except ValueError as error:
                errors.append(f"Invalid {'A' if query_type == 1 else 'AAAA'} answer: {error}")
                continue
            records.append({"name": owner, "type": "A" if query_type == 1 else "AAAA", "value": str(address), "ttl": item.get("TTL"), "remaining_ttl": remaining_ttl(item.get("TTL"), age), "resolver": resolver, "source_url": source_url, "observed_at": observed_at, "http_age": age, "chain": chain[:]})
    if any(item["remaining_ttl"] is None for item in records):
        errors.append("DNS answer has an invalid or missing TTL")
    addresses = [item for item in records if item["type"] in {"A", "AAAA"}]
    ttl_values = [item["remaining_ttl"] for item in records]
    if not addresses:
        for item in payload.get("Authority", []) or []:
            if not isinstance(item, dict) or item.get("type") != 6:
                continue
            try:
                minimum = int(str(item.get("data", "")).split()[-1])
            except (ValueError, IndexError):
                continue
            soa_ttl = remaining_ttl(item.get("TTL"), age)
            if soa_ttl is not None and minimum >= 0:
                ttl_values.append(min(soa_ttl, max(0, minimum - age)))
    ttl = min(ttl_values) if ttl_values and all(value is not None for value in ttl_values) else None
    control = headers.get("cache-control", "")
    maximum = re.search(r'(?:^|,)\s*max-age\s*=\s*"?(\d+)', control, re.I)
    if maximum and ttl is not None:
        ttl = min(ttl, max(0, int(maximum[1]) - age))
    if re.search(r"(?:^|,)\s*no-(?:store|cache)\b", control, re.I):
        ttl = 0
    next_name = chain[-1] if len(chain) > 1 and not addresses and not errors else None
    return {"records": records, "errors": errors, "status": status, "next_name": next_name, "ttl": ttl}


@dataclass
class DNSResult:
    records: list
    errors: list
    statuses: dict
    observed_at: str
    mode: str
    ttl: int | None = None
    system_error: str | None = None
    cached: bool = False

    @property
    def complete(self):
        return not self.errors

    def graph(self, host, source_url):
        host = dns_name(host)
        entities = {}
        edges = {}
        for record in self.records:
            metadata = {"dns": {**record, "mode": self.mode, "cached": self.cached, "query": host, "system_error": self.system_error, "complete": self.complete, "statuses": self.statuses, "errors": self.errors}, "discovered_from": source_url}
            evidence_url = record.get("source_url") or source_url
            if record["type"] == "CNAME":
                for name in (record["name"], record["value"]):
                    entities[f"domain:{name}"] = {"id": f"domain:{name}", "kind": "domain", "name": name, "value": name, "metadata": metadata, "source_url": evidence_url, "observed_at": record["observed_at"], "confidence": 1.0}
                key = (record["name"], record["value"], "cname_to", evidence_url)
                edges[key] = {"from_id": f"domain:{record['name']}", "to_id": f"domain:{record['value']}", "relation": "cname_to", "source_url": evidence_url, "observed_at": record["observed_at"], "confidence": 1.0}
            else:
                address = record["value"]
                entities[f"ip:{address}"] = {"id": f"ip:{address}", "kind": "ip", "name": address, "value": address, "metadata": metadata, "source_url": evidence_url, "observed_at": record["observed_at"], "confidence": 1.0}
                if record["type"] != "IP_LITERAL":
                    key = (host, address, "resolves_to", evidence_url)
                    edges[key] = {"from_id": f"domain:{host}", "to_id": f"ip:{address}", "relation": "resolves_to", "source_url": evidence_url, "observed_at": record["observed_at"], "confidence": 1.0}
        return list(entities.values()), list(edges.values())


class DNSResolver:
    def __init__(self, config, http):
        self.mode = config.get("dns_mode", "fallback")
        if self.mode not in {"system", "fallback", "doh"}:
            raise ValueError("dns_mode must be system, fallback, or doh")
        self.url = config.get("dns_doh_url", "https://dns.google/resolve")
        self.timeout = float(config.get("dns_timeout", 5))
        concurrency = int(config.get("dns_concurrency", 4))
        if self.timeout <= 0 or concurrency < 1:
            raise ValueError("DNS timeout/concurrency must be positive")
        self.http = http
        self.semaphore = asyncio.Semaphore(concurrency)
        self.system_semaphore = asyncio.Semaphore(concurrency)
        self.locks = {}
        self.cache = {}
        self.errors = {}
        self.results = {}

    async def _system(self, host):
        async with self.system_semaphore:
            values = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), self.timeout)
        now = observed_time()
        records = {}
        for family, _, _, _, sockaddr in values:
            if family not in {socket.AF_INET, socket.AF_INET6}:
                continue
            address = ipaddress.ip_address(sockaddr[0])
            if address.version != (4 if family == socket.AF_INET else 6):
                continue
            records[str(address)] = {"name": host, "type": "A" if family == socket.AF_INET else "AAAA", "value": str(address), "ttl": None, "remaining_ttl": None, "resolver": "system", "source_url": "", "observed_at": now}
        if not records:
            raise OSError("system resolver returned no A/AAAA addresses")
        return DNSResult(list(records.values()), [], {"system": "NOERROR"}, now, "system")

    async def _family(self, host, query_type):
        current = host
        seen = set()
        records = []
        errors = []
        ttls = []
        status = "ERROR"
        for _ in range(8):
            if current in seen:
                errors.append("CNAME resolution loop")
                break
            seen.add(current)
            params = {"name": current, "type": query_type, "edns_client_subnet": "0.0.0.0/0"}
            try:
                async with self.semaphore:
                    response = await asyncio.wait_for(self.http.get(self.url, params=params, headers={"Accept": "application/dns-json"}, cache=False, max_bytes=256 * 1024), self.timeout)
                    payload = await asyncio.to_thread(read_json, response.path)
                url = self.url + ("&" if "?" in self.url else "?") + urlencode(params)
                result = parse_answer(payload, current, query_type, self.url, url, observed_time(), response.headers)
            except Exception as error:
                errors.append(f"{type(error).__name__}: {error}")
                status = "ERROR"
                break
            records.extend(result["records"])
            errors.extend(result["errors"])
            status = result["status"]
            ttls.append(time.monotonic() + result["ttl"] if result["ttl"] is not None else None)
            if result["next_name"]:
                current = result["next_name"]
                continue
            break
        else:
            errors.append("CNAME resolution exceeds eight DNS queries")
        deadline = min(ttls) if ttls and all(value is not None for value in ttls) else None
        label = "A" if query_type == 1 else "AAAA"
        return records, [f"{host} {label}: {error}" for error in errors], status, deadline

    async def resolve(self, host):
        host = dns_name(host)
        lock = self.locks.setdefault(host, asyncio.Lock())
        async with lock:
            cached = self.cache.get(host)
            if cached and cached[0] > time.monotonic():
                result = replace(cached[1], cached=True)
            else:
                self.cache.pop(host, None)
                now = observed_time()
                try:
                    address = ipaddress.ip_address(host)
                except ValueError:
                    address = None
                if address is not None:
                    result = DNSResult([{"name": host, "type": "IP_LITERAL", "value": str(address), "ttl": None, "remaining_ttl": None, "resolver": "literal", "source_url": "", "observed_at": now}], [], {"literal": "NOERROR"}, now, "literal")
                else:
                    result = None
                    system_error = None
                    if self.mode != "doh":
                        try:
                            result = await self._system(host)
                        except Exception as error:
                            system_error = f"{type(error).__name__}: {error}"
                            if self.mode == "system":
                                result = DNSResult([], [f"{host} system DNS: {system_error}"], {"system": "ERROR"}, now, "system")
                    if result is None:
                        families = await asyncio.gather(self._family(host, 1), self._family(host, 28))
                        records = [record for family in families for record in family[0]]
                        errors = [error for family in families for error in family[1]]
                        statuses = {label: family[2] for label, family in zip(("A", "AAAA"), families)}
                        if "NXDOMAIN" in statuses.values() and any(record["type"] in {"A", "AAAA"} for record in records):
                            errors.append(f"{host}: conflicting positive and NXDOMAIN family responses")
                        ttls = [family[3] for family in families]
                        deadline = min(ttls) if all(value is not None for value in ttls) else None
                        ttl = max(0, int(deadline - time.monotonic())) if deadline is not None else None
                        result = DNSResult(records, errors, statuses, now, "doh", ttl, system_error)
                        if result.complete and ttl is not None and ttl > 0:
                            self.cache[host] = (deadline, result)
            self.results[host] = result
            if result.errors:
                self.errors[host] = result.errors
            else:
                self.errors.pop(host, None)
            return result
