import asyncio
import hashlib
import importlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .ingestion import staging_queue


EXTENSIONS = {
    "exposure": ("extension_network", "normalize_network"),
    "corporate": ("extension_corporate", "normalize_corporate"),
    "developer": ("extension_developer", "normalize_developer"),
    "threat": ("extension_threat", "normalize_threat"),
    "hardware": ("extension_hardware", "normalize_hardware"),
}
NATIVE = [
    ("nvd", "NVD", "vulnerability", "https://nvd.nist.gov/"),
    ("kev", "CISA KEV", "vulnerability", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
    ("epss", "FIRST EPSS", "vulnerability", "https://www.first.org/epss/"),
    ("github", "GitHub Advisory Database", "vulnerability", "https://github.com/advisories"),
    ("osv", "OSV", "vulnerability", "https://osv.dev/"),
    ("cve_program", "CVE Program", "vulnerability", "https://www.cve.org/"),
    ("csaf", "Vendor CSAF", "vulnerability", "https://www.csaf.io/"),
    ("network", "RIPEstat routing", "network", "https://stat.ripe.net/"),
    ("wikidata", "Wikidata company websites", "corporate", "https://www.wikidata.org/"),
    ("news", "Security/vendor RSS", "threat", "https://github.com/Dylrobar/signalwatch#collection"),
    ("web", "Public websites and DNS", "network", "https://github.com/Dylrobar/signalwatch#collection"),
]


def scrub_source_url(url):
    parsed = urlsplit(str(url))
    host = parsed.hostname or ""
    if ":" in host:
        host = "[" + host + "]"
    if parsed.port:
        host += ":" + str(parsed.port)
    hidden = ("key", "token", "secret", "password", "signature", "credential", "authorization")
    query = [(key, value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)
             if not any(part in key.lower() for part in hidden)]
    return urlunsplit((parsed.scheme, host, parsed.path, urlencode(query), ""))


def public_settings(value):
    if isinstance(value, dict):
        return {key: public_settings(child) for key, child in value.items()
                if not re.search(r"(?:password|secret|token|api[_-]?key|authorization|credentials|headers)|^key$", key, re.I)}
    if isinstance(value, list):
        return [public_settings(child) for child in value]
    if isinstance(value, str) and re.match(r"https?://", value.strip(), re.I):
        try:
            return scrub_source_url(value.strip())
        except ValueError:
            return ""
    return value


async def stage_payload(config, store, payload, *, provider, source_url="", content_type="application/json",
                        stream_key="", metadata=None, observed_at=None):
    values = {**(metadata or {}), "provider": provider}
    location = scrub_source_url(source_url)
    context = json.dumps([location, values, content_type, observed_at], sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode()
    key = hashlib.sha256(bytes(payload) + b"\0" + context).hexdigest()
    return await asyncio.to_thread(staging_queue(store, config).enqueue, payload, source="public:" + provider,
                                   adapter="public_source", content_type=content_type, source_url=location,
                                   stream_key=stream_key, metadata=values, observed_at=observed_at,
                                   idempotency_key=key)


def definitions():
    rows = [{"id": name, "name": label, "category": category, "family": name, "access": "native",
             "description": "Existing native collector", "homepage": homepage, "required": []}
            for name, label, category, homepage in NATIVE]
    for module, _ in EXTENSIONS.values():
        rows.extend(importlib.import_module("." + module, __package__).SOURCE_DEFINITIONS)
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        raise ValueError("Duplicate public source ID")
    return rows


def normalize_public_source(item, max_records=5000):
    from .normalization import NormalizationError
    provider = item.get("metadata", {}).get("provider")
    for module, handler in EXTENSIONS.values():
        implementation = importlib.import_module("." + module, __package__)
        if provider in {row["id"] for row in implementation.SOURCE_DEFINITIONS}:
            return getattr(implementation, handler)(item, max_records=max_records)
    raise NormalizationError("Unknown public-source provider")


def source_catalog(config, store):
    states = {row["name"]: row for row in store.sources()}
    settings = config.get("provider_settings", {})
    credentials = config.get("provider_credentials", {})
    rows = []
    for spec in definitions():
        provider = spec["id"]
        options = settings.get(provider, {})
        family_state = states.get(spec["family"], {})
        health = family_state.get("counts", {}).get("provider_health", {}).get(provider, {})
        if not health:
            health = states.get("provider:" + provider, {})
        if spec["access"] == "native":
            health = family_state
        enabled = config["sources"].get(spec["family"], False) and options.get("enabled", True)
        credential = bool(credentials.get(spec.get("credential_provider", provider)))
        requirements = list(health.get("requirements") or [])
        state = health.get("status") or (family_state.get("status") if spec["access"] == "native" else None) or "not_collected"
        if not enabled:
            state, requirements = "disabled", []
        elif spec["access"] == "api_key" and not credential and not (options.get("url") or options.get("urls")):
            state, requirements = "unconfigured", requirements or ["Provider credentials"]
        elif not health and spec["access"] in {"configured_url", "import"} and not (options.get("url") or options.get("urls")):
            state, requirements = "unconfigured", list(spec.get("required") or ["Public source URL or import"])
        row = {**spec, "status": state, "requirements": requirements, "enabled": bool(enabled),
               "credential_configured": credential, "credential_env": "SIGNALWATCH_" + spec.get("credential_provider", provider).upper() + "_CREDENTIALS", "health": health}
        rows.append(row)
    return {"items": rows, "total": len(rows)}
