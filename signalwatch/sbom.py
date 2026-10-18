import hashlib
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from .csaf import cpe_identity, purl_identity
from .matching import ecosystem_identity, normalize, package_identity


def canonical_asset_url(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("An asset URL is required")
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A public HTTP(S) asset URL without credentials is required")
    parsed.port
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


def components(document):
    if document.get("bomFormat") == "CycloneDX":
        version = document.get("specVersion")
        if version not in {"1.4", "1.5", "1.6", "1.7"}:
            raise ValueError(f"Unsupported CycloneDX specification version: {version}")
        rows = document.get("components", [])
        metadata = document.get("metadata", {})
        if not isinstance(rows, list) or not isinstance(metadata, dict):
            raise ValueError("CycloneDX components must be an array and metadata an object")
        pending = list(reversed(rows))
        if "component" in metadata:
            pending.append(metadata["component"])
        result = []
        while pending:
            item = pending.pop()
            if not isinstance(item, dict):
                raise ValueError("CycloneDX component entries must be objects")
            nested = item.get("components", [])
            if not isinstance(nested, list):
                raise ValueError("Nested CycloneDX components must be an array")
            result.append(item)
            pending.extend(reversed(nested))
        return "CycloneDX", version, result
    if "spdxVersion" in document:
        version = document["spdxVersion"]
        if version not in {"SPDX-2.2", "SPDX-2.3"}:
            raise ValueError(f"Unsupported SPDX specification version: {version}; only SPDX 2.2 and 2.3 JSON are supported")
        rows = document.get("packages", [])
        if not isinstance(rows, list) or any(not isinstance(item, dict) for item in rows):
            raise ValueError("SPDX packages must be an array of objects")
        return "SPDX", version.removeprefix("SPDX-"), rows
    raise ValueError("Unsupported SBOM format; expected CycloneDX 1.4–1.7 or SPDX 2.2/2.3 JSON; SPDX 3 and JSON-LD are unsupported")


def identifiers(component, format_name):
    if format_name == "CycloneDX":
        return [(kind, component[kind]) for kind in ("purl", "cpe") if component.get(kind)]
    references = component.get("externalRefs", [])
    if not isinstance(references, list) or any(not isinstance(item, dict) for item in references):
        raise ValueError("SPDX externalRefs must be an array of objects")
    values = []
    for item in references:
        kind = item.get("referenceType", "")
        if not isinstance(kind, str):
            raise ValueError("SPDX external reference types must be strings")
        if isinstance(kind, str) and kind.startswith(("http://spdx.org/rdf/references/", "https://spdx.org/rdf/references/")):
            kind = kind.rsplit("/", 1)[-1]
        if kind == "purl":
            values.append(("purl", item.get("referenceLocator")))
        elif kind in {"cpe22Type", "cpe23Type"}:
            values.append(("cpe", item.get("referenceLocator")))
    return values


def concrete_version(value):
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError("SBOM component versions must be strings")
    if value.casefold() in {"", "noassertion", "none", "unknown", "-"} or "*" in value or "?" in value:
        return ""
    return value


def observation_key(value):
    if value.get("ecosystem"):
        return ("package", ecosystem_identity(value["ecosystem"]), package_identity(value["ecosystem"], value["package"]), value["version"])
    return (value["part"], normalize(value["vendor"]), normalize(value["product"]), value["version"])


def parse_sbom(document, asset_url, source_key="default"):
    if not isinstance(document, dict):
        raise ValueError("The SBOM document must be a JSON object")
    if not isinstance(source_key, str) or not source_key.strip():
        raise ValueError("The SBOM source key must be a nonempty string")
    target = canonical_asset_url(asset_url)
    format_name, spec_version, rows = components(document)
    origin = "sbom:" + hashlib.sha256(source_key.encode()).hexdigest()[:24]
    observed_at = datetime.now(timezone.utc).isoformat()
    observations = []
    seen = set()
    reasons = Counter()
    imported = duplicates = 0
    for component in rows:
        if format_name == "CycloneDX" and component.get("scope") == "excluded":
            reasons["excluded_component"] += 1
            continue
        if format_name == "CycloneDX" and component.get("versionRange"):
            reasons["external_version_range"] += 1
            continue
        try:
            declared_version = concrete_version(component.get("version" if format_name == "CycloneDX" else "versionInfo"))
        except ValueError:
            reasons["invalid_version"] += 1
            continue
        values = identifiers(component, format_name)
        identities = []
        qualified = False
        for kind, value in values:
            if kind == "purl" and isinstance(value, str) and (urlsplit(value).query or urlsplit(value).fragment):
                qualified = True
            identity = purl_identity(value) if kind == "purl" else cpe_identity(value)
            if identity:
                identity = dict(identity)
                identity["identifier_kind"] = kind
                identity["identifier"] = value
                identity["version"] = concrete_version((identity.get("versions") or [identity.get("version")])[0])
                identities.append(identity)
        if not identities:
            reasons["qualified_purl_unsupported" if qualified else "no_supported_identifier"] += 1
            continue
        versions = {value for value in [declared_version, *(identity["version"] for identity in identities)] if value}
        if len(versions) > 1:
            reasons["version_mismatch"] += 1
            continue
        version = next(iter(versions), "")
        added = 0
        for identity in identities:
            identity["version"] = version
            key = observation_key(identity)
            if key in seen:
                continue
            seen.add(key)
            reference = component.get("bom-ref" if format_name == "CycloneDX" else "SPDXID")
            observation = {
                "asset_id": target, "origin": origin, "source_url": target,
                "observed_at": observed_at, "confidence": 1.0, "version": version,
                "sbom_format": format_name, "sbom_spec_version": spec_version,
                "sbom_source_key": source_key, "sbom_ref": reference,
                "evidence": f"User-supplied {format_name} {spec_version} SBOM; source={source_key}; identifier={identity['identifier']}",
            }
            if identity.get("ecosystem"):
                observation.update({"ecosystem": identity["ecosystem"], "package": identity["package"], "purl": identity["purl"], "part": "package"})
            else:
                observation.update({"vendor": identity["vendor"], "product": identity["product"], "part": identity["part"], "cpe": identity["criteria"]})
            observations.append(observation)
            added += 1
        if added:
            imported += 1
        else:
            duplicates += 1
    messages = {
        "excluded_component": "Excluded CycloneDX components are not imported.",
        "external_version_range": "External version ranges do not identify an installed version.",
        "invalid_version": "Component versions must be strings.",
        "qualified_purl_unsupported": "Qualified or subpath PURLs are unsupported; distribution and repository scopes are not guessed.",
        "no_supported_identifier": "No supported explicit CPE or PURL identity was found; package names are not used to infer one.",
        "version_mismatch": "Component and identifier versions disagree; conflicting entries are not imported.",
    }
    report = {
        "format": format_name, "spec_version": spec_version, "total": len(rows),
        "imported": imported, "skipped": sum(reasons.values()), "duplicates": duplicates,
        "observations": len(observations), "skip_reasons": dict(reasons),
        "warnings": [f"{count} component(s): {messages[reason]}" for reason, count in reasons.items()],
    }
    return {
        "batch": {
            "entities": [{"id": target, "kind": "asset", "name": target, "value": target, "source_url": target, "observed_at": observed_at, "metadata": {"evidence_role": "declared_sbom_inventory", "sbom_source_key": source_key}}],
            "observations": observations,
            "observation_snapshots": [{"asset_id": target, "origin": origin}],
        },
        "report": report,
    }
