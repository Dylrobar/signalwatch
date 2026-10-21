"""Separate product/version candidates from evidence of runtime exposure.

Passive technology observations cannot establish application code reachability.
The small reviewed prerequisite catalog cites publisher evidence; absence of a
component in the inventory is unknown, never proof it is disabled.
"""
from .matching import normalize

PHP_PDO_ADVISORY = "https://github.com/php/php-src/security/advisories/GHSA-8xr5-qppj-gvwj"
PREREQUISITES = {
    "CVE-2025-14180": {
        "source_url": PHP_PDO_ADVISORY,
        "impact": "Availability impact (denial of service); no confidentiality or integrity impact reported by the publisher.",
        "requirements": [
            "The affected PHP runtime uses the PDO PostgreSQL driver.",
            "The relevant PDO connection enables PDO::ATTR_EMULATE_PREPARES.",
            "Attacker-controlled invalid character sequences reach the affected prepared-statement parameter path.",
        ],
    },
}


def assess(record, evidence):
    supporting = evidence.get("supporting", [])
    reasons = ["A product/version correlation is not a demonstrated exposure. Runtime configuration and reachable application paths have not been verified."]
    http = any(item.get("kind") == "http_observation" for item in supporting)
    if http:
        reasons.append("HTTP banners are self-reported technology evidence; they do not establish the installed package revision, distribution backport status, or enabled modules.")
    if record["version_state"] not in {"exact", "affected_range"}:
        reasons.append("The affected installed version has not been established.")
    if evidence.get("contradicting"):
        reasons.append("Conflicting or contrary evidence exists; resolve it before reporting this asset as affected.")
    versions = {item.get("version") for item in supporting if item.get("kind") == "http_observation"
                and normalize(item.get("product")) == normalize(record.get("product")) and item.get("version") not in {None, "", "*", "-"}}
    if len(versions) > 1:
        reasons.append("HTTP observations report different versions; they may describe stale banners or separate deployments.")
    rule = PREREQUISITES.get(record["advisory_id"], {})
    requirements = [{"requirement": value, "state": "unknown", "source_url": rule["source_url"]}
                    for value in rule.get("requirements", [])]
    if requirements:
        reasons.append("Publisher-specific prerequisites are unverified. CMS detection, including WordPress, does not prove a database driver is present or absent.")
    return {"state": "unverified", "label": "Needs runtime verification", "reportable": None,
            "reasons": reasons, "prerequisites": requirements, "impact": rule.get("impact"),
            "patch_status": "unverified" if http else "not_assessed",
            "reachability": "unknown"}
