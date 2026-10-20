"""Conservative, bounded evaluation of NVD CPE configuration trees.

The observation inventory is open world: an absent prerequisite is unknown,
not false. Evaluation is scoped to one asset and one affected product. This is
configuration evidence, never confirmation that a deployment is exploitable.
"""

import re

from .matching import normalize, version_match

UNKNOWN = "unknown"
MAX_NODES = 512
MAX_DEPTH = 20
MAX_CONDITIONS = 40
_ATTRIBUTES = ("part", "vendor", "product", "version", "update", "edition", "language",
               "sw_edition", "target_sw", "target_hw", "other")


def ensure_schema(conn):
    if "assessment" not in {row[1] for row in conn.execute("PRAGMA table_info(alerts)")}:
        conn.execute("ALTER TABLE alerts ADD COLUMN assessment TEXT NOT NULL DEFAULT '{}'")


def cpe_attributes(value):
    fields, field, escaped = [], [], False
    for character in str(value or ""):
        if character == ":" and not escaped:
            fields.append("".join(field))
            field = []
        else:
            field.append(character)
        escaped = character == "\\" and not escaped
    fields.append("".join(field))
    if len(fields) != 13 or fields[:2] != ["cpe", "2.3"]:
        return {}
    return dict(zip(_ATTRIBUTES, (re.sub(r"\\(.)", r"\1", part) for part in fields[2:])))


def _identity(item):
    return (normalize(item.get("vendor")), normalize(item.get("product")), item.get("part") or "a")


def _combine(operator, states):
    if not states:
        return UNKNOWN
    if operator == "AND":
        return "false" if "false" in states else UNKNOWN if UNKNOWN in states else "true"
    return "true" if "true" in states else UNKNOWN if UNKNOWN in states else "false"


def evaluate(configurations, observations, target):
    """Return tri-state applicability using only target's same-asset observations.

    OR branches describing other vulnerable products are excluded from the
    target's assessment; AND environmental requirements remain mandatory.
    Non-vulnerable CPE leaves describe required environments, not exclusions.
    """
    target = dict(target)
    identity = _identity(target)
    inventory = {}
    for item in observations:
        item = dict(item)
        if item.get("asset_id") == target.get("asset_id"):
            inventory.setdefault(_identity(item), []).append(item)
    conditions, visited, incomplete = [], 0, False

    def leaf(item):
        nonlocal visited, incomplete
        visited += 1
        if visited > MAX_NODES or not isinstance(item, dict):
            incomplete = True
            return UNKNOWN, False
        criteria = str(item.get("criteria") or item.get("cpe23Uri") or "")
        parsed = cpe_attributes(criteria)
        relevant = bool(parsed and _identity(parsed) == identity and item.get("vulnerable") is True)
        state, reason, ids = UNKNOWN, "CPE syntax or identity is unsupported.", []
        if parsed and parsed["part"] in {"a", "o", "h"} and all(
                value and not any(char in value for char in "*?") for value in (parsed["vendor"], parsed["product"])):
            observed = inventory.get(_identity(parsed), [])
            states = []
            for observation in observed:
                ids.append(observation.get("id", ""))
                matches, version_state, _ = version_match(observation.get("version"), item)
                bounded = any(item.get(key) not in (None, "") for key in
                              ("versionStartIncluding", "versionStartExcluding", "versionEndIncluding", "versionEndExcluding"))
                # A wildcard without bounds tests presence, not version order.
                result = "true" if parsed["version"] == "*" and not bounded else (
                    "false" if not matches else "true" if version_state in {"exact", "affected_range"} else UNKNOWN)
                actual = cpe_attributes(observation.get("cpe"))
                for key in _ATTRIBUTES[4:]:
                    wanted = parsed[key]
                    if wanted == "*":
                        continue
                    found = actual.get(key)
                    extra = (UNKNOWN if not found or found == "*" or any(char in wanted for char in "*?")
                             else "true" if normalize(found) == normalize(wanted) else "false")
                    result = _combine("AND", [result, extra])
                states.append(result)
            state = _combine("OR", states)
            company_environment = (str(target.get("asset_id", "")).startswith("company:")
                                   or str(target.get("origin", "")).startswith("technographic:")) and _identity(parsed) != identity
            if company_environment:
                # A company may run these products on unrelated hosts. Public
                # text cannot establish either presence or absence alongside
                # this specific affected deployment.
                state = UNKNOWN
            reason = ("Same-asset product and version requirements match." if state == "true" else
                      "Observed same-asset versions or CPE attributes contradict this requirement." if state == "false" else
                      "Company-level technology assertions do not establish a co-located deployment environment." if company_environment else
                      "Required product is not observed on this asset; absence is not proof of absence." if not observed else
                      "Observed version or required CPE attributes cannot be verified.")
        else:
            incomplete = True
        if len(conditions) < MAX_CONDITIONS:
            conditions.append({"criteria": criteria[:1000], "state": state, "reason": reason,
                               "vulnerable": item.get("vulnerable") is True,
                               "observation_ids": [value for value in ids[:8] if value]})
        return state, relevant

    def node(item, depth=0, in_negation=False):
        nonlocal visited, incomplete
        visited += 1
        if visited > MAX_NODES or depth > MAX_DEPTH or not isinstance(item, dict):
            incomplete = True
            return UNKNOWN, False
        operator = item.get("operator", "OR")
        if operator not in {"AND", "OR"} or not isinstance(item.get("negate", False), bool):
            incomplete = True
            return UNKNOWN, False
        leaves = item.get("cpeMatch", item.get("cpe_match", []))
        children = item.get("nodes", item.get("children", []))
        if not isinstance(leaves, list) or not isinstance(children, list):
            incomplete = True
            return UNKNOWN, False
        results = [leaf(value) for value in leaves[:MAX_NODES]]
        results.extend(node(value, depth + 1, in_negation or item.get("negate", False))
                       for value in children[:MAX_NODES] if visited <= MAX_NODES)
        relevant = any(result[1] for result in results)
        if len(leaves) + len(children) > MAX_NODES or visited > MAX_NODES:
            return UNKNOWN, relevant
        selected = ([result for result in results if result[1]]
                    if operator == "OR" and relevant and not in_negation and not item.get("negate") else results)
        state = _combine(operator, [result[0] for result in selected])
        if item.get("negate"):
            state = {"true": "false", "false": "true", UNKNOWN: UNKNOWN}[state]
        return state, relevant

    roots = configurations if isinstance(configurations, list) else [configurations]
    results = [node(item) for item in roots[:MAX_NODES]]
    relevant = [state for state, applies in results if applies]
    state = _combine("OR", relevant)
    limited = visited > MAX_NODES or len(roots) > MAX_NODES
    if limited or incomplete:
        state = UNKNOWN
    reason = ("Published configuration requirements match same-asset observations; deployment and exploitability still require verification."
              if state == "true" else "Observed same-asset evidence contradicts the published configuration requirements."
              if state == "false" else "CPE configuration or operating-system prerequisites remain unknown; retain the potential match.")
    return {"state": state, "reasons": [reason], "conditions": conditions,
            "limited": limited, "incomplete": incomplete, "inventory_scope": "same_asset"}
