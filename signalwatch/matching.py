import re
import unicodedata

from packaging.version import InvalidVersion, Version
from packaging.specifiers import InvalidSpecifier, Specifier


CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.I)


def normalize(value):
    value = unicodedata.normalize("NFKC", str(value or "")).casefold()
    return re.sub(r"[\s_-]+", " ", value).strip()


def ecosystem_identity(ecosystem):
    value = str(ecosystem or "")
    head, separator, scope = value.partition(":")
    key = normalize(head)
    canonical = {"pip": "pypi", "rust": "crates.io", "composer": "packagist", "actions": "github actions", "erlang": "hex", "swift": "swifturl"}.get(key, key)
    return canonical + (":" + scope if separator else "")


def package_identity(ecosystem, package):
    if ecosystem_identity(ecosystem) == "pypi":
        return re.sub(r"[-_.]+", "-", str(package)).casefold()
    return str(package)


def identifier(value):
    value = str(value or "").strip()
    return value.upper() if value.upper().startswith(("CVE-", "GHSA-")) else value


def cpe_fields(value):
    fields, field, escaped = [], [], False
    for character in str(value or ""):
        if character == ":" and not escaped:
            fields.append("".join(field))
            field = []
        else:
            field.append(character)
        escaped = character == "\\" and not escaped
    fields.append("".join(field))
    if len(fields) < 6 or fields[:2] != ["cpe", "2.3"]:
        return {}
    return dict(zip(("part", "vendor", "product", "version"), (re.sub(r"\\(.)", r"\1", value) for value in fields[2:6])))


def comparable(value):
    value = str(value or "").strip()
    if not re.fullmatch(r"v?\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?", value, re.I):
        return None
    try:
        return Version(value)
    except InvalidVersion:
        return None


def version_match(observed, affected):
    observed = str(observed or "").strip()
    if not observed or observed in {"*", "-", "unknown"}:
        return True, "unknown", "Observed version is unknown."
    if affected.get("version_unverified"):
        return True, "version_unverified", "Native version/status rules require verification before affected versions can be established."
    version = str(affected.get("version") or cpe_fields(affected.get("criteria")).get("version") or "*")
    current = comparable(observed)
    uncertain = False
    checks = 0
    if version not in {"*", "-", ""}:
        if observed.casefold() == version.casefold():
            checks += 1
        elif "*" in version or "?" in version:
            uncertain = True
        else:
            expected = comparable(version)
            if current is not None and expected is not None:
                if current != expected:
                    return False, "unaffected", "Observed version differs from the specified affected version."
                checks += 1
            else:
                uncertain = True
    for key, operator in (("versionStartIncluding", "ge"), ("versionStartExcluding", "gt"), ("versionEndIncluding", "le"), ("versionEndExcluding", "lt")):
        if affected.get(key) in (None, ""):
            continue
        bound = comparable(affected[key])
        if current is None or bound is None:
            uncertain = True
            continue
        passed = {"ge": current >= bound, "gt": current > bound, "le": current <= bound, "lt": current < bound}[operator]
        if not passed:
            return False, "unaffected", "Observed version falls outside a supported affected version bound."
        checks += 1
    if uncertain:
        return True, "version_unverified", "Version syntax or CPE pattern requires manual verification."
    if checks:
        state = "exact" if version not in {"*", "-", ""} else "affected_range"
        return True, state, "Observed version matches published affected version criteria."
    return True, "version_unverified", "The advisory does not provide a bounded affected version range."


def rank(severity=None, kev=False, epss=None):
    return round(min(100.0, max(0.0, float(severity or 0)) * 5 + (40 if kev else 0) + max(0.0, min(1.0, float(epss or 0))) * 10), 2)


def semver(value, *, allow_v=False):
    """Strict SemVer 2.0 precedence, including prereleases and build metadata."""
    value = str(value or "")
    if len(value) > 256:
        return None
    if allow_v:
        value = value.removeprefix("v")
    number = r"(?:0|[1-9][0-9]*)"
    match = re.fullmatch(rf"({number})\.({number})\.({number})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?", value)
    if not match:
        return None
    prerelease = match.group(4)
    identifiers = (prerelease or "").split(".") if prerelease else []
    if any(item.isdigit() and len(item) > 1 and item.startswith("0") for item in identifiers):
        return None
    return (*map(int, match.groups()[:3]), 0 if prerelease else 1,
            tuple((0, int(item)) if item.isdigit() else (1, item) for item in identifiers))


def pep440(value):
    try:
        return Version(str(value)) if len(str(value)) <= 256 else None
    except InvalidVersion:
        return None


def osv_version_match(observed, affected):
    observed = str(observed or "").strip()
    if not observed or observed in {"*", "-", "unknown"}:
        return True, "unknown", "Observed package version is unknown."
    versions = affected.get("versions") or []
    if observed in versions:
        return True, "exact", "Observed package version is explicitly listed by OSV."
    ranges = affected.get("ranges") or []
    if not ranges and affected.get("version_range"):
        return github_version_match(observed, affected)
    if not ranges:
        if versions:
            return False, "unaffected", "Observed package version is absent from OSV's enumerated affected versions."
        return True, "version_unverified", "OSV does not provide comparable affected versions."
    uncertain = False
    for interval in ranges:
        if not isinstance(interval, dict):
            uncertain = True
            continue
        range_type = interval.get("type")
        supported = range_type == "SEMVER" or (range_type == "ECOSYSTEM" and ecosystem_identity(affected.get("ecosystem")) == "pypi")
        compare = semver if range_type == "SEMVER" else pep440
        current = compare(observed)
        if not supported or current is None or not isinstance(interval.get("events"), list) or not interval["events"]:
            uncertain = True
            continue
        introduced = None
        active = False
        for event in interval.get("events", []):
            if not isinstance(event, dict) or len(event) != 1 or not set(event) <= {"introduced", "fixed", "last_affected", "limit"}:
                uncertain = True
                continue
            if "introduced" in event:
                if active:
                    uncertain = True
                introduced = event["introduced"]
                active = True
                continue
            closing = next((key for key in ("fixed", "last_affected", "limit") if key in event), None)
            if not closing or not active:
                uncertain = True
                continue
            lower = None if introduced == "0" else compare(introduced)
            upper = compare(event[closing])
            if upper is None or (introduced != "0" and lower is None) or (lower is not None and upper < lower):
                uncertain = True
            elif (lower is None or current >= lower) and (current <= upper if closing == "last_affected" else current < upper):
                return True, "affected_range", "Observed package version matches an OSV affected range."
            active = False
        if active:
            lower = None if introduced == "0" else compare(introduced)
            if introduced != "0" and lower is None:
                uncertain = True
            elif lower is None or current >= lower:
                return True, "affected_range", "Observed package version matches an OSV affected range."
    if uncertain:
        return True, "version_unverified", "OSV range syntax requires ecosystem-specific verification."
    return False, "unaffected", "Observed package version falls outside the published OSV ranges."


def github_version_match(observed, affected):
    ecosystem = ecosystem_identity(affected.get("ecosystem"))
    observed = str(observed or "").strip()
    if ecosystem not in {"pypi", "npm", "crates.io", "go"}:
        return True, "version_unverified", "GitHub package range requires ecosystem-specific verification."
    compare = pep440 if ecosystem == "pypi" else lambda value: semver(value, allow_v=True)
    current = compare(observed)
    if current is None:
        return True, "version_unverified", "GitHub package version syntax is unsupported."
    conditions = str(affected.get("version_range") or "").split(",")
    evaluated = []
    prerelease_anchor = False
    for condition in conditions:
        match = re.fullmatch(r"\s*(<=|>=|<|>|==|=)\s*(\S+)\s*", condition)
        if match is None:
            return True, "version_unverified", "GitHub package range syntax is unsupported."
        operator, version = match.groups()
        bound = compare(version)
        if bound is None:
            return True, "version_unverified", "GitHub package range syntax is unsupported."
        if ecosystem == "pypi":
            try:
                evaluated.append(Specifier(("==" if operator == "=" else operator) + version).contains(current, prereleases=True))
            except InvalidSpecifier:
                return True, "version_unverified", "GitHub package range syntax is unsupported."
        else:
            prerelease_anchor = prerelease_anchor or bound[3] == 0 and bound[:3] == current[:3]
            evaluated.append({"<=": current <= bound, ">=": current >= bound, "<": current < bound, ">": current > bound, "==": current == bound, "=": current == bound}[operator])
    if ecosystem != "pypi" and current[3] == 0 and not prerelease_anchor:
        return True, "version_unverified", "Prerelease inclusion requires an explicit same-release prerelease bound."
    if not all(evaluated):
        return False, "unaffected", "Observed package version falls outside GitHub's affected range."
    return True, "affected_range", "Observed package version matches GitHub's affected range."
