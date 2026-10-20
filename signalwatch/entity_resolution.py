"""Deterministic company identity anchors within one authenticated workspace.

Identity matching does not grant ownership of every host or address associated
with an organization. Weak names and routing affiliations remain candidates.
"""
import ipaddress
import json
import re
import unicodedata
from urllib.parse import urlsplit

import tldextract


_PSL = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)
_LEGAL_SUFFIXES = {"inc", "incorporated", "llc", "ltd", "limited", "plc", "corp", "corporation", "gmbh", "ag", "sarl", "company", "co"}
_DENIED = "(status!='confirmed' OR role!='owned')"
NAME_TOKEN_LIMIT = 128
NAME_CANDIDATE_LIMIT = 200


class DomainConflict(ValueError):
    pass


def _hostname(value):
    if not isinstance(value, str):
        raise ValueError("Domain must be a hostname")
    value = value.strip().rstrip(".")
    if not value or any(character in value for character in "/:@*?#[]\\") or any(character.isspace() for character in value):
        raise ValueError("Domain must be a hostname without a URL, path, credentials, wildcard or port")
    try:
        domain = value.encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("Domain contains an invalid internationalized hostname") from error
    labels = domain.split(".")
    if len(domain) > 253 or len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("Domain must be a valid public hostname")
    try:
        ipaddress.ip_address(domain)
    except ValueError:
        return domain
    raise ValueError("A company domain cannot be an IP address")


def canonical_domain(value):
    domain = _hostname(value)
    parts = _PSL(domain)
    if not parts.suffix or not parts.domain:
        raise ValueError("Company domain must identify a registrable public hostname, not a public or private suffix")
    return domain


def _words(value):
    if not isinstance(value, str):
        return ""
    text = unicodedata.normalize("NFKC", value).casefold()
    return " ".join("".join(character if character.isalnum() else " " for character in text).split())


def normalize_company_name(value):
    words = _words(value).split()
    while words:
        if words[-1] in _LEGAL_SUFFIXES:
            words.pop()
        elif len(words) >= 3 and words[-3:] == ["l", "l", "c"]:
            del words[-3:]
        elif len(words) >= 4 and words[-4:] == ["s", "a", "r", "l"]:
            del words[-4:]
        else:
            break
    return " ".join(words)


def provenance_url(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError("Identity anchor requires an HTTP(S) evidence source URL")
    value = value.strip()
    try:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username is not None or parsed.password is not None:
            raise ValueError("Identity evidence URL must use HTTP(S) without credentials")
        parsed.port
        if any(character.isspace() for character in value) or any(ord(character) < 32 for character in value):
            raise ValueError("Identity evidence URL contains whitespace or control characters")
    except (TypeError, UnicodeError) as error:
        raise ValueError("Invalid identity evidence URL") from error
    return value


def ensure_schema(conn):
    columns = {row[1] for row in conn.execute("PRAGMA table_info(company_profiles)")}
    for column in ("primary_domain", "primary_domain_evidence", "primary_domain_source_url"):
        if column not in columns:
            conn.execute("ALTER TABLE company_profiles ADD COLUMN " + column + " TEXT NOT NULL DEFAULT ''")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS company_primary_domain ON company_profiles(primary_domain) WHERE primary_domain!=''")
    conn.execute("""CREATE TABLE IF NOT EXISTS company_asn_anchors (
     company_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
     asn INTEGER NOT NULL CHECK(asn BETWEEN 1 AND 4294967295), evidence TEXT NOT NULL,
     source_url TEXT NOT NULL, verified_at TEXT NOT NULL, PRIMARY KEY(company_id,asn))""")
    conn.execute("CREATE INDEX IF NOT EXISTS company_asn_anchor_lookup ON company_asn_anchors(asn,company_id)")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS company_asn_anchor_insert BEFORE INSERT ON company_asn_anchors
     WHEN NOT EXISTS(SELECT 1 FROM entities WHERE id=new.company_id AND kind='company')
     BEGIN SELECT RAISE(ABORT,'ASN anchor requires a company entity'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS company_asn_anchor_update BEFORE UPDATE OF company_id ON company_asn_anchors
     WHEN NOT EXISTS(SELECT 1 FROM entities WHERE id=new.company_id AND kind='company')
     BEGIN SELECT RAISE(ABORT,'ASN anchor requires a company entity'); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS company_identity_entity_guard BEFORE UPDATE OF id,kind ON entities
     WHEN old.kind='company' AND (new.kind IS NOT 'company' OR new.id IS NOT old.id) AND (
       EXISTS(SELECT 1 FROM company_profiles WHERE company_id=old.id OR parent_company_id=old.id)
       OR EXISTS(SELECT 1 FROM company_asn_anchors WHERE company_id=old.id)
       OR EXISTS(SELECT 1 FROM company_asset_decisions WHERE company_id=old.id))
     BEGIN SELECT RAISE(ABORT,'Company identity references require a stable company entity'); END""")
    for operation in ("INSERT", "UPDATE OF company_id"):
        name = "insert" if operation == "INSERT" else "update"
        conn.execute(f"""CREATE TRIGGER IF NOT EXISTS company_profile_type_{name} BEFORE {operation} ON company_profiles
         WHEN NOT EXISTS(SELECT 1 FROM entities WHERE id=new.company_id AND kind='company')
         BEGIN SELECT RAISE(ABORT,'Company profile requires a company entity'); END""")
    conn.execute("""CREATE TABLE IF NOT EXISTS company_identity_labels (
     company_id TEXT NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
     label TEXT NOT NULL, UNIQUE(company_id,label))""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS company_identity_label_entity_guard BEFORE UPDATE OF id,kind ON entities
     WHEN old.kind='company' AND (new.kind IS NOT 'company' OR new.id IS NOT old.id)
      AND EXISTS(SELECT 1 FROM company_identity_labels WHERE company_id=old.id)
     BEGIN SELECT RAISE(ABORT,'Company labels require a stable company entity'); END""")
    conn.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS company_identity_fts USING fts5(
     label, content=company_identity_labels, content_rowid=rowid)""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS company_identity_label_ai AFTER INSERT ON company_identity_labels BEGIN
     INSERT INTO company_identity_fts(rowid,label) VALUES(new.rowid,new.label); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS company_identity_label_ad AFTER DELETE ON company_identity_labels BEGIN
     INSERT INTO company_identity_fts(company_identity_fts,rowid,label) VALUES('delete',old.rowid,old.label); END""")
    conn.execute("""CREATE TRIGGER IF NOT EXISTS company_identity_label_au AFTER UPDATE ON company_identity_labels BEGIN
     INSERT INTO company_identity_fts(company_identity_fts,rowid,label) VALUES('delete',old.rowid,old.label);
     INSERT INTO company_identity_fts(rowid,label) VALUES(new.rowid,new.label); END""")
    conn.execute("CREATE TABLE IF NOT EXISTS company_identity_migrations(version TEXT PRIMARY KEY)")
    if not conn.execute("SELECT 1 FROM company_identity_migrations WHERE version='normalized-labels-v1'").fetchone():
        for row in conn.execute("SELECT id FROM entities WHERE kind='company'"):
            refresh_labels(conn, row[0])
        conn.execute("INSERT INTO company_identity_migrations VALUES('normalized-labels-v1')")


def refresh_labels(conn, company_id):
    """Maintain candidate search labels without changing source/profile labels."""
    row = conn.execute("""SELECT e.name,p.name AS profile_name,p.legal_name,p.aliases,p.brands
     FROM entities e LEFT JOIN company_profiles p ON p.company_id=e.id WHERE e.id=? AND e.kind='company'""", (company_id,)).fetchone()
    labels = [row["name"], row["profile_name"], row["legal_name"]] if row else []
    if row:
        for key in ("aliases", "brands"):
            try:
                values = json.loads(row[key] or "[]")
            except (TypeError, ValueError):
                values = []
            if isinstance(values, list):
                labels.extend(value for value in values if isinstance(value, str))
    labels = {normalize_company_name(label) for label in labels}
    labels = {label for label in labels if len(label) > 1}
    old = {item[0] for item in conn.execute("SELECT label FROM company_identity_labels WHERE company_id=?", (company_id,))}
    conn.executemany("DELETE FROM company_identity_labels WHERE company_id=? AND label=?", [(company_id, label) for label in old - labels])
    conn.executemany("INSERT INTO company_identity_labels(company_id,label) VALUES(?,?)", [(company_id, label) for label in sorted(labels - old)])


def verified_asns(conn, company_id):
    return [dict(row) for row in conn.execute("SELECT asn,evidence,source_url,verified_at FROM company_asn_anchors WHERE company_id=? ORDER BY asn", (company_id,))]


def prepare_asns(values, previous, timestamp):
    if not isinstance(values, list) or len(values) > 100:
        raise ValueError("Verified ASNs must be an array of at most 100 evidence records")
    previous = {record["asn"]: record for record in previous}
    retained = {}
    for value in values:
        if not isinstance(value, dict) or type(value.get("asn")) is not int or not 1 <= value["asn"] <= 4294967295:
            raise ValueError("ASN must be an integer between 1 and 4294967295")
        evidence = value.get("evidence")
        if not isinstance(evidence, str) or not evidence.strip() or len(evidence) > 10000:
            raise ValueError("Verified ASN requires nonempty evidence of at most 10000 characters")
        result = {"asn": value["asn"], "evidence": evidence.strip(), "source_url": provenance_url(value.get("source_url"))}
        old = previous.get(result["asn"], {})
        result["verified_at"] = old.get("verified_at", timestamp) if all(old.get(key) == result[key] for key in ("evidence", "source_url")) else timestamp
        if result["asn"] in retained and retained[result["asn"]] != result:
            raise ValueError("Duplicate ASN entries contain conflicting evidence")
        retained[result["asn"]] = result
    return [retained[key] for key in sorted(retained)]


def _excluded(conn, company_id, host, anchor=None):
    exact = conn.execute("SELECT status,role FROM company_asset_decisions WHERE company_id=? AND asset_id=?", (company_id, "domain:" + host)).fetchone()
    if exact is not None:
        return tuple(exact) != ("confirmed", "owned")
    if anchor and anchor != host:
        labels = host.split(".")
        ancestors = ["domain:" + ".".join(labels[index:]) for index in range(1, len(labels) - len(anchor.split(".")) + 1)]
        if ancestors:
            denied = conn.execute("SELECT 1 FROM company_asset_decisions WHERE company_id=? AND asset_id IN (" +
                                  ",".join("?" for _ in ancestors) + ") AND " + _DENIED + " LIMIT 1", (company_id, *ancestors)).fetchone()
            if denied:
                return True
    return False


def _domain_match(conn, host):
    labels = host.split(".")
    suffixes = [".".join(labels[index:]) for index in range(len(labels) - 1)]
    # Probe bounded label suffixes through the unique anchor index instead of
    # scanning every company for every article or asset lookup.
    rows = conn.execute("""SELECT p.company_id,p.primary_domain FROM company_profiles p CROSS JOIN entities e ON e.id=p.company_id AND e.kind='company'
     WHERE p.primary_domain!='' AND p.primary_domain IN (""" + ",".join("?" for _ in suffixes) + ") ORDER BY length(p.primary_domain) DESC,p.company_id", suffixes).fetchall()
    if rows:
        row = rows[0]
        if _excluded(conn, row["company_id"], host, row["primary_domain"]):
            return {"owners": [], "blocked": [row["company_id"]], "method": "primary_domain", "matched_domain": row["primary_domain"]}
        # A manual claim for this precise host by a different company remains
        # a conflict instead of silently replacing either operator decision.
        others = [item[0] for item in conn.execute("""SELECT a.company_id FROM company_asset_decisions a JOIN entities e ON e.id=a.company_id AND e.kind='company'
         WHERE a.asset_id=? AND a.status='confirmed' AND a.role='owned' AND a.company_id!=? ORDER BY a.company_id""", ("domain:" + host, row["company_id"]))]
        return {"owners": [row["company_id"], *others], "blocked": [], "method": "primary_domain", "matched_domain": row["primary_domain"]}
    # Preserve unambiguous existing official/manual domain evidence. A www
    # alias is only the legacy fallback; primary anchors never collapse it.
    apex = host.removeprefix("www.")
    variants = ("domain:" + apex, "domain:www." + apex)
    candidates = conn.execute("""SELECT DISTINCT e.id FROM (
      SELECT from_id AS company_id FROM edges WHERE relation='official_website' AND to_id IN (?,?)
      UNION SELECT company_id FROM company_asset_decisions WHERE asset_id IN (?,?) AND status='confirmed' AND role='owned'
     ) a CROSS JOIN entities e ON a.company_id=e.id WHERE e.kind='company' ORDER BY e.id""", variants * 2).fetchall()
    owners, blocked = [], []
    for (company_id,) in candidates:
        denied = _excluded(conn, company_id, host)
        if not denied:
            denied = bool(conn.execute("SELECT 1 FROM company_asset_decisions WHERE company_id=? AND asset_id IN (?,?) AND " + _DENIED + " LIMIT 1", (company_id, *variants)).fetchone())
        (blocked if denied else owners).append(company_id)
    return {"owners": owners, "blocked": blocked, "method": "legacy_domain", "matched_domain": host}


def _name_candidates(conn, context, text):
    names = [normalize_company_name(context.get(key)) for key in ("name", "legal_name", "alias", "company_name")]
    names = {name for name in names if len(name) > 1}
    body = " " + _words(text[:64000] if isinstance(text, str) else "") + " "
    if not names and body == "  ":
        return set()
    tokens = list(dict.fromkeys(" ".join(sorted(names)).split() + body.split()))[:NAME_TOKEN_LIMIT]
    if not tokens:
        return set()
    expression = " OR ".join('"' + token.replace('"', '""') + '"' for token in tokens)
    candidates = set()
    # Hydrate at most this many indexed label hits. Names always remain weak
    # candidates, including when a common label exceeds the search budget.
    rows = conn.execute("""SELECT l.company_id,l.label FROM company_identity_fts
     CROSS JOIN company_identity_labels l ON l.rowid=company_identity_fts.rowid
     CROSS JOIN entities e ON e.id=l.company_id
     WHERE company_identity_fts MATCH ? AND e.kind='company'
     ORDER BY company_identity_fts.rowid LIMIT ?""", (expression, NAME_CANDIDATE_LIMIT))
    for row in rows:
        if row["label"] in names or " " + row["label"] + " " in body:
            candidates.add(row["company_id"])
    return candidates


def resolve(conn, context=None, source_url="", text=""):
    context = context if isinstance(context, dict) else {}
    explicit = context.get("company_id") if isinstance(context.get("company_id"), str) else ""
    explicit_exists = bool(explicit and conn.execute("SELECT 1 FROM entities WHERE id=? AND kind='company'", (explicit,)).fetchone())
    hosts = []
    source_host = None
    if isinstance(source_url, str) and source_url:
        try:
            parsed = urlsplit(provenance_url(source_url))
            source_host = parsed.hostname
        except ValueError:
            pass
    for value in (context.get("domain"), source_host):
        if value:
            try:
                host = _hostname(value)
            except ValueError:
                continue
            if host not in hosts:
                hosts.append(host)
    matches = [_domain_match(conn, host) for host in hosts]
    owners = set(owner for match in matches for owner in match["owners"])
    # A rejected competing owner disambiguates a single host. A separately
    # supplied, wholly excluded host still vetoes another host's resolution.
    blocked = set(owner for match in matches if not match["owners"] for owner in match["blocked"])
    evidence = next((match for match in matches if match["owners"] and match["method"] == "primary_domain"),
                    next((match for match in matches if match["owners"]), None))
    output = {"organization_id": None, "status": "unattributed", "method": "none", "candidates": [], "matched_domain": "", "reason": "No unique domain identity evidence"}
    if owners:
        candidates = owners | blocked | ({explicit} if explicit_exists else set())
        if blocked or len(owners) != 1 or explicit and (not explicit_exists or explicit not in owners):
            return {**output, "status": "conflict", "method": "domain_conflict", "candidates": sorted(candidates),
                    "matched_domain": evidence["matched_domain"], "reason": "Company identifiers or domain anchors disagree"}
        owner = next(iter(owners))
        return {**output, "organization_id": owner, "status": "resolved", "method": evidence["method"],
                "candidates": [owner], "matched_domain": evidence["matched_domain"], "reason": "Unique matching company domain evidence"}
    if blocked:
        return {**output, "status": "conflict", "method": "manual_exclusion", "candidates": sorted(blocked),
                "matched_domain": next(match["matched_domain"] for match in matches if match["blocked"]),
                "reason": "Manual asset decisions exclude the matching company"}
    if explicit and not explicit_exists:
        return {**output, "status": "conflict", "method": "invalid_company", "reason": "The supplied company identifier does not identify a company"}
    candidates = _name_candidates(conn, context, text)
    method = "name_candidate" if candidates else "none"
    asn = context.get("asn")
    if isinstance(asn, str) and re.fullmatch(r"(?:AS)?[0-9]+", asn.strip(), re.I):
        asn = int(asn.strip().upper().removeprefix("AS"))
    if type(asn) is int and 1 <= asn <= 4294967295:
        affiliated = {row[0] for row in conn.execute("SELECT company_id FROM company_asn_anchors WHERE asn=? ORDER BY company_id", (asn,))}
        candidates.update(affiliated)
        if affiliated:
            method = "asn_affiliation"
    if explicit_exists:
        candidates.add(explicit)
        if method == "none":
            method = "explicit_candidate"
    if candidates:
        return {**output, "status": "candidate", "method": method, "candidates": sorted(candidates),
                "reason": "Names, explicit identifiers and ASN affiliations require supporting domain evidence"}
    return output
