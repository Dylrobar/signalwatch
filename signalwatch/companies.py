"""User company profiles and evidence-based asset associations.

Profiles and decisions are separate from source entities so collection cannot
overwrite a user's labels or attribution decisions.
"""
import ipaddress
import json
import math
from collections import defaultdict
from urllib.parse import urlsplit


COMPANY_SCHEMA = """
CREATE TABLE IF NOT EXISTS company_profiles (
 company_id TEXT PRIMARY KEY, name TEXT NOT NULL, legal_name TEXT NOT NULL DEFAULT '',
 aliases TEXT NOT NULL DEFAULT '[]', brands TEXT NOT NULL DEFAULT '[]',
 parent_company_id TEXT NOT NULL DEFAULT '', notes TEXT NOT NULL DEFAULT '',
 source_url TEXT NOT NULL DEFAULT '', updated_at TEXT NOT NULL,
 primary_domain TEXT NOT NULL DEFAULT '', primary_domain_evidence TEXT NOT NULL DEFAULT '',
 primary_domain_source_url TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS company_parent ON company_profiles(parent_company_id);
CREATE TABLE IF NOT EXISTS company_asset_decisions (
 company_id TEXT NOT NULL, asset_id TEXT NOT NULL, status TEXT NOT NULL,
 role TEXT NOT NULL, evidence TEXT NOT NULL DEFAULT '', source_url TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL, PRIMARY KEY(company_id, asset_id)
);
CREATE VIRTUAL TABLE IF NOT EXISTS company_profile_fts USING fts5(
 name, legal_name, aliases, brands, content=company_profiles, content_rowid=rowid
);
CREATE TRIGGER IF NOT EXISTS company_profile_ai AFTER INSERT ON company_profiles BEGIN
 INSERT INTO company_profile_fts(rowid,name,legal_name,aliases,brands)
 VALUES(new.rowid,new.name,new.legal_name,new.aliases,new.brands);
END;
CREATE TRIGGER IF NOT EXISTS company_profile_ad AFTER DELETE ON company_profiles BEGIN
 INSERT INTO company_profile_fts(company_profile_fts,rowid,name,legal_name,aliases,brands)
 VALUES('delete',old.rowid,old.name,old.legal_name,old.aliases,old.brands);
END;
CREATE TRIGGER IF NOT EXISTS company_profile_au AFTER UPDATE ON company_profiles
 WHEN old.name!=new.name OR old.legal_name!=new.legal_name OR old.aliases!=new.aliases OR old.brands!=new.brands BEGIN
 INSERT INTO company_profile_fts(company_profile_fts,rowid,name,legal_name,aliases,brands)
 VALUES('delete',old.rowid,old.name,old.legal_name,old.aliases,old.brands);
 INSERT INTO company_profile_fts(rowid,name,legal_name,aliases,brands)
 VALUES(new.rowid,new.name,new.legal_name,new.aliases,new.brands);
END;
"""

MAX_ASSETS = 500
MAX_HOPS = 4
MAX_EDGES = 5000
MAX_PROOF = 64


def company(conn, company_id):
    row = conn.execute("SELECT * FROM entities WHERE id=?", (company_id,)).fetchone()
    if row is None:
        raise LookupError("Company does not exist")
    if row["kind"] != "company":
        raise ValueError("Entity is not a company")
    return dict(row)


def labels(values):
    from .entity_resolution import normalize_company_name
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError("Company aliases and brands must be arrays of strings")
    unique = {}
    for value in values:
        value = value.strip()
        if value:
            unique.setdefault(normalize_company_name(value) or value.casefold(), value)
    return list(unique.values())


def validate_parent(conn, company_id, parent_company_id):
    if not parent_company_id:
        return
    company(conn, parent_company_id)
    seen = {company_id}
    current = parent_company_id
    while current:
        if current in seen:
            raise ValueError("Company parent relationship would create a cycle")
        seen.add(current)
        row = conn.execute("SELECT parent_company_id FROM company_profiles WHERE company_id=?", (current,)).fetchone()
        current = row[0] if row else ""


def asset_identity(asset_url):
    try:
        parsed = urlsplit(asset_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Asset must be an HTTP(S) URL without credentials")
        parsed.port
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if not host:
            raise ValueError("Asset URL requires a hostname")
        try:
            host = str(ipaddress.ip_address(host))
        except ValueError:
            pass
        return "domain:" + host, host
    except (UnicodeError, TypeError) as error:
        raise ValueError("Invalid asset hostname") from error


def compact_company(conn, company_id):
    row = conn.execute("""SELECT e.id,e.kind,coalesce(p.name,e.name) AS name,e.value
     FROM entities e LEFT JOIN company_profiles p ON p.company_id=e.id
     WHERE e.id=? AND e.kind='company'""", (company_id,)).fetchone()
    return dict(row) if row else None


def company_profile(conn, entity):
    from .entity_resolution import verified_asns
    row = conn.execute("SELECT * FROM company_profiles WHERE company_id=?", (entity["id"],)).fetchone()
    saved = dict(row) if row else {}
    parent_id = saved.get("parent_company_id", "")
    children = conn.execute("""SELECT e.id,e.kind,p.name,e.value FROM company_profiles p
     JOIN entities e ON e.id=p.company_id WHERE p.parent_company_id=? AND e.kind='company'
     ORDER BY p.name COLLATE NOCASE,e.id""", (entity["id"],))
    return {
        "company_id": entity["id"], "name": saved.get("name", entity["name"]),
        "legal_name": saved.get("legal_name", ""), "aliases": json.loads(saved.get("aliases", "[]")),
        "brands": json.loads(saved.get("brands", "[]")), "parent_company_id": parent_id,
        "parent_company": compact_company(conn, parent_id) if parent_id else None,
        "subsidiaries": [dict(child) for child in children], "notes": saved.get("notes", ""),
        "source_url": saved.get("source_url", entity.get("source_url") or ""),
        "updated_at": saved.get("updated_at", entity["updated_at"]),
        "primary_domain": saved.get("primary_domain", ""),
        "primary_domain_evidence": saved.get("primary_domain_evidence", ""),
        "primary_domain_source_url": saved.get("primary_domain_source_url", ""),
        "verified_asns": verified_asns(conn, entity["id"]),
    }


def confidence(value):
    try:
        result = float(value)
        return min(1.0, max(0.0, result)) if math.isfinite(result) else 0.0
    except (TypeError, ValueError):
        return 0.0


def www_equivalent(left, right):
    left, right = left.removeprefix("domain:"), right.removeprefix("domain:")
    return left != right and (left == "www." + right or right == "www." + left)


def company_assets(conn, company_id):
    """Resolve a bounded graph without treating shared networks as ownership."""
    from .entity_resolution import resolve
    nodes, decisions, official, edges, proofs = {}, {}, defaultdict(list), [], defaultdict(set)
    truncated = False
    saved = conn.execute("SELECT * FROM company_profiles WHERE company_id=?", (company_id,)).fetchone()
    profile = dict(saved) if saved else {}
    primary_domain = profile.get("primary_domain", "")
    primary_asset = "domain:" + primary_domain if primary_domain else ""
    namespace_edges = {}

    def add(asset_id):
        nonlocal truncated
        if not asset_id.startswith("domain:"):
            return False
        if asset_id not in nodes:
            if len(nodes) >= MAX_ASSETS:
                truncated = True
                return False
            nodes[asset_id] = {"id": asset_id}
        return True

    def edge(value):
        edges.append(value)
        return len(edges) - 1

    def bounded_proof(proof, asset_id, path):
        nonlocal truncated
        proof = proof | set(path)
        if len(proof) <= MAX_PROOF:
            return proof
        truncated = True
        selected = list(dict.fromkeys(path))
        ordered = sorted(proof - set(selected), key=lambda index: (edges[index]["to_id"] != asset_id,
                                                                  edges[index]["relation"] != "redirects_to", index))
        # Keep relationship steps before additional source variants of a step,
        # reserving one complete source-to-target path before alternatives.
        variants = []
        relationships = {(edges[index]["from_id"], edges[index]["to_id"], edges[index]["relation"]) for index in selected}
        for index in ordered:
            item = edges[index]
            identity = (item["from_id"], item["to_id"], item["relation"])
            if identity in relationships:
                variants.append(index)
            else:
                relationships.add(identity)
                selected.append(index)
        return set((selected + variants)[:MAX_PROOF])

    if primary_asset and add(primary_asset):
        item = {"from_id": company_id, "to_id": primary_asset, "relation": "primary_domain_anchor",
                "source_url": profile.get("primary_domain_source_url", ""),
                "observed_at": profile["updated_at"], "confidence": 1.0,
                "evidence": profile.get("primary_domain_evidence", "")}
        official[primary_asset].append(item)
        proofs[primary_asset].add(edge(item))

    # User decisions take precedence and remain visible even without a current
    # source relationship. They never rewrite the source-managed graph.
    rows = conn.execute("SELECT * FROM company_asset_decisions WHERE company_id=? ORDER BY asset_id LIMIT ?", (company_id, MAX_ASSETS + 1))
    for raw in rows:
        item = dict(raw)
        if not add(item["asset_id"]):
            continue
        decisions[item["asset_id"]] = item
        proofs[item["asset_id"]].add(edge({
            "from_id": company_id, "to_id": item["asset_id"],
            "relation": "company_asset_" + item["status"], "source_url": item["source_url"],
            "observed_at": item["updated_at"], "confidence": 1.0, "evidence": item["evidence"],
        }))
    rows = conn.execute("""SELECT * FROM edges WHERE from_id=? AND relation='official_website'
     AND to_id LIKE 'domain:%' ORDER BY to_id,source_url LIMIT ?""", (company_id, MAX_EDGES + 1))
    for index, raw in enumerate(rows):
        if index >= MAX_EDGES:
            truncated = True
            break
        item = dict(raw)
        if add(item["to_id"]):
            official[item["to_id"]].append(item)
            proofs[item["to_id"]].add(edge(item))

    # A primary domain establishes a namespace, not ownership of every hostname.
    # Keep discovered descendants visible as candidates without adding their
    # observations or alerts to company risk. A more-specific company anchor
    # fences its entire subtree from the broader namespace.
    anchor_decision = decisions.get(primary_asset)
    anchor_resolution = resolve(conn, {"domain": primary_domain, "company_id": company_id}) if primary_asset else {}
    expand_namespace = primary_asset and anchor_resolution.get("organization_id") == company_id and (not anchor_decision or
        anchor_decision["status"] == "confirmed" and anchor_decision["role"] == "owned")
    if expand_namespace:
        rows = conn.execute("""SELECT e.id FROM entities e WHERE e.id LIKE ?
         AND NOT EXISTS (SELECT 1 FROM company_profiles p WHERE p.company_id!=?
          AND p.primary_domain!='' AND length(p.primary_domain)>length(?)
          AND p.primary_domain LIKE ? AND (e.id='domain:'||p.primary_domain OR e.id LIKE 'domain:%.'||p.primary_domain))
         ORDER BY e.id LIMIT ?""", ("domain:%." + primary_domain, company_id, primary_domain,
                                     "%." + primary_domain, MAX_ASSETS + 1))
        for raw in rows:
            asset_id = raw["id"]
            if not add(asset_id):
                continue
            identity = edge({"from_id": primary_asset, "to_id": asset_id, "relation": "namespace_candidate",
                             "source_url": profile.get("primary_domain_source_url", ""),
                             "observed_at": profile["updated_at"], "confidence": 0.5,
                             "evidence": "Known hostname within the primary domain; ownership is unconfirmed"})
            namespace_edges[asset_id] = identity
            proofs[asset_id].update(proofs[primary_asset] | {identity})

    # Load redirects at most once per domain, four hops from direct evidence.
    # Candidate paths can be inspected, but cannot grant included status.
    frontier, visited, redirects = set(decisions) | set(official), set(), []
    for _ in range(MAX_HOPS):
        frontier = {asset_id for asset_id in frontier - visited
                    if decisions.get(asset_id, {}).get("status") != "rejected"
                    and decisions.get(asset_id, {}).get("role") != "service"}
        if not frontier:
            break
        visited.update(frontier)
        slots = ",".join("?" for _ in frontier)
        remaining = MAX_EDGES - len(redirects)
        rows = conn.execute("SELECT * FROM edges WHERE relation='redirects_to' AND from_id IN (" + slots + ") ORDER BY from_id,to_id,source_url LIMIT ?", (*sorted(frontier), remaining + 1))
        following = set()
        for index, raw in enumerate(rows):
            if index >= remaining:
                truncated = True
                break
            item = dict(raw)
            if add(item["to_id"]):
                identity = edge(item)
                redirects.append((item, identity))
                following.add(item["to_id"])
        frontier = following

    # A depth limit is also incomplete evidence when an outgoing redirect
    # remains unread, including a cycle closing back onto a known domain.
    boundary = {asset_id for asset_id in frontier - visited
                if decisions.get(asset_id, {}).get("status") != "rejected"
                and decisions.get(asset_id, {}).get("role") != "service"}
    if boundary:
        slots = ",".join("?" for _ in boundary)
        omitted = conn.execute("SELECT 1 FROM edges WHERE relation='redirects_to' AND from_id IN (" + slots
                               + ") AND to_id LIKE 'domain:%' LIMIT 1", sorted(boundary)).fetchone()
        truncated = truncated or omitted is not None

    # Keep conflicting decisions visible, but never let an ambiguous owner
    # seed inclusion or propagate inclusion through a www/apex redirect.
    conflicts = {}
    for asset_id in nodes:
        resolution = resolve(conn, {"domain": asset_id.removeprefix("domain:"), "company_id": company_id})
        if resolution["status"] == "conflict" or resolution.get("organization_id") not in (None, company_id):
            conflicts[asset_id] = resolution
    included = {}
    for asset_id in nodes:
        if asset_id in conflicts:
            continue
        decision = decisions.get(asset_id)
        if decision:
            if decision["status"] == "confirmed" and decision["role"] == "owned":
                included[asset_id] = 1.0
        elif official[asset_id]:
            included[asset_id] = max(confidence(item["confidence"]) for item in official[asset_id])

    # Propagate complete supporting paths and inclusion separately. Only a
    # narrow www/apex redirect from an already included asset can auto-include.
    reachable_confidence = {asset_id: included.get(asset_id, 1.0 if asset_id in decisions else max((confidence(item["confidence"]) for item in official[asset_id]), default=0.0)) for asset_id in nodes if asset_id in decisions or official[asset_id]}
    paths = {asset_id: [max(proofs[asset_id], key=lambda index: (confidence(edges[index]["confidence"]), -index))]
             for asset_id in reachable_confidence}
    for asset_id, identity in namespace_edges.items():
        if asset_id not in reachable_confidence:
            reachable_confidence[asset_id] = 0.5
            paths[asset_id] = paths.get(primary_asset, []) + [identity]
    included_paths = {asset_id: paths[asset_id] for asset_id in included}
    for _ in range(MAX_HOPS):
        next_proofs = {asset_id: set(proof) for asset_id, proof in proofs.items()}
        next_included = dict(included)
        next_confidence = dict(reachable_confidence)
        next_paths, next_included_paths = dict(paths), dict(included_paths)
        for item, identity in redirects:
            source, target = item["from_id"], item["to_id"]
            if source not in reachable_confidence:
                continue
            path = paths[source] + [identity]
            if target not in next_paths or len(path) < len(next_paths[target]):
                next_paths[target] = path
            if source in included and target not in decisions and target not in conflicts and www_equivalent(source, target):
                next_included[target] = max(next_included.get(target, 0.0), min(included[source], confidence(item["confidence"])))
                path = included_paths[source] + [identity]
                if target not in next_included_paths or len(path) < len(next_included_paths[target]):
                    next_included_paths[target] = path
            proof = proofs[source] | {identity}
            merged = next_proofs.setdefault(target, set()) | proof
            next_proofs[target] = bounded_proof(merged, target, next_included_paths.get(target, next_paths[target]))
            next_confidence[target] = max(next_confidence.get(target, 0.0), min(reachable_confidence[source], confidence(item["confidence"])))
        proofs, included, reachable_confidence = next_proofs, next_included, next_confidence
        paths, included_paths = next_paths, next_included_paths

    if not nodes:
        return [], truncated
    slots = ",".join("?" for _ in nodes)
    identities = sorted(nodes)
    entities = {row["id"]: dict(row) for row in conn.execute("SELECT id,name FROM entities WHERE id IN (" + slots + ")", identities)}
    observations = {row[0]: row[1] for row in conn.execute("SELECT asset_id,count(*) FROM observations WHERE asset_id IN (" + slots + ") GROUP BY asset_id", identities)}
    warnings = {row[0]: row[1] for row in conn.execute("SELECT asset_id,count(*) FROM alerts WHERE asset_id IN (" + slots + ") GROUP BY asset_id", identities)}
    assets = []
    for asset_id in identities:
        decision = decisions.get(asset_id)
        if decision:
            status, role = decision["status"], decision["role"]
            reasons = [{"confirmed": "Manual confirmation", "candidate": "Manual candidate", "rejected": "Manual rejection"}[status] + (": " + decision["evidence"] if decision["evidence"] else "")]
            if role == "service":
                reasons.append("Service dependency; excluded from company-owned infrastructure")
        elif asset_id == primary_asset:
            status, role = "primary", "owned"
            reasons = ["Explicit primary-domain identity anchor"]
        elif official[asset_id]:
            status, role = "official", "website"
            reasons = ["Official website evidence; legal ownership is not established"]
        elif asset_id in included:
            status, role = "redirect", "website"
            reasons = ["Observed www/apex-equivalent redirect from an included website"]
        elif asset_id in namespace_edges:
            status, role = "candidate", "website"
            reasons = ["Known hostname within the primary domain; ownership requires confirmation"]
        else:
            status, role = "candidate", "website"
            reasons = ["Observed redirect destination; company association needs confirmation"]
        if asset_id in conflicts and (not decision or decision["status"] == "confirmed" and decision["role"] == "owned"):
            status = "conflict"
            reasons.append("Excluded from company risk: " + conflicts[asset_id]["reason"])
        proof = sorted(bounded_proof(proofs[asset_id], asset_id, included_paths.get(asset_id, paths.get(asset_id, []))))
        assets.append({
            "id": asset_id, "name": entities.get(asset_id, {}).get("name", asset_id.removeprefix("domain:")),
            "status": status, "role": role, "included": asset_id in included,
            "decision_status": decision["status"] if decision else None,
            "confidence": included.get(asset_id, reachable_confidence.get(asset_id, 0.0)),
            "reasons": reasons, "evidence": [edges[index] for index in proof[:MAX_PROOF]],
            "observation_count": observations.get(asset_id, 0), "warning_count": warnings.get(asset_id, 0),
        })
    return assets, truncated
