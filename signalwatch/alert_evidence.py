"""Bounded, company-scoped evidence links for a potential exposure warning."""

from collections import defaultdict
from urllib.parse import urlsplit

from .matching import normalize

LIMIT = 20


class EvidenceIndex:
    def __init__(self, conn):
        self.conn = conn
        self.inventory = {}
        self.documents = {}
        self.context = {}
        self.groups = defaultdict(dict)

    def observations(self, asset_id):
        if asset_id not in self.inventory:
            self.inventory[asset_id] = [dict(row) for row in self.conn.execute(
                "SELECT * FROM observations WHERE asset_id=? ORDER BY observed_at DESC,id", (asset_id,))]
        return self.inventory[asset_id]

    def document(self, asset_id, document_id):
        key = (asset_id, document_id)
        if key not in self.documents:
            row = self.conn.execute("SELECT content_hash FROM technographic_documents WHERE id=? AND organization_id=?",
                                    (document_id, asset_id)).fetchone()
            self.documents[key] = row[0] if row else ""
        return self.documents[key]

    def add(self, row, matches, state, reason):
        document_id = row["origin"].removeprefix("technographic:") if row["origin"].startswith("technographic:") else ""
        item = {"id": row["id"], "source_url": row["source_url"], "evidence": row["evidence"],
                "observed_at": row["observed_at"], "version": row["version"],
                "status": state, "kind": ("public_text_assertion" if document_id else "http_observation"
                                          if row["origin"] == "web" else "sbom_inventory"
                                          if row["origin"].startswith("sbom:") else "observation"),
                "reason": reason, "vendor": row["vendor_name"], "product": row["product_name"]}
        if document_id:
            item["document_id"] = document_id
        # Each observation can join several advisory documents and ranges. A
        # failed alternative range is not contradictory when another matches.
        group = self.groups[(row["asset_id"], row["canonical_id"])]
        key = (row["id"], row["vendor"], row["product"])
        old = group.get(key)
        if old is None or matches and not old[0]:
            group[key] = (matches, item)

    def contradictions(self, asset_id, vendor, product, part):
        if asset_id not in self.context:
            self.context[asset_id] = [dict(row) for row in self.conn.execute("""SELECT f.*,
                (SELECT s.source_url FROM technographic_sources s JOIN evidence_resolution r
                 ON r.source_entity_id=s.source_entity_id AND r.organization_id=s.organization_id
                 WHERE s.document_id=f.document_id AND s.organization_id=f.organization_id AND r.status='resolved'
                 ORDER BY s.last_seen_at DESC,s.source_url LIMIT 1) AS source_url
                FROM tech_fingerprints f WHERE f.organization_id=? AND f.status IN ('negated','historical')
                AND EXISTS (SELECT 1 FROM technographic_sources s JOIN evidence_resolution r
                 ON r.source_entity_id=s.source_entity_id AND r.organization_id=s.organization_id
                 WHERE s.document_id=f.document_id AND s.organization_id=f.organization_id AND r.status='resolved')
                ORDER BY f.last_seen_at DESC,f.id""", (asset_id,))]
        result = []
        for row in self.context[asset_id]:
            if (normalize(row["vendor"]), normalize(row["product"]), row["part"]) != (vendor, product, part):
                continue
            result.append({"id": row["id"], "source_url": row["source_url"] or "", "evidence": row["evidence_snippet"],
                           "observed_at": row["last_seen_at"], "version": row["version"], "status": row["status"],
                           "kind": "public_text_context", "document_id": row["document_id"],
                           "vendor": row["vendor_name"], "product": row["product_name"],
                           "reason": "Public text describes historical or explicitly denied use; it does not prove a current deployment is absent."})
        return result

    def _dedup(self, asset_id, items):
        result, seen = [], set()
        for item in sorted(items, key=lambda item: (item["observed_at"] or "", item["id"]), reverse=True):
            document_id = item.get("document_id", "")
            content_hash = self.document(asset_id, document_id) if document_id else ""
            key = (content_hash or document_id or item["source_url"] or item["id"],
                   item.get("product", ""), item["version"], item["status"])
            if key not in seen:
                seen.add(key)
                result.append(item)
        return result

    def assessment(self, key, record):
        asset_id, _ = key
        grouped = list(self.groups[key].values())
        supporting = self._dedup(asset_id, [item for matches, item in grouped if matches])
        contradicting = self._dedup(asset_id, [item for matches, item in grouped if not matches] +
                                   self.contradictions(asset_id, normalize(record["vendor_identity"]),
                                                       normalize(record["product_identity"]), record["part_identity"]))
        sources = set()
        for item in supporting:
            document_id = item.get("document_id", "")
            if document_id:
                sources.add("document:" + (self.document(asset_id, document_id) or document_id))
            else:
                try:
                    host = urlsplit(item["source_url"]).hostname
                except ValueError:
                    host = None
                sources.add("origin:" + (host or item["source_url"] or item["id"]))
        factors = ["Exact normalized vendor, product and CPE part are required.",
                   "Confidence is the strongest retained observation; corroboration does not inflate it.",
                   "Source count deduplicates syndicated document content and HTTP origins; it is not a probability of independence.",
                   "Version assessment: " + record["version_state"] + "."]
        if any(item["kind"] == "public_text_assertion" for item in supporting):
            factors.append("Public text asserts organization use; host deployment and present version still require verification.")
        if contradicting:
            factors.append("Contradictory observations or historical/negated statements are retained for review; timestamps may describe different deployments.")
        return {"supporting": supporting[:LIMIT], "contradicting": contradicting[:LIMIT],
                "independent_sources": len(sources), "confidence_factors": factors,
                "truncated": len(supporting) > LIMIT or len(contradicting) > LIMIT}
