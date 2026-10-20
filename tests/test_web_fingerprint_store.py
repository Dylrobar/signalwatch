import copy
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from signalwatch.store import Store
from signalwatch.technographic_store import SCHEMA, document_input
from signalwatch.technographic_verifier import verify_batch


def finding(product="nginx", status="http_detected", **changes):
    return {"vendor": "f5", "vendor_name": "F5", "product": product, "product_name": product,
            "category": "Web server", "part": "a", "version": "1.24.0",
            "cpe": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*", "status": status,
            "confidence": 0.95, "evidence_snippet": "Server: nginx/1.24.0",
            "method": "http_fingerprint_v1", "evidence_type": "header", **changes}


def page(url="https://acme.test/", findings=None, **context):
    host = url.split("/")[2]
    return {"id": "web_fingerprint:" + hashlib.sha256(url.encode()).hexdigest(), "kind": "web_fingerprint",
            "name": "HTTP technology evidence", "source_url": url,
            "metadata": {"provider": "http_fingerprint", "company_context": {"domain": host, **context},
                         "fingerprints": [finding()] if findings is None else findings}}


class WebFingerprintStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.ingest({"entities": [{"id": "company:acme", "kind": "company", "name": "Acme"},
                                        {"id": "domain:acme.test", "kind": "domain", "value": "acme.test"}],
                           "edges": [{"from_id": "company:acme", "to_id": "domain:acme.test", "relation": "official_website"}]})

    def evidence(self):
        return self.store.detail("company:acme")["technographics"]

    def test_company_evidence_preserves_vectors_versions_cpe_and_source_without_virtual_observations(self):
        findings = [finding(),
                    finding("react", "implied_dependency", vendor="facebook", version="", cpe=None,
                            evidence_type="implied", implied_by=["Next.js"], evidence_snippet="Dependency implied by Next.js"),
                    finding("okta", "csp_integration", vendor="okta", version="", cpe=None, evidence_type="csp",
                            csp_directive="connect-src", matched_host="*.okta.com", evidence_snippet="connect-src *.okta.com")]
        source = page(findings=findings)
        self.store.ingest({"entities": [source]})
        evidence = self.evidence()
        self.assertEqual((evidence["documents"], evidence["total"]), (1, 3))
        by_product = {row["product"]: row for row in evidence["fingerprints"]}
        self.assertEqual(by_product["nginx"]["version"], "1.24.0")
        self.assertEqual(by_product["nginx"]["cpe"], findings[0]["cpe"])
        self.assertEqual(by_product["nginx"]["evidence_type"], "header")
        self.assertEqual(by_product["react"]["implied_by"], ["Next.js"])
        self.assertEqual(by_product["okta"]["csp_directive"], "connect-src")
        self.assertEqual(by_product["okta"]["matched_host"], "*.okta.com")
        for row in evidence["fingerprints"]:
            self.assertEqual(row["source_url"], "https://acme.test/")
            self.assertEqual(row["source_type"], "http_fingerprint")
            self.assertEqual(row["asset_id"], "domain:acme.test")
        self.assertEqual(self.store.detail("company:acme")["observations"], [])
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM observations").fetchone()[0], 0)

    def test_candidate_host_evidence_survives_then_projects_only_after_confirmation(self):
        source = page("https://portal.acme.test/")
        self.store.ingest({"entities": [{"id": "domain:portal.acme.test", "kind": "domain", "value": "portal.acme.test"}, source],
                           "edges": [{"from_id": "domain:acme.test", "to_id": "domain:portal.acme.test", "relation": "redirects_to"},
                                     {"from_id": "domain:portal.acme.test", "to_id": source["id"], "relation": "has_public_evidence"}]})
        self.assertEqual(self.evidence()["total"], 0)
        self.assertTrue(any(edge["to_id"] == source["id"] for edge in self.store.detail("domain:portal.acme.test")["relationships"]))
        for status, expected in (("confirmed", 1), ("rejected", 0), ("confirmed", 1)):
            with self.subTest(status=status):
                result = self.store.set_company_asset("company:acme", "https://portal.acme.test", status=status,
                                                      evidence="Reviewed asset", source_url="https://acme.test/about")
                self.assertEqual(result["technographics"]["total"], expected)
                self.assertTrue(any(edge["from_id"] == "domain:portal.acme.test" and edge["to_id"] == source["id"]
                                    for edge in self.store.detail(source["id"])["relationships"]))

    def test_origin_company_context_cannot_attribute_unowned_redirect_destination(self):
        source = page("https://unrelated.test/", domain="acme.test", company_id="company:acme")
        counts = self.store.ingest({"entities": [source]})
        self.assertEqual(counts["technographic_unattributed"], 1)
        self.assertEqual(self.evidence()["total"], 0)

    def test_ambiguous_company_ownership_keeps_only_host_evidence(self):
        source = page()
        self.store.ingest({"entities": [source]})
        self.assertEqual(self.evidence()["total"], 1)
        self.store.ingest({"entities": [{"id": "company:other", "kind": "company", "name": "Other"}, source],
                           "edges": [{"from_id": "company:other", "to_id": "domain:acme.test", "relation": "official_website"},
                                     {"from_id": "domain:acme.test", "to_id": source["id"], "relation": "has_public_evidence"}]})
        self.assertEqual(self.evidence()["total"], 0)
        self.assertEqual(self.store.detail("company:other")["technographics"]["total"], 0)
        self.assertTrue(any(edge["from_id"] == "domain:acme.test" and edge["to_id"] == source["id"]
                            for edge in self.store.detail(source["id"])["relationships"]))

    def test_www_attribution_requires_the_actual_included_redirect_asset(self):
        source = page("https://www.acme.test/")
        self.store.ingest({"entities": [source]})
        self.assertEqual(self.evidence()["total"], 0)
        self.store.ingest({"entities": [{"id": "domain:www.acme.test", "kind": "domain", "value": "www.acme.test"}, source],
                           "edges": [{"from_id": "domain:acme.test", "to_id": "domain:www.acme.test", "relation": "redirects_to"}]})
        self.assertEqual(self.evidence()["total"], 1)

    def test_changed_and_empty_response_withdraw_stale_active_fingerprints(self):
        source = page()
        self.store.ingest({"entities": [source]})
        with patch("signalwatch.technographics.extract", side_effect=AssertionError("HTTP evidence is already classified")):
            self.store.ingest({"entities": [page(findings=[finding(version="1.26.0", evidence_snippet="Server: nginx/1.26.0")])]})
        self.assertEqual([row["version"] for row in self.evidence()["fingerprints"]], ["1.26.0"])
        self.store.ingest({"entities": [page(findings=[])]})
        self.assertEqual(self.evidence()["total"], 0)
        self.assertFalse(any(edge["relation"].startswith("technology_") for edge in self.store.detail(source["id"])["relationships"]))
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM technographic_documents").fetchone()[0], 3)

    def test_same_evidence_on_different_owned_hosts_keeps_both_provenances(self):
        self.store.set_company_asset("company:acme", "https://portal.acme.test", evidence="Reviewed asset", source_url="https://acme.test/about")
        self.store.ingest({"entities": [page(), page("https://portal.acme.test/")]})
        evidence = self.evidence()
        self.assertEqual((evidence["documents"], evidence["total"]), (2, 2))
        self.assertEqual({row["source_url"] for row in evidence["fingerprints"]}, {"https://acme.test/", "https://portal.acme.test/"})
        self.store.ingest({"entities": [page()]})
        self.assertEqual(self.evidence()["total"], 2)

    def test_catalog_evidence_method_and_empty_cpe_survive_storage(self):
        self.store.ingest({"entities": [page(findings=[finding("Catalog product", method="projectdiscovery_wappalyzer")])]})
        row = self.evidence()["fingerprints"][0]
        self.assertEqual(row["method"], "projectdiscovery_wappalyzer")
        self.assertIsNone(row["cpe"])
        self.assertEqual(self.store.stats()["observations"], 0)

    def test_imported_indirect_evidence_cannot_assert_versions_or_cpe(self):
        self.store.ingest({"entities": [page(findings=[finding(status="implied_dependency"), finding(status="csp_integration")])]})
        rows = self.evidence()["fingerprints"]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["version"] == "" and row["cpe"] is None for row in rows))

    def test_duplicate_findings_and_catalog_overlap_do_not_collide(self):
        self.store.ingest({"entities": [page(findings=[finding(), finding(), finding(confidence=0.98),
                                                       finding(method="projectdiscovery_wappalyzer")])]})
        rows = self.evidence()["fingerprints"]
        self.assertEqual(len(rows), 2)
        methods = {row["method"]: row for row in rows}
        self.assertEqual(methods["http_fingerprint_v1"]["confidence"], 0.98)
        self.assertIsNone(methods["projectdiscovery_wappalyzer"]["cpe"])

    def test_exact_owned_asset_is_not_lost_to_bounded_asset_graph(self):
        self.store.set_company_asset("company:acme", "https://portal.acme.test", evidence="Reviewed asset", source_url="https://acme.test/about")
        with patch("signalwatch.companies.company_assets", return_value=([], True)):
            self.store.ingest({"entities": [page("https://portal.acme.test/"), page()]})
        self.assertEqual(self.evidence()["total"], 2)

    def test_structured_http_findings_never_enter_text_llm_verification(self):
        config = {"provider_settings": {"technographics": {"verifier_url": "https://models.example/chat/completions", "verifier_model": "configured-model"}},
                  "provider_credentials": {"technographics": {"api_key": "synthetic-key"}}}
        batch = {"entities": [page()]}
        original = copy.deepcopy(batch)
        store = Mock()
        with patch("signalwatch.technographic_verifier._chat") as chat:
            verify_batch(batch, config, store)
        chat.assert_not_called()
        store.technographic_document_seen.assert_not_called()
        self.assertEqual(batch, original)

    def test_legacy_fingerprint_schema_is_migrated_without_losing_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.db"
            with sqlite3.connect(path) as conn:
                conn.executescript(SCHEMA.replace(",\n evidence_details TEXT NOT NULL DEFAULT '{}'", ""))
                conn.execute("INSERT INTO tech_fingerprints VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                             ("old", "company:old", "document:old", "vendor", "product", "Vendor", "Product", "category", "a", "", None,
                              "asserted_use", 0.8, "retained text evidence", "text-method", "2026-10-01", "2026-10-01"))
            migrated = Store(path)
            with migrated.connection() as conn:
                row = conn.execute("SELECT evidence_snippet,evidence_details FROM tech_fingerprints WHERE id='old'").fetchone()
                self.assertEqual(tuple(row), ("retained text evidence", "{}"))
            reopened = Store(path)
            with reopened.connection() as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM tech_fingerprints").fetchone()[0], 1)

    def test_invalid_structured_findings_fail_without_replacing_retained_evidence(self):
        self.store.ingest({"entities": [page()]})
        for value in ([finding(confidence=float("nan"))], [finding(status="asserted_use")], "not a list"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                document_input(page(findings=value))
        self.assertEqual(self.evidence()["total"], 1)


if __name__ == "__main__":
    unittest.main()
