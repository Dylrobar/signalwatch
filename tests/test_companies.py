import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.store import SCHEMA, Store


class CompanyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "companies.db"
        self.store = Store(self.path)
        self.company_id = "company:wikidata:Q123"
        self.store.ingest({"entities": [{"id": self.company_id, "kind": "company", "name": "Source company", "value": "Q123",
                                          "metadata": {"wikidata": "Q123"}, "source_url": "https://www.wikidata.org/entity/Q123"}]})

    def link(self, source, target, relation="redirects_to", source_url=None, confidence=1.0):
        self.store.ingest({"edges": [{"from_id": source, "to_id": target, "relation": relation,
                                       "source_url": source_url or "https://evidence.example/" + relation,
                                       "confidence": confidence}]})

    def official(self, host="example.com", source_url=None):
        self.link(self.company_id, "domain:" + host, "official_website", source_url)

    def assets(self, detail=None):
        return {asset["id"]: asset for asset in (detail or self.store.detail(self.company_id))["company_profile"]["assets"]}

    def decide(self, host, status="confirmed", role="owned"):
        return self.store.set_company_asset(self.company_id, "https://" + host + "/", status, role,
                                            "Reviewed company inventory", "https://evidence.example/inventory")

    def observation(self, host):
        return {"asset_id": "domain:" + host, "vendor": "acme", "product": "gateway", "version": "1.0",
                "source_url": "https://" + host + "/", "evidence": "Visible product version"}

    def test_profile_search_and_user_data_survive_collector_ingest_and_restart(self):
        result = self.store.save_company_profile(self.company_id, "Preferred company", legal_name="Registered Holdings LLC",
                                                 aliases=["Old Name", "old name", ""], brands=["Blue Widget"],
                                                 notes="A user note", source_url="https://evidence.example/legal")
        profile = result["company_profile"]
        self.assertEqual(profile["aliases"], ["Old Name"])
        self.assertEqual(profile["brands"], ["Blue Widget"])
        self.assertEqual(result["name"], "Preferred company")
        for query in ("Registered", "Old Name", "Blue Wid", "Preferred"):
            self.assertEqual(self.store.search(query, "company")["items"][0]["id"], self.company_id)
        self.store.ingest({"entities": [{"id": self.company_id, "kind": "company", "name": "New source label", "value": "Q123",
                                          "metadata": {"wikidata": "Q123", "new_source_field": True}}]})
        reopened = Store(self.path)
        detail = reopened.detail(self.company_id)
        self.assertEqual(detail["company_profile"], profile)
        self.assertEqual(detail["name"], "Preferred company")
        self.assertTrue(detail["metadata"]["new_source_field"])
        self.assertEqual(reopened.search("Blue Widget")["items"][0]["name"], "Preferred company")
        # Updating the profile also updates its independent search index.
        reopened.save_company_profile(self.company_id, "Preferred company", aliases=["Fresh name"])
        self.assertEqual(reopened.search("Blue Widget")["total"], 0)
        self.assertEqual(reopened.search("Fresh name")["total"], 1)
        self.assertEqual(reopened.search("New source")["total"], 1)

    def test_manual_companies_parent_validation_and_no_subsidiary_rollup(self):
        parent = self.store.save_company_profile(name="Parent firm")
        parent_id = parent["id"]
        child = self.store.save_company_profile(self.company_id, "Child firm", parent_company_id=parent_id)
        self.assertTrue(parent_id.startswith("company:manual:"))
        self.assertEqual(child["company_profile"]["parent_company"]["name"], "Parent firm")
        self.assertEqual(self.store.detail(parent_id)["company_profile"]["subsidiaries"][0]["id"], self.company_id)
        self.official()
        self.assertEqual(self.store.detail(parent_id)["company_profile"]["assets"], [])
        with self.assertRaisesRegex(ValueError, "cycle"):
            self.store.save_company_profile(parent_id, "Parent firm", parent_company_id=self.company_id)
        with self.assertRaisesRegex(ValueError, "cycle"):
            self.store.save_company_profile(parent_id, "Parent firm", parent_company_id=parent_id)
        with self.assertRaises(LookupError):
            self.store.save_company_profile(self.company_id, "Child firm", parent_company_id="company:missing")
        self.store.ingest({"entities": [{"id": "domain:other.example", "kind": "domain", "name": "Other"}]})
        with self.assertRaisesRegex(ValueError, "not a company"):
            self.store.save_company_profile(self.company_id, "Child firm", parent_company_id="domain:other.example")
        self.assertEqual(self.store.detail(self.company_id)["company_profile"]["parent_company_id"], parent_id)

    def test_www_redirect_rolls_up_observations_warnings_advisories_and_articles(self):
        self.official()
        self.link("domain:example.com", "domain:www.example.com", confidence=0.8)
        self.store.ingest({"observations": [self.observation("www.example.com")],
                           "advisories": [{"id": "CVE-2026-12345", "title": "Acme gateway issue", "source": "NVD",
                                            "affected": [{"vendor": "acme", "product": "gateway", "version": "1.0"}]}],
                           "articles": [{"url": "https://news.example/story", "title": "Acme gateway security update", "cves": ["CVE-2026-12345"]}]})
        self.store.reconcile()
        detail = self.store.detail(self.company_id)
        assets = self.assets(detail)
        self.assertEqual(assets["domain:example.com"]["status"], "official")
        www = assets["domain:www.example.com"]
        self.assertEqual((www["status"], www["role"], www["included"]), ("redirect", "website", True))
        self.assertEqual(www["confidence"], 0.8)
        self.assertEqual({edge["relation"] for edge in www["evidence"]}, {"official_website", "redirects_to"})
        self.assertEqual((www["observation_count"], www["warning_count"]), (1, 1))
        self.assertEqual(len(detail["observations"]), 1)
        self.assertEqual(len(detail["alerts"]), 1)
        self.assertEqual(len(detail["advisories"]), 1)
        self.assertEqual(len(detail["related_articles"]), 1)

    def test_external_redirect_is_candidate_until_confirmed_and_service_is_excluded(self):
        self.official()
        self.link("domain:example.com", "domain:hosted.vendor.example")
        self.link("domain:hosted.vendor.example", "domain:www.hosted.vendor.example")
        self.store.ingest({"observations": [self.observation("hosted.vendor.example"), self.observation("www.hosted.vendor.example")]})
        before = self.store.detail(self.company_id)
        self.assertEqual(before["observations"], [])
        self.assertFalse(self.assets(before)["domain:hosted.vendor.example"]["included"])
        self.assertFalse(self.assets(before)["domain:www.hosted.vendor.example"]["included"])
        confirmed = self.decide("hosted.vendor.example")
        self.assertTrue(self.assets(confirmed)["domain:hosted.vendor.example"]["included"])
        self.assertTrue(self.assets(confirmed)["domain:www.hosted.vendor.example"]["included"])
        self.assertEqual(len(confirmed["observations"]), 2)
        service = self.decide("hosted.vendor.example", role="service")
        self.assertFalse(self.assets(service)["domain:hosted.vendor.example"]["included"])
        self.assertNotIn("domain:www.hosted.vendor.example", self.assets(service))
        self.assertEqual(service["observations"], [])

    def test_rejection_wins_survives_source_refresh_and_blocks_redirect_traversal(self):
        self.official()
        self.link("domain:example.com", "domain:www.example.com")
        self.link("domain:www.example.com", "domain:external.example")
        self.decide("www.example.com", "rejected")
        self.official("www.example.com", "https://www.wikidata.org/refreshed")
        assets = self.assets(Store(self.path).detail(self.company_id))
        self.assertEqual(assets["domain:www.example.com"]["status"], "rejected")
        self.assertFalse(assets["domain:www.example.com"]["included"])
        self.assertNotIn("domain:external.example", assets)
        self.assertIn("Reviewed company inventory", " ".join(assets["domain:www.example.com"]["reasons"]))
        restored = self.store.set_company_asset(self.company_id, "https://www.example.com/", "automatic")
        self.assertTrue(self.assets(restored)["domain:www.example.com"]["included"])
        self.assertIn("domain:external.example", self.assets(restored))

    def test_manual_candidate_excludes_official_asset_and_manual_only_asset_normalizes_idna(self):
        self.official()
        self.decide("example.com", "candidate")
        self.assertFalse(self.assets()["domain:example.com"]["included"])
        result = self.decide("BÜCHER.Example.:8443/path")
        asset = self.assets(result)["domain:xn--bcher-kva.example"]
        self.assertTrue(asset["included"])
        self.assertEqual(asset["evidence"][0]["evidence"], "Reviewed company inventory")
        self.assertEqual(self.store.stats()["crawl_urls"], 0)
        self.store.set_company_asset(self.company_id, "https://bücher.example/other", "automatic")
        self.assertNotIn("domain:xn--bcher-kva.example", self.assets())

    def test_redirect_cycles_multiple_paths_and_network_edges_do_not_claim_ownership(self):
        self.official("one.example", "https://official.example/one")
        self.official("two.example", "https://official.example/two")
        self.link("domain:one.example", "domain:destination.example", source_url="https://one.example/")
        self.link("domain:two.example", "domain:destination.example", source_url="https://two.example/")
        self.link("domain:destination.example", "domain:one.example")
        self.link("domain:one.example", "domain:shared.example", "resolves_to")
        assets = self.assets()
        self.assertEqual(len(assets), 3)
        destination = assets["domain:destination.example"]
        self.assertFalse(destination["included"])
        self.assertTrue({"https://one.example/", "https://two.example/", "https://official.example/one", "https://official.example/two"}.issubset({edge["source_url"] for edge in destination["evidence"]}))
        self.assertNotIn("domain:shared.example", assets)

    def test_asset_count_and_redirect_depth_are_bounded(self):
        self.official("0.example")
        for number in range(6):
            self.link(f"domain:{number}.example", f"domain:{number + 1}.example")
        detail = self.store.detail(self.company_id)
        self.assertEqual(set(self.assets(detail)), {f"domain:{number}.example" for number in range(5)})
        self.assertTrue(detail["company_profile"]["assets_truncated"])
        with patch("signalwatch.companies.MAX_ASSETS", 3):
            limited = self.store.detail(self.company_id)
        self.assertEqual(len(limited["company_profile"]["assets"]), 3)
        self.assertTrue(limited["company_profile"]["assets_truncated"])

    def test_depth_truncation_includes_omitted_cycle_closure_but_not_loaded_cycles(self):
        self.official("0.example")
        self.link("domain:0.example", "domain:1.example")
        self.link("domain:1.example", "domain:0.example")
        self.assertFalse(self.store.detail(self.company_id)["company_profile"]["assets_truncated"])
        for number in range(1, 4):
            self.link(f"domain:{number}.example", f"domain:{number + 1}.example")
        self.link("domain:4.example", "domain:0.example")
        self.assertTrue(self.store.detail(self.company_id)["company_profile"]["assets_truncated"])

    def test_proof_cap_retains_redirect_steps_before_duplicate_official_sources(self):
        for number in range(65):
            self.official(source_url=f"https://official.example/reference/{number}")
        self.link("domain:example.com", "domain:www.example.com")
        detail = self.store.detail(self.company_id)
        proof = self.assets(detail)["domain:www.example.com"]["evidence"]
        self.assertEqual(len(proof), 64)
        self.assertTrue(any(edge["to_id"] == "domain:www.example.com" and edge["relation"] == "redirects_to" for edge in proof))
        self.assertTrue(any(edge["from_id"] == self.company_id and edge["relation"] == "official_website" for edge in proof))
        self.assertTrue(detail["company_profile"]["assets_truncated"])
        self.assertEqual(len(self.assets(detail)["domain:example.com"]["evidence"]), 64)
        # The cap keeps the intermediate www step and original company source,
        # even after another three hops to a candidate destination.
        previous = "www.example.com"
        for host in ("other.example", "www.other.example", "final.example"):
            self.link("domain:" + previous, "domain:" + host)
            previous = host
        proof = self.assets()["domain:final.example"]["evidence"]
        pairs = {(edge["from_id"], edge["to_id"]) for edge in proof}
        self.assertTrue({(self.company_id, "domain:example.com"),
                         ("domain:example.com", "domain:www.example.com"),
                         ("domain:www.example.com", "domain:other.example"),
                         ("domain:other.example", "domain:www.other.example"),
                         ("domain:www.other.example", "domain:final.example")}.issubset(pairs))

    def test_missing_noncompany_and_invalid_decisions_fail_without_partial_writes(self):
        with self.assertRaises(LookupError):
            self.store.save_company_profile("company:missing", "Missing")
        with self.assertRaises(ValueError):
            self.store.save_company_profile(name=" ")
        with self.assertRaises(ValueError):
            self.store.save_company_profile(name="Invalid", aliases="not-an-array")
        for changes in ({"status": "invalid"}, {"role": "invalid"}, {"evidence": ""}, {"source_url": ""}, {"asset_url": "https://user:pass@example.com/"}):
            arguments = {"company_id": self.company_id, "asset_url": "https://example.com/", "evidence": "Reviewed", "source_url": "https://evidence.example/"}
            arguments.update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.store.set_company_asset(**arguments)
        self.assertEqual(self.store.detail(self.company_id)["company_profile"]["assets"], [])

    def test_proof_cap_keeps_complete_path_when_many_official_roots_converge(self):
        for number in range(65):
            host = f"root{number}.example"
            self.official(host)
            self.link("domain:" + host, "domain:destination.example")
        detail = self.store.detail(self.company_id)
        proof = self.assets(detail)["domain:destination.example"]["evidence"]
        pairs = {(edge["from_id"], edge["to_id"]) for edge in proof}
        self.assertEqual(len(proof), 64)
        self.assertTrue(any((self.company_id, source) in pairs for source, target in pairs if target == "domain:destination.example"))
        self.assertTrue(detail["company_profile"]["assets_truncated"])


class CompanyMigrationTests(unittest.TestCase):
    def test_existing_database_and_entity_search_are_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "old.db"
            with sqlite3.connect(path) as conn:
                conn.executescript(SCHEMA)
                conn.execute("INSERT INTO entities(id,kind,name,value,metadata,confidence,updated_at) VALUES(?,?,?,?,?,?,?)",
                             ("company:existing", "company", "Existing Name", "existing", json.dumps({"keep": True}), 1, "2026-01-01"))
            store = Store(path)
            self.assertEqual(store.search("Existing")["total"], 1)
            detail = store.detail("company:existing")
            self.assertTrue(detail["metadata"]["keep"])
            self.assertEqual(detail["company_profile"]["name"], "Existing Name")
            store.save_company_profile("company:existing", "Saved Name", legal_name="Legal Search Name")
            self.assertEqual(Store(path).search("Legal Search")["total"], 1)


if __name__ == "__main__":
    unittest.main()
