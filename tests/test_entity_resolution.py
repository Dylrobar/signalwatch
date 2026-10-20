import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.entity_resolution import DomainConflict, NAME_CANDIDATE_LIMIT, canonical_domain, normalize_company_name, resolve
from signalwatch.store import Store


class EntityResolutionTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.ingest({"entities": [{"id": "company:a", "kind": "company", "name": "Acme"},
                                         {"id": "company:b", "kind": "company", "name": "Other"}]})

    def anchor(self, company_id="company:a", domain="example.com", **values):
        return self.store.save_company_profile(company_id, "Acme" if company_id == "company:a" else "Other",
                                               primary_domain=domain, primary_domain_evidence="Verified official website",
                                               primary_domain_source_url="https://" + domain + "/about", **values)

    def resolve(self, context=None, **values):
        with self.store.connection() as conn:
            return resolve(conn, context, **values)

    def decide(self, company_id, host, status="confirmed", role="owned"):
        return self.store.set_company_asset(company_id, "https://" + host, status, role,
                                            "Reviewed inventory", "https://evidence.example.com/inventory")

    def test_canonical_domain_uses_offline_private_psl_and_exact_host(self):
        self.assertEqual(canonical_domain("BÜCHER.DE."), "xn--bcher-kva.de")
        self.assertEqual(canonical_domain("WWW.Example.COM"), "www.example.com")
        self.assertEqual(canonical_domain("tenant.github.io"), "tenant.github.io")
        for value in ("com", "co.uk", "github.io", "blogspot.com", "127.0.0.1", "[::1]", "*.example.com",
                      "https://example.com", "name@example.com", "example.com/path", "example.com:443", "foo..com",
                      "example.unknown-suffix", "-name.example.com", True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                canonical_domain(value)

    def test_longest_domain_boundary_and_www_remains_distinct(self):
        self.anchor()
        self.anchor("company:b", "team.example.com")
        for host, owner in (("api.example.com", "company:a"), ("jobs.team.example.com", "company:b"),
                            ("badexample.com", None), ("example.com.attacker.net", None)):
            with self.subTest(host=host):
                self.assertEqual(self.resolve({"domain": host})["organization_id"], owner)
        self.anchor(domain="www.example.com")
        self.assertIsNone(self.resolve({"domain": "example.com"})["organization_id"])
        self.assertEqual(self.resolve({"domain": "www.example.com"})["organization_id"], "company:a")

    def test_explicit_identifier_and_conflicting_source_domains_never_override_anchor(self):
        self.anchor()
        self.anchor("company:b", "example.org")
        for context, url in (({"company_id": "company:b", "domain": "example.com"}, ""),
                             ({"company_id": "company:missing", "domain": "example.com"}, ""),
                             ({"domain": "example.com"}, "https://example.org/about")):
            result = self.resolve(context, source_url=url)
            self.assertEqual(result["status"], "conflict")
            self.assertIsNone(result["organization_id"])
        self.assertEqual(self.resolve({"company_id": "company:a"})["status"], "candidate")
        self.assertEqual(self.resolve({"company_id": "company:missing"})["status"], "conflict")

    def test_manual_primary_exclusion_cannot_be_bypassed_by_a_second_domain(self):
        self.anchor()
        self.anchor("company:b", "example.org")
        self.decide("company:a", "example.com", "rejected")
        self.assertEqual(self.resolve({"domain": "api.example.com"})["method"], "manual_exclusion")
        result = self.resolve({"domain": "example.com"}, source_url="https://example.org/")
        self.assertEqual(result["status"], "conflict")
        self.assertEqual(result["candidates"], ["company:a", "company:b"])
        self.decide("company:a", "api.example.com")
        self.assertEqual(self.resolve({"domain": "api.example.com"})["organization_id"], "company:a")

    def test_manual_competing_claims_are_conflicts_and_retained(self):
        self.anchor()
        self.decide("company:b", "api.example.com")
        self.assertEqual(self.resolve({"domain": "api.example.com"})["status"], "conflict")
        self.decide("company:a", "shared.example.org")
        self.decide("company:b", "shared.example.org")
        result = self.resolve({"domain": "shared.example.org"})
        self.assertEqual((result["status"], result["candidates"]), ("conflict", ["company:a", "company:b"]))
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM company_asset_decisions").fetchone()[0], 3)

    def test_rejected_intermediate_namespace_blocks_descendants_except_exact_confirmation(self):
        self.anchor()
        self.decide("company:a", "api.example.com", "rejected")
        self.assertEqual(self.resolve({"domain": "deep.api.example.com"})["status"], "conflict")
        self.assertEqual(self.resolve({"domain": "other.example.com"})["organization_id"], "company:a")
        self.decide("company:a", "deep.api.example.com")
        self.assertEqual(self.resolve({"domain": "deep.api.example.com"})["organization_id"], "company:a")

    def test_rejected_competitor_disambiguates_same_host_but_cannot_override_separate_blocked_host(self):
        self.store.ingest({"edges": [{"from_id": company_id, "to_id": "domain:shared.test", "relation": "official_website"}
                                      for company_id in ("company:a", "company:b")]})
        self.decide("company:b", "shared.test", "rejected")
        self.assertEqual(self.resolve({"domain": "shared.test"})["organization_id"], "company:a")
        self.anchor("company:b", "example.org")
        self.decide("company:b", "example.org", "rejected")
        self.assertEqual(self.resolve({"domain": "shared.test"}, source_url="https://example.org")["status"], "conflict")

    def test_legacy_official_exact_domain_only_and_manual_denial(self):
        self.store.ingest({"edges": [{"from_id": "company:a", "to_id": "domain:old.test", "relation": "official_website"}]})
        self.assertEqual(self.resolve({"domain": "old.test"})["method"], "legacy_domain")
        self.assertEqual(self.resolve({"domain": "www.old.test"})["organization_id"], "company:a")
        self.assertIsNone(self.resolve({"domain": "api.old.test"})["organization_id"])
        self.decide("company:a", "old.test", role="service")
        self.assertEqual(self.resolve({"domain": "www.old.test"})["status"], "conflict")

    def test_weak_names_unicode_legal_suffixes_and_collisions_are_candidates(self):
        self.assertEqual(normalize_company_name("ＡＣＭＥ, L.L.C."), "acme")
        self.anchor(aliases=["Blue—Sky, Inc.", "blue sky llc"])
        self.anchor("company:b", "example.org", aliases=["BLUE SKY"])
        self.assertEqual(self.store.detail("company:a")["company_profile"]["aliases"], ["Blue—Sky, Inc."])
        for context, text in (({"name": "Blue Sky Corporation"}, ""), ({}, "Blue Sky announced a merger.")):
            result = self.resolve(context, text=text)
            self.assertEqual((result["status"], result["candidates"]), ("candidate", ["company:a", "company:b"]))
            self.assertIsNone(result["organization_id"])
        self.assertEqual(self.resolve(text="The Blue Skywalker software is available.")["status"], "unattributed")

    def test_normalized_index_handles_unicode_and_keeps_collector_profile_names_independent(self):
        self.store.ingest({"entities": [{"id": "company:a", "kind": "company", "name": "ＡＣＭＥ Straße, Inc."}]})
        result = self.resolve({"name": "acme strasse LLC"})
        self.assertEqual((result["status"], result["candidates"]), ("candidate", ["company:a"]))
        self.store.save_company_profile("company:a", "Preferred Name", aliases=["Blue-Sky"], brands=["Straße"])
        self.assertEqual(self.resolve({"name": "ACME STRASSE"})["candidates"], ["company:a"])
        self.assertEqual(self.resolve({"name": "strasse"})["candidates"], ["company:a"])
        self.store.ingest({"entities": [{"id": "company:a", "kind": "company", "name": "New collected label"}]})
        for label in ("Preferred Name", "Blue Sky", "strasse", "New collected label"):
            self.assertEqual(self.resolve({"name": label})["candidates"], ["company:a"])
        self.assertEqual(self.resolve({"name": "ACME STRASSE"})["status"], "unattributed")
        self.store.save_company_profile("company:a", "Preferred Name", aliases=["Replacement"])
        self.assertEqual(self.resolve({"name": "Blue Sky"})["status"], "unattributed")

    def test_common_name_candidate_hydration_is_bounded_and_never_resolves(self):
        def grow(start, end):
            with self.store.connection(write=True) as conn:
                conn.executemany("INSERT INTO entities(id,kind,name,value,updated_at) VALUES(?,'company','Common Name','','2026-01-01')",
                                 [(f"company:load:{number:05}",) for number in range(start, end)])
                conn.executemany("INSERT INTO company_identity_labels(company_id,label) VALUES(?,'common name')",
                                 [(f"company:load:{number:05}",) for number in range(start, end)])

        def measure():
            with self.store.connection() as conn:
                steps = [0]
                def tick():
                    steps[0] += 100
                    return 0
                conn.set_progress_handler(tick, 100)
                result = resolve(conn, {"name": "Common Name Incorporated"}, text="Common Name announced news.")
                conn.set_progress_handler(None, 0)
                return steps[0], result
        grow(0, 1000)
        small_steps, small = measure()
        grow(1000, 10000)
        large_steps, large = measure()
        self.assertEqual(large, small)
        self.assertEqual(large["status"], "candidate")
        self.assertIsNone(large["organization_id"])
        self.assertEqual(len(large["candidates"]), NAME_CANDIDATE_LIMIT)
        self.assertLess(large_steps, 10000)
        self.assertLess(large_steps, small_steps * 2 + 1000)

    def test_bad_or_credentialed_urls_cannot_abort_or_supply_strong_evidence(self):
        self.anchor()
        for url in ("http://[bad", "https://user:secret@example.com/", "https://@example.com", "ftp://example.com",
                    "https://example.com:999999", "https://example.com/\nsecret"):
            with self.subTest(url=url):
                self.assertEqual(self.resolve(source_url=url)["status"], "unattributed")

    def test_duplicate_domain_save_is_atomic_and_proofs_cannot_be_reused(self):
        self.anchor()
        with self.assertRaises(DomainConflict):
            self.anchor("company:b", "EXAMPLE.COM")
        self.assertEqual(self.store.detail("company:b")["name"], "Other")
        self.assertEqual(self.store.detail("company:b")["company_profile"]["primary_domain"], "")
        with self.assertRaises(ValueError):
            self.store.save_company_profile("company:a", "Changed", primary_domain="example.net")
        self.assertEqual(self.store.detail("company:a")["name"], "Acme")
        with self.assertRaises(ValueError):
            self.store.save_company_profile("company:a", "Acme", primary_domain_source_url="https://user@example.com")

    def test_omitted_identity_preserved_and_explicit_clear_keeps_collected_edges(self):
        anchor = {"asn": 64501, "evidence": "Registry match", "source_url": "https://rdap.example.com/autnum/64501"}
        saved = self.anchor(verified_asns=[anchor])["company_profile"]
        self.store.ingest({"edges": [{"from_id": "company:a", "to_id": "domain:legacy.test", "relation": "official_website"}]})
        updated = self.store.save_company_profile("company:a", "Renamed")["company_profile"]
        for key in ("primary_domain", "primary_domain_evidence", "primary_domain_source_url", "verified_asns"):
            self.assertEqual(saved[key], updated[key])
        self.assertEqual(self.resolve({"asn": "AS64501"})["status"], "candidate")
        self.assertIsNone(self.resolve({"asn": 64501})["organization_id"])
        self.store.save_company_profile("company:a", "Renamed", primary_domain="", verified_asns=[])
        with self.store.connection() as conn:
            relations = {row[0] for row in conn.execute("SELECT relation FROM edges WHERE from_id='company:a'")}
            self.assertEqual(relations, {"official_website"})
            self.assertEqual(conn.execute("SELECT count(*) FROM company_asn_anchors").fetchone()[0], 0)
            self.assertIsNotNone(conn.execute("SELECT 1 FROM entities WHERE id='asn:AS64501'").fetchone())

    def test_asn_validation_and_non_company_mutation_guards(self):
        anchor = {"asn": 1, "evidence": "Registry", "source_url": "https://registry.example.com/1"}
        for value in (True, 0, 4294967296, "1", 1.5):
            with self.subTest(asn=value), self.assertRaises(ValueError):
                self.anchor(verified_asns=[{**anchor, "asn": value}])
        self.anchor(verified_asns=[anchor, anchor])
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM company_asn_anchors").fetchone()[0], 1)
        with self.assertRaises(sqlite3.IntegrityError), self.store.connection(write=True) as conn:
            conn.execute("UPDATE entities SET kind='domain' WHERE id='company:a'")
        with self.assertRaises(sqlite3.IntegrityError), self.store.connection(write=True) as conn:
            conn.execute("UPDATE entities SET id='company:replacement' WHERE id='company:a'")
        with self.assertRaises(sqlite3.IntegrityError), self.store.connection(write=True) as conn:
            conn.execute("UPDATE entities SET id=NULL WHERE id='company:a'")

    def test_reprojection_failure_rolls_back_profile_and_graph_anchors(self):
        self.anchor()
        with patch("signalwatch.technographic_store.reproject_company_identity", side_effect=RuntimeError("projection failed")):
            with self.assertRaises(RuntimeError):
                self.anchor(domain="replacement.example.com")
        self.assertEqual(self.store.detail("company:a")["company_profile"]["primary_domain"], "example.com")
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT to_id FROM edges WHERE relation='primary_domain_anchor'").fetchone()[0], "domain:example.com")
            self.assertIsNone(conn.execute("SELECT 1 FROM entities WHERE id='domain:replacement.example.com'").fetchone())

    def test_additive_migration_preserves_existing_profile_and_decisions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "legacy.db"
            store = Store(path)
            item = store.save_company_profile(name="Legacy", aliases=["Former Name"])
            store.set_company_asset(item["id"], "https://legacy.test", "candidate", "owned", "Unconfirmed", "https://evidence.test")
            with store.connection(write=True) as conn:
                conn.execute("DROP INDEX company_primary_domain")
                for column in ("primary_domain", "primary_domain_evidence", "primary_domain_source_url"):
                    conn.execute("ALTER TABLE company_profiles DROP COLUMN " + column)
                conn.execute("DELETE FROM company_identity_migrations")
                conn.execute("DELETE FROM company_identity_labels")
            reopened = Store(path)
            profile = reopened.detail(item["id"])["company_profile"]
            self.assertEqual((profile["aliases"], profile["primary_domain"], profile["verified_asns"]), (["Former Name"], "", []))
            self.assertEqual((profile["assets"][0]["status"], profile["assets"][0]["included"]), ("candidate", False))
            with reopened.connection() as conn:
                self.assertEqual(resolve(conn, {"name": "Former Name"})["candidates"], [item["id"]])


if __name__ == "__main__":
    unittest.main()
