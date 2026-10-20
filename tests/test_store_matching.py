import concurrent.futures
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from signalwatch.matching import cpe_fields, ecosystem_identity, github_version_match, normalize, osv_version_match, version_match
from signalwatch.store import Store


class VersionTests(unittest.TestCase):
    def test_supported_boundaries(self):
        affected = {"versionStartIncluding": "1.2.0", "versionEndExcluding": "2.0.0"}
        self.assertTrue(version_match("1.2.0", affected)[0])
        self.assertTrue(version_match("1.9.0", affected)[0])
        self.assertFalse(version_match("2.0.0", affected)[0])
        self.assertFalse(version_match("1.1.9", affected)[0])
        self.assertFalse(version_match("1.2.0", {"versionStartExcluding": "1.2.0"})[0])
        self.assertTrue(version_match("1.2.0", {"versionEndIncluding": "1.2.0"})[0])

    def test_unknown_and_unsupported_versions_remain_candidates(self):
        self.assertEqual(version_match(None, {"version": "1.0"})[1], "unknown")
        self.assertEqual(version_match("1.0-rpm1", {"versionEndExcluding": "2.0-rpm1"})[1], "version_unverified")
        self.assertEqual(version_match("1.5", {"version": "1.*"})[1], "version_unverified")

    def test_github_supported_package_range(self):
        affected = {"ecosystem": "npm", "version_range": ">= 1.0.0, < 2.0.0"}
        self.assertTrue(github_version_match("1.5.0", affected)[0])
        self.assertFalse(github_version_match("2.0.0", affected)[0])
        affected["version_range"] = "< 1.2.0 || >= 2.0.0"
        self.assertEqual(github_version_match("1.5.0", affected)[1], "version_unverified")
        self.assertEqual(ecosystem_identity("pip"), ecosystem_identity("PyPI"))
        self.assertEqual(ecosystem_identity("Rust"), ecosystem_identity("crates.io"))

    def test_cpe_escaped_product(self):
        fields = cpe_fields(r"cpe:2.3:a:vendor:example\:product:1.0:*:*:*:*:*:*:*")
        self.assertEqual(fields["product"], "example:product")

    def test_exact_version(self):
        self.assertTrue(version_match("1.0.0", {"version": "1.0"})[0])
        self.assertFalse(version_match("1.1", {"version": "1.0"})[0])
        self.assertTrue(version_match("release-a", {"version": "release-b"})[0])

    def test_osv_multiple_ranges_and_boundaries(self):
        affected = {"ecosystem": "npm", "package": "x", "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.2.0"}, {"introduced": "2.0.0"}, {"last_affected": "2.0.5"}]}]}
        for version in ("0.0.1", "1.1.9", "2.0.0", "2.0.5"):
            self.assertTrue(osv_version_match(version, affected)[0], version)
        for version in ("1.2.0", "1.9.9", "2.0.6"):
            self.assertFalse(osv_version_match(version, affected)[0], version)

    def test_osv_ecosystem_ordering_is_conservative(self):
        affected = {"ecosystem": "Debian", "package": "x", "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}
        self.assertEqual(osv_version_match("99.0", affected)[1], "version_unverified")
        affected["ranges"][0]["type"] = "GIT"
        self.assertEqual(osv_version_match("abcdef", affected)[1], "version_unverified")
        affected["ranges"][0]["type"] = "SEMVER"
        self.assertEqual(osv_version_match("1.2.0-rc.1", affected)[1], "version_unverified")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "test.sqlite3"
        self.store = Store(self.path)

    def tearDown(self):
        self.directory.cleanup()

    def advisory(self, **changes):
        item = {"id": "CVE-2025-12345", "title": "Acme Edge Router issue", "source": "NVD", "url": "https://example.org/CVE-2025-12345", "severity": 9.0, "modified": "2025-01-01T00:00:00Z", "affected": [{"vendor": "acme", "product": "edge_router", "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}]}
        item.update(changes)
        return item

    def observation(self, **changes):
        item = {"asset_id": "domain:example.org", "vendor": "Acme", "product": "edge-router", "version": "1.5", "source_url": "https://example.org/", "evidence": "HTTP product identifier", "confidence": .8}
        item.update(changes)
        return item

    def test_idempotency_and_indexes(self):
        batch = {"advisories": [self.advisory()], "observations": [self.observation()]}
        self.store.ingest(batch)
        self.store.reconcile()
        before = self.store.stats()
        self.store.ingest(batch)
        self.store.reconcile()
        self.assertEqual(before, self.store.stats())
        self.assertEqual(self.store.alerts()["total"], 1)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")
            indexes = {row[1] for row in conn.execute("PRAGMA index_list('affected')")}
            self.assertIn("affected_product", indexes)

    def test_no_substring_or_unknown_vendor_match(self):
        self.store.ingest({"advisories": [self.advisory()], "observations": [self.observation(product="edge_router_pro"), self.observation(asset_id="other", vendor="other")]})
        self.assertEqual(self.store.reconcile()["alerts"], 0)
        self.assertEqual(normalize("Edge_Router"), normalize("edge-router"))

    def test_unknown_version_is_potential_and_has_context(self):
        self.store.ingest({"advisories": [self.advisory(configurations={"nodes": []})], "observations": [self.observation(version=None)]})
        self.store.reconcile()
        alert = self.store.alerts()["items"][0]
        self.assertEqual(alert["status"], "potential")
        self.assertEqual(alert["version_state"], "unknown")
        self.assertEqual(alert["confidence"], .8)
        self.assertTrue(any("configuration" in reason for reason in alert["reasons"]))

    def test_patched_observation_removes_alert(self):
        self.store.ingest({"advisories": [self.advisory()], "observations": [self.observation()]})
        self.store.reconcile()
        self.store.ingest({"observations": [self.observation(version="2.0")]})
        self.assertEqual(self.store.reconcile()["alerts"], 0)
        self.assertEqual(self.store.stats()["observations"], 1)

    def test_cpe_part_discrimination(self):
        self.store.ingest({"advisories": [self.advisory(affected=[{"vendor": "acme", "product": "edge_router", "part": "h"}])], "observations": [self.observation()]})
        self.assertEqual(self.store.reconcile()["alerts"], 0)
        self.store.ingest({"observations": [self.observation(asset_id="device:a", part="h")]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)

    def test_non_vulnerable_configuration_is_not_alert(self):
        self.store.ingest({"advisories": [self.advisory(affected=[{"vendor": "acme", "product": "edge_router", "vulnerable": False}])], "observations": [self.observation()]})
        self.assertEqual(self.store.reconcile()["alerts"], 0)

    def test_alias_links_deduplicate_alerts_regardless_order(self):
        ghsa = self.advisory(id="GHSA-AAAA-BBBB-CCCC", aliases=[], source="GitHub", url="https://github.com/advisories/GHSA-AAAA-BBBB-CCCC")
        self.store.ingest({"advisories": [ghsa], "observations": [self.observation()]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        cve = self.advisory(aliases=["GHSA-AAAA-BBBB-CCCC"])
        self.store.ingest({"advisories": [cve], "articles": [{"url": "https://news.example.org/item", "title": "A report", "cves": [ghsa["id"]]}]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        alert = self.store.alerts()["items"][0]
        self.assertEqual(alert["advisory_id"], cve["id"])
        self.assertEqual(self.store.advisories()["total"], 1)
        detail = self.store.detail(cve["id"])
        self.assertIn(ghsa["id"], detail["aliases"])
        self.assertEqual(detail["articles"][0]["title"], "A report")

    def test_rejected_cve_cancels_alias_group(self):
        ghsa = self.advisory(id="GHSA-AAAA-BBBB-CCCC", aliases=["CVE-2025-12345"])
        self.store.ingest({"advisories": [ghsa, self.advisory(rejected=True)], "observations": [self.observation()]})
        self.assertEqual(self.store.reconcile()["alerts"], 0)
        self.assertEqual(self.store.advisories()["total"], 0)

    def test_source_rows_preserve_cpe_and_osv_ranges(self):
        osv = self.advisory(id="OSV:CVE-2025-12345", source="OSV", aliases=["CVE-2025-12345"], affected=[{"ecosystem": "PyPI", "package": "example-package", "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}])
        self.store.ingest({"advisories": [osv, self.advisory()], "observations": [self.observation(), {"asset_id": "package:host", "ecosystem": "PyPI", "package": "example_package", "version": "1.0"}]})
        self.assertEqual(self.store.reconcile()["alerts"], 2)
        self.assertEqual(self.store.stats()["advisories"], 1)
        self.assertEqual(self.store.stats()["advisory_documents"], 2)
        self.assertEqual(len(self.store.detail(osv["id"])["advisory"]["affected"]), 1)
        self.store.ingest({"advisories": [dict(osv, rejected=True, affected=[])]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        self.assertEqual(self.store.alerts()["items"][0]["asset_id"], "domain:example.org")

    def test_github_osv_ecosystem_identity(self):
        github = self.advisory(id="GHSA-AAAA-BBBB-CCCC", affected=[{"ecosystem": "pip", "product": "example-package", "vendor": "pip", "version_range": "< 2.0"}])
        self.store.ingest({"advisories": [github], "observations": [{"asset_id": "host:a", "ecosystem": "PyPI", "package": "example_package", "version": "1.0"}]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        self.store.ingest({"observations": [{"asset_id": "host:a", "ecosystem": "PyPI", "package": "example_package", "version": "2.0"}]})
        self.assertEqual(self.store.reconcile()["alerts"], 0)

    def test_package_names_do_not_false_merge(self):
        osv = self.advisory(id="OSV:GHSA-AAAA-BBBB-CCCC", aliases=["GHSA-AAAA-BBBB-CCCC"], affected=[{"ecosystem": "npm", "package": "example-package", "versions": ["1.0.0"]}])
        self.store.ingest({"advisories": [osv], "observations": [{"asset_id": "asset:a", "ecosystem": "npm", "package": "example_package", "version": "1.0.0"}]})
        self.assertEqual(self.store.reconcile()["alerts"], 0)
        self.store.ingest({"observations": [{"asset_id": "asset:b", "ecosystem": "npm", "package": "example-package", "version": "1.0.0"}]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)

    def test_kev_epss_ranking(self):
        self.store.ingest({"advisories": [self.advisory()], "observations": [self.observation()], "kev": [{"cveID": "CVE-2025-12345", "dateAdded": "2025-01-01"}], "epss": [{"cve": "CVE-2025-12345", "epss": ".9", "percentile": ".99", "date": "2025-01-02"}]})
        self.store.reconcile()
        alert = self.store.alerts()["items"][0]
        self.assertTrue(alert["kev"])
        self.assertEqual(alert["rank"], 94)
        self.assertEqual(self.store.advisories(kev=True)["total"], 1)

    def test_provenance_not_legal_company(self):
        self.store.ingest({"advisories": [self.advisory()]})
        vendor = self.store.detail("vendor:acme")
        self.assertEqual(vendor["kind"], "vendor")
        self.assertFalse(vendor["metadata"]["verified_legal_company"])
        self.assertEqual(vendor["metadata"]["evidence_role"], "cpe_vendor_label")
        self.assertEqual(vendor["relationships"][0]["source_url"], "https://example.org/CVE-2025-12345")

    def test_kev_snapshot_removes_only_missing_kev_documents(self):
        records = [{"cveID": "CVE-2025-12345", "dateAdded": "2025-01-01", "vulnerabilityName": "Acme issue"}, {"cveID": "CVE-2025-54321", "dateAdded": "2025-01-01", "vulnerabilityName": "Other issue"}]
        self.store.ingest({"kev_snapshot": records, "advisories": [self.advisory()]})
        self.assertEqual(self.store.advisories(kev=True)["total"], 2)
        self.assertGreaterEqual(self.store.advisories()["items"][0]["rank"], 40)
        self.store.ingest({"kev_snapshot": [records[1]]})
        self.assertEqual(self.store.advisories(kev=True)["total"], 1)
        self.assertIsNotNone(self.store.detail("CVE-2025-12345")["advisory"])
        self.assertIsNone(self.store.detail("KEV:CVE-2025-12345"))
        self.store.ingest({"kev_snapshot": []})
        self.assertEqual(self.store.advisories(kev=True)["total"], 0)
        self.assertEqual(self.store.advisories()["total"], 1)

    def test_page_snapshot_removes_disappeared_fingerprint(self):
        observation = self.observation(origin="web")
        self.store.ingest({"advisories": [self.advisory()], "observations": [observation]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        self.store.ingest({"observation_pages": [{"asset_id": observation["asset_id"], "source_url": observation["source_url"]}], "observations": []})
        self.assertEqual(self.store.reconcile()["alerts"], 0)
        self.assertEqual(self.store.stats()["observations"], 0)
        self.assertFalse(any(row["relation"] == "observed_technology" for row in self.store.detail(observation["asset_id"])["relationships"]))

    def test_manual_and_web_same_page_keep_separate_versions(self):
        imported = self.observation(version="1.5", evidence="Imported inventory")
        web = self.observation(version="", evidence="Public page product match", origin="web")
        self.store.ingest({"observations": [imported, web], "advisories": [self.advisory()]})
        observations = self.store.detail(imported["asset_id"])["observations"]
        self.assertEqual(len(observations), 2)
        self.assertEqual({row["origin"]: row["version"] for row in observations}, {"imported": "1.5", "web": ""})
        self.store.ingest({"observation_pages": [{"asset_id": imported["asset_id"], "source_url": imported["source_url"]}], "observations": [dict(web, version="3.0")]})
        observations = self.store.detail(imported["asset_id"])["observations"]
        self.assertEqual({row["origin"]: row["version"] for row in observations}, {"imported": "1.5", "web": "3.0"})
        self.store.ingest({"observation_pages": [{"asset_id": imported["asset_id"], "source_url": imported["source_url"]}], "observations": []})
        detail = self.store.detail(imported["asset_id"])
        self.assertEqual(len(detail["observations"]), 1)
        self.assertEqual(detail["observations"][0]["evidence"], "Imported inventory")
        self.assertEqual(detail["observations"][0]["origin"], "imported")
        self.assertTrue(any(row["relation"] == "observed_technology" for row in detail["relationships"]))
        self.assertEqual(self.store.reconcile()["alerts"], 1)

    def test_legacy_unknown_origin_migrates_as_imported(self):
        observation = self.observation()
        self.store.ingest({"observations": [observation]})
        with self.store.connection(write=True) as conn:
            # Simulate the schema before both origin and its dependent evidence
            # invariants existed; reopening must reinstall the current guards.
            triggers = conn.execute("SELECT name FROM sqlite_master WHERE type='trigger' AND name GLOB 'technographic_*'").fetchall()
            for trigger in triggers:
                conn.execute('DROP TRIGGER "' + trigger[0].replace('"', '""') + '"')
            conn.execute("DROP TABLE technographic_integrity_migrations")
            conn.execute("DROP INDEX observations_page_origin")
            conn.execute("ALTER TABLE observations DROP COLUMN origin")
        reopened = Store(self.path)
        self.assertEqual(reopened.detail(observation["asset_id"])["observations"][0]["origin"], "imported")
        reopened.ingest({"observations": [observation]})
        self.assertEqual(reopened.stats()["observations"], 1)
        reopened.ingest({"observation_pages": [{"asset_id": observation["asset_id"], "source_url": observation["source_url"]}], "observations": []})
        self.assertEqual(reopened.stats()["observations"], 1)

    def test_same_vendor_product_news_single_specific_token(self):
        self.store.ingest({"observations": [self.observation(vendor="wordpress", product="wordpress"), self.observation(asset_id="asset:generic", vendor="generic", product="server")], "articles": [{"url": "https://news.example.org/wordpress", "title": "WordPress security fix", "cves": []}, {"url": "https://news.example.org/generic", "title": "A server problem", "cves": []}]})
        related = self.store.detail("domain:example.org")["related_articles"]
        self.assertEqual(len(related), 1)
        self.assertEqual(related[0]["match_phrases"], ["wordpress"])
        self.assertEqual(self.store.detail("asset:generic")["related_articles"], [])

    def test_detail_without_entity_has_no_cycles(self):
        self.store.ingest({"advisories": [self.advisory()]})
        with self.store.connection(write=True) as conn:
            conn.execute("DELETE FROM entities WHERE id='CVE-2025-12345'")
        detail = self.store.detail("CVE-2025-12345")
        self.assertIsNot(detail, detail["advisory"])
        import json
        self.assertTrue(json.dumps(detail))

    def test_news_without_cve_links_by_observed_product_phrase(self):
        self.store.ingest({"observations": [self.observation()], "articles": [{"url": "https://news.example.org/zero", "title": "Acme Edge Router emergency security update", "summary": "A newly disclosed issue", "cves": []}, {"url": "https://news.example.org/unrelated", "title": "Router sales report", "cves": []}]})
        related = self.store.detail("domain:example.org")["related_articles"]
        self.assertEqual(len(related), 1)
        self.assertEqual(related[0]["match_type"], "product_mention")
        self.assertEqual(related[0]["status"], "candidate")
        self.assertEqual(self.store.alerts()["total"], 0)

    def test_search_quotes_and_fts(self):
        self.store.ingest({"entities": [{"id": "company:a", "kind": "company", "name": "Acme Research", "value": "Acme"}], "advisories": [self.advisory()], "articles": [{"url": "https://news.example.org/a", "title": "Critical router security issue"}]})
        self.assertEqual(self.store.search('"Research"', kind="company")["total"], 1)
        self.assertEqual(self.store.advisories("Edge Router")["total"], 1)
        self.assertEqual(self.store.articles("router")["total"], 1)
        self.assertEqual(self.store.search("nonexistent")["total"], 0)

    def test_active_advisory_stats_match_canonical_list(self):
        first = self.advisory()
        duplicate = self.advisory(id="GHSA-AAAA-BBBB-CCCC", aliases=[first["id"]], source="GitHub")
        rejected = self.advisory(id="CVE-2025-54321", rejected=True)
        rejected_alias = self.advisory(id="OSV:CVE-2025-54321", aliases=[rejected["id"]], source="OSV")
        withdrawn = self.advisory(id="GHSA-DDDD-EEEE-FFFF", rejected=True)
        other = self.advisory(id="GHSA-GGGG-HHHH-IIII")
        self.store.ingest({"advisories": [first, duplicate, rejected, rejected_alias, withdrawn, other]})
        stats = self.store.stats()
        self.assertEqual(stats["advisory_documents"], 6)
        self.assertEqual(stats["advisories"], 2)
        self.assertEqual(stats["advisories"], self.store.advisories()["total"])
        self.assertEqual({item["id"] for item in self.store.advisories()["items"]}, {first["id"], other["id"]})

    def test_canonical_detail_resolves_existing_source_without_nvd(self):
        cases = [
            ("CVE-2025-11111", {"kev": [{"cveID": "CVE-2025-11111", "vulnerabilityName": "Known exploitation", "dateAdded": "2025-01-01"}]}, "KEV:CVE-2025-11111", "CISA KEV"),
            ("CVE-2025-22222", {"advisories": [self.advisory(id="GHSA-AAAA-BBBB-CCCC", aliases=["CVE-2025-22222"], source="GitHub", url="https://github.com/advisories/GHSA-AAAA-BBBB-CCCC")]}, "GHSA-AAAA-BBBB-CCCC", "GitHub"),
            ("CVE-2025-33333", {"advisories": [self.advisory(id="OSV:CVE-2025-33333", aliases=["CVE-2025-33333"], source="OSV", url="https://osv.dev/vulnerability/CVE-2025-33333")]}, "OSV:CVE-2025-33333", "OSV"),
        ]
        for cve, batch, source_id, source in cases:
            with self.subTest(source=source):
                self.store.ingest(batch)
                before = self.store.stats()["advisory_documents"]
                detail = self.store.detail(cve.lower())
                self.assertEqual(detail["requested_id"], cve)
                self.assertEqual(detail["canonical_id"], cve)
                self.assertEqual(detail["source_record_id"], source_id)
                self.assertEqual(detail["advisory"]["id"], source_id)
                self.assertEqual(detail["advisory"]["source"], source)
                self.assertEqual(self.store.detail(source_id)["advisory"], detail["advisory"])
                self.assertEqual(before, self.store.stats()["advisory_documents"])
                with self.store.connection() as conn:
                    self.assertIsNone(conn.execute("SELECT id FROM advisories WHERE id=?", (cve,)).fetchone())

    def test_alias_detail_without_graph_entity_resolves_real_source(self):
        advisory = self.advisory(aliases=["GHSA-AAAA-BBBB-CCCC"])
        self.store.ingest({"advisories": [advisory]})
        with self.store.connection() as conn:
            self.assertIsNone(conn.execute("SELECT id FROM entities WHERE id='GHSA-AAAA-BBBB-CCCC'").fetchone())
        detail = self.store.detail("GHSA-AAAA-BBBB-CCCC")
        self.assertEqual(detail["advisory"]["id"], advisory["id"])
        self.assertEqual(detail["advisory"]["url"], advisory["url"])
        self.assertEqual(detail["requested_id"], "GHSA-AAAA-BBBB-CCCC")
        self.assertTrue(any(edge["relation"] == "affected_by" for edge in detail["relationships"]))
        self.assertIsNone(self.store.detail("CVE-2025-99999"))

    def test_advisory_rank_and_newest_sort_are_stable(self):
        older = self.advisory(id="CVE-2025-11111", modified="2025-01-01T00:00:00Z", severity=9)
        newer = self.advisory(id="CVE-2025-22222", modified="2025-02-01T00:00:00Z", severity=2)
        tied = self.advisory(id="CVE-2025-33333", modified=newer["modified"], severity=2)
        self.store.ingest({"advisories": [tied, newer, older]})
        self.assertEqual([item["id"] for item in self.store.advisories()["items"]], [older["id"], newer["id"], tied["id"]])
        self.assertEqual([item["id"] for item in self.store.advisories(sort="newest")["items"]], [newer["id"], tied["id"], older["id"]])
        self.assertEqual([self.store.advisories("", False, 1, offset, sort="newest")["items"][0]["id"] for offset in range(3)], [newer["id"], tied["id"], older["id"]])
        with self.assertRaises(ValueError):
            self.store.advisories(sort="unknown")

    def test_alert_kev_version_filters_and_newest_sort(self):
        records = [
            self.advisory(id="CVE-2025-11111", severity=9, affected=[{"vendor": "acme", "product": "exact_product", "version": "1.5"}]),
            self.advisory(id="CVE-2025-22222", severity=8, affected=[{"vendor": "acme", "product": "range_product", "versionEndExcluding": "2.0"}]),
            self.advisory(id="CVE-2025-33333", severity=7, affected=[{"vendor": "acme", "product": "unverified_product"}]),
        ]
        observations = [
            self.observation(asset_id="asset:exact", product="exact_product"),
            self.observation(asset_id="asset:unknown", product="exact_product", version=""),
            self.observation(asset_id="asset:range", product="range_product"),
            self.observation(asset_id="asset:unverified", product="unverified_product"),
        ]
        self.store.ingest({"advisories": records, "observations": observations, "kev": [{"cveID": records[0]["id"]}]})
        self.store.reconcile()
        self.assertEqual(self.store.alerts()["total"], 4)
        for state, asset in (("exact", "asset:exact"), ("unknown", "asset:unknown"), ("affected_range", "asset:range"), ("version_unverified", "asset:unverified")):
            matches = self.store.alerts(version_state=state)
            self.assertEqual(matches["total"], 1)
            self.assertEqual(matches["items"][0]["asset_id"], asset)
        self.assertEqual(self.store.alerts(kev=True)["total"], 2)
        self.assertEqual(self.store.alerts(kev=True, version_state="exact")["items"][0]["asset_id"], "asset:exact")
        self.assertEqual(self.store.alerts(kev=True, version_state="affected_range")["total"], 0)
        self.assertEqual(self.store.alerts("range", kev=True)["total"], 0)
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE alerts SET first_seen='2025-01-01T00:00:00Z',last_seen='2025-03-01T00:00:00Z'")
            conn.execute("UPDATE alerts SET first_seen='2025-02-01T00:00:00Z',last_seen='2025-01-01T00:00:00Z' WHERE asset_id='asset:unverified'")
        self.assertTrue(self.store.alerts()["items"][0]["kev"])
        self.assertEqual(self.store.alerts(sort="newest")["items"][0]["asset_id"], "asset:unverified")
        ordered = [item["id"] for item in self.store.alerts(sort="newest")["items"]]
        pages = [self.store.alerts("", 1, offset, sort="newest")["items"][0]["id"] for offset in range(4)]
        self.assertEqual(pages, ordered)
        with self.assertRaises(ValueError):
            self.store.alerts(sort="unknown")
        with self.assertRaises(ValueError):
            self.store.alerts(version_state="affected")

    def test_product_graph_advisories_without_asset_alerts(self):
        for part, kind in (("a", "technology"), ("h", "device"), ("o", "os")):
            with self.subTest(kind=kind):
                vendor = "vendor_" + part
                affected = [{"vendor": vendor, "product": "edge_router", "part": part}]
                ghsa = self.advisory(id="GHSA-AAAA-BBBB-CCC" + part.upper(), aliases=[], affected=affected)
                cve = self.advisory(id="CVE-2025-1111" + str(ord(part)), aliases=[ghsa["id"]], affected=affected)
                rejected = self.advisory(id="CVE-2025-2222" + str(ord(part)), rejected=True, affected=affected)
                context = self.advisory(id="CVE-2025-3333" + str(ord(part)), affected=[dict(affected[0], vulnerable=False)])
                self.store.ingest({"advisories": [ghsa]})
                self.store.ingest({"advisories": [cve, rejected, context]})
                product = self.store.detail(f"cpe:{part}:{normalize(vendor)}:edge router")
                self.assertEqual(product["kind"], kind)
                self.assertEqual(product["alerts"], [])
                self.assertEqual([item["id"] for item in product["advisories"]], [cve["id"]])
                self.assertEqual(product["advisories"][0]["source"], cve["source"])

    def test_package_graph_advisories_deduplicate_aliases(self):
        affected = [{"ecosystem": "PyPI", "package": "example-package", "versions": ["1.0"]}]
        older = self.advisory(id="OSV:GHSA-AAAA-BBBB-CCCC", source="OSV", aliases=["GHSA-AAAA-BBBB-CCCC", "CVE-2025-11111"], affected=affected)
        newer = self.advisory(id="GHSA-AAAA-BBBB-CCCC", source="GitHub", aliases=["CVE-2025-11111"], modified="2025-02-01T00:00:00Z", affected=affected)
        self.store.ingest({"advisories": [older, newer]})
        product = self.store.detail("package:pypi:example-package")
        self.assertEqual(product["kind"], "package")
        self.assertEqual(product["alerts"], [])
        self.assertEqual([item["id"] for item in product["advisories"]], [newer["id"]])
        self.assertEqual(product["advisories"][0]["canonical_id"], "CVE-2025-11111")

    def test_network_targets_only_stale_global_unicast_ips(self):
        fresh = datetime.now(timezone.utc).isoformat()
        entities = [
            {"id": "ip:9.9.9.9", "kind": "ip", "value": "9.9.9.9"},
            {"id": "ip:8.8.8.8", "kind": "ip", "value": "8.8.8.8", "metadata": {"network_enriched_at": "2000-01-01T00:00:00Z"}},
            {"id": "ip:1.1.1.1", "kind": "ip", "value": "1.1.1.1", "metadata": {"network_enriched_at": fresh}},
            {"id": "ip:2606:4700:4700::1111", "kind": "ip", "value": "2606:4700:4700::1111", "metadata": {"network_enriched_at": "invalid"}},
        ]
        for address in ("10.0.0.1", "127.0.0.1", "192.0.2.1", "224.0.0.1", "::1", "fe80::1", "ff02::1", "not-an-ip"):
            entities.append({"id": "ip:" + address, "kind": "ip", "value": address})
        self.store.ingest({"entities": entities})
        targets = self.store.network_targets(10, 24)
        self.assertEqual({item["value"] for item in targets}, {"9.9.9.9", "8.8.8.8", "2606:4700:4700::1111"})
        self.assertEqual(targets[-1]["value"], "8.8.8.8")
        self.assertEqual(len(self.store.network_targets(1, 24)), 1)
        self.assertEqual(self.store.network_pending_count(24), 3)
        self.store.ingest({"entities": [{"id": "ip:9.9.9.9", "kind": "ip", "value": "9.9.9.9", "metadata": {"network_enriched_at": fresh}}]})
        self.assertEqual(self.store.network_pending_count(24), 2)
        self.assertNotIn("9.9.9.9", {item["value"] for item in self.store.network_targets(10, 24)})

    def test_latest_authoritative_cve_state_controls_alias_group(self):
        cve = "CVE-2025-12345"
        nvd = self.advisory(rejected=True, modified="2025-01-01T08:00:00Z")
        ghsa = self.advisory(id="GHSA-AAAA-BBBB-CCCC", source="GitHub", aliases=[cve], modified="2025-04-01T00:00:00Z")
        cve5 = self.advisory(id="CVE5:" + cve, source="cve_program", aliases=[cve], modified="2025-01-01T04:30:00-04:00", configurations={"cve_state": "PUBLISHED"})
        self.store.ingest({"advisories": [nvd, ghsa], "observations": [self.observation()]})
        self.assertEqual(self.store.reconcile()["alerts"], 0)
        self.store.ingest({"advisories": [cve5]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        self.assertEqual(self.store.advisories()["total"], 1)
        rejected = dict(cve5, rejected=True, modified="2025-01-01T08:40:00Z", configurations={"cve_state": "REJECTED"})
        self.store.ingest({"advisories": [rejected]})
        self.assertEqual(self.store.reconcile()["alerts"], 0)
        self.assertEqual(self.store.stats()["advisories"], 0)
        republished = dict(cve5, modified="2025-01-01T09:00:00Z")
        self.store.ingest({"advisories": [republished]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        self.assertEqual(self.store.stats()["advisories"], self.store.advisories()["total"])

    def test_source_local_withdrawal_cannot_reject_canonical_cve(self):
        cve = self.advisory()
        withdrawn = self.advisory(id="OSV:" + cve["id"], source="OSV", aliases=[cve["id"]], rejected=True, modified="2099-01-01T00:00:00Z", configurations={"cve_state": "REJECTED"})
        self.store.ingest({"advisories": [cve, withdrawn], "observations": [self.observation()]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        self.assertEqual(self.store.advisories()["total"], 1)

    def test_cve5_native_version_rules_do_not_claim_cpe_exact_version(self):
        matches, state, reason = version_match("3.0", {"criteria": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*", "version_unverified": True, "cve_versions": [{"version": "1.0", "status": "affected"}]})
        self.assertTrue(matches)
        self.assertEqual(state, "version_unverified")
        self.assertIn("Native", reason)

    def test_article_cross_cycle_merge_keeps_other_feed_evidence(self):
        url = "https://news.example.org/shared"
        first = {"url": url, "title": "A complete report", "summary": "Detailed report preserving vendor findings and vulnerability evidence", "source": "Feed A", "cves": ["CVE-2025-11111"], "feed_url": "https://a.example.org/feed"}
        second = {"url": url, "title": "A short excerpt", "summary": "Short excerpt", "source": "Feed B", "cves": [], "feed_url": "https://b.example.org/feed"}
        self.store.ingest({"articles": [first]})
        self.store.ingest({"articles": [second]})
        article = self.store.articles()["items"][0]
        self.assertEqual(article["cves"], first["cves"])
        self.assertEqual(article["summary"], first["summary"])
        self.assertEqual(article["feed_urls"], [first["feed_url"], second["feed_url"]])
        self.assertEqual(article["feed_sources"], ["Feed A", "Feed B"])
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT advisory_id FROM article_links WHERE article_id=?", (article["id"],)).fetchone()[0], first["cves"][0])
        corrected_first = dict(first, cves=[], summary="Corrected report", feed_records={first["feed_url"]: {"source": "Feed A", "title": first["title"], "summary": "Corrected report", "cves": []}})
        self.store.ingest({"articles": [corrected_first]})
        corrected = self.store.articles()["items"][0]
        self.assertEqual(corrected["cves"], [])
        self.assertEqual(corrected["summary"], "Corrected report")
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM article_links WHERE article_id=?", (article["id"],)).fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM edges WHERE from_id=? AND relation='mentions'", (article["id"],)).fetchone()[0], 0)

    def test_article_same_cycle_feed_records_preserve_unchanged_feed(self):
        url = "https://news.example.org/merged"
        feed_a, feed_b = "https://a.example.org/feed", "https://b.example.org/feed"
        first = {"url": url, "title": "Combined article", "summary": "Long summary from A", "source": "Feed A", "cves": ["CVE-2025-11111", "CVE-2025-22222"], "feed_urls": [feed_a, feed_b], "feed_sources": ["Feed A", "Feed B"], "feed_records": {feed_a: {"source": "Feed A", "summary": "Long summary from A", "cves": ["CVE-2025-11111"]}, feed_b: {"source": "Feed B", "summary": "Summary B", "cves": ["CVE-2025-22222"]}}}
        self.store.ingest({"articles": [first]})
        changed = {"url": url, "title": "Changed B", "summary": "B corrected", "source": "Feed B", "cves": [], "feed_url": feed_b, "feed_records": {feed_b: {"source": "Feed B", "summary": "B corrected", "cves": []}}}
        self.store.ingest({"articles": [changed]})
        article = self.store.articles()["items"][0]
        self.assertEqual(article["cves"], ["CVE-2025-11111"])
        self.assertEqual(article["summary"], "Long summary from A")
        self.store.ingest({"articles": [changed]})
        self.assertEqual(self.store.articles()["total"], 1)
        self.assertEqual(self.store.articles()["items"][0], article)

    def test_unattributed_article_imports_preserve_union_and_fuller_summary(self):
        url = "https://news.example.org/imported"
        self.store.ingest({"articles": [{"url": url, "title": "Original", "summary": "Full original summary", "source": "Import A", "cves": ["CVE-2025-11111"]}]})
        self.store.ingest({"articles": [{"url": url, "title": "Excerpt", "summary": "Short", "source": "Import B", "cves": []}]})
        article = self.store.articles()["items"][0]
        self.assertEqual(article["cves"], ["CVE-2025-11111"])
        self.assertEqual(article["summary"], "Full original summary")
        self.assertEqual(article["feed_sources"], ["Import A", "Import B"])

    def test_events_track_meaningful_advisory_source_changes(self):
        advisory = self.advisory()
        self.store.ingest({"advisories": [advisory]})
        first = self.store.events(kind="advisory_added")
        self.assertEqual(first["total"], 1)
        event = first["items"][0]
        self.assertIn("first observed locally", event["title"])
        self.assertEqual(event["subject_id"], advisory["id"])
        self.assertEqual(event["canonical_id"], advisory["id"])
        self.assertIsNone(event["before"])
        self.assertEqual(event["after"]["severity"], 9)
        self.assertEqual(event, self.store.event(str(event["id"])))
        self.assertIsNone(self.store.event(999999))
        self.store.ingest({"advisories": [advisory]})
        metadata_update = dict(advisory, modified="2025-04-01T00:00:00Z", summary="Updated prose only", references=["https://example.org/reference"], raw={"feed_updated": True})
        self.store.ingest({"advisories": [metadata_update]})
        self.assertEqual(self.store.events()["total"], 1)
        changed = dict(metadata_update, severity=7.5, title="Changed title", affected=[dict(advisory["affected"][0], versionEndExcluding="3.0")])
        self.store.ingest({"advisories": [changed]})
        self.assertEqual(self.store.events(kind="advisory_changed")["total"], 1)
        change = self.store.events(kind="advisory_changed")["items"][0]
        self.assertEqual(set(change["after"]["changed_fields"]), {"severity", "title", "affected"})
        self.assertEqual(change["before"]["severity"], 9)
        self.assertEqual(change["after"]["severity"], 7.5)
        self.assertNotIn("raw", change["after"])
        self.store.ingest({"advisories": [changed]})
        self.assertEqual(self.store.stats()["events"], 2)
        self.assertEqual(self.store.events(q="CVE-2025-12345", kind="advisory_changed")["total"], 1)

    def test_event_search_includes_native_advisory_title(self):
        advisory = self.advisory(title="HistoryScope package vulnerability")
        self.store.ingest({"advisories": [advisory]})
        first = self.store.events(q="historyscope")
        self.assertEqual(first["total"], 1)
        self.assertEqual(first["items"][0]["canonical_id"], advisory["id"])
        self.assertIn(advisory["title"], first["items"][0]["title"])
        self.store.ingest({"advisories": [dict(advisory, severity=7.0)]})
        self.assertEqual(self.store.events(q="historyscope", kind="advisory_changed")["total"], 1)

    def test_native_version_range_change_has_visible_snapshot_digest(self):
        affected = {"ecosystem": "PyPI", "package": "example-package", "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0"}]}]}
        advisory = self.advisory(affected=[affected])
        self.store.ingest({"advisories": [advisory]})
        changed = dict(affected, ranges=[{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}])
        self.store.ingest({"advisories": [dict(advisory, affected=[changed])]})
        event = self.store.events(kind="advisory_changed")["items"][0]
        self.assertEqual(event["before"]["affected"], event["after"]["affected"])
        self.assertNotEqual(event["before"]["affected_digest"], event["after"]["affected_digest"])
        self.assertEqual(event["after"]["changed_fields"], ["affected"])

    def test_events_start_without_fabricating_existing_history(self):
        advisory = self.advisory()
        self.store.ingest({"advisories": [advisory]})
        with self.store.connection(write=True) as conn:
            conn.execute("DROP TABLE events")
            conn.execute("DROP TABLE advisory_seen")
        reopened = Store(self.path)
        self.assertEqual(reopened.events()["total"], 0)
        reopened.ingest({"advisories": [advisory]})
        self.assertEqual(reopened.events()["total"], 0)
        reopened.ingest({"advisories": [dict(advisory, severity=7)]})
        self.assertEqual(reopened.events(kind="advisory_changed")["total"], 1)
        self.assertEqual(reopened.events(kind="advisory_added")["total"], 0)

    def test_advisory_events_merge_aliases_without_new_local_addition(self):
        ghsa = self.advisory(id="GHSA-AAAA-BBBB-CCCC", source="GitHub", aliases=[])
        self.store.ingest({"advisories": [ghsa], "observations": [self.observation()]})
        self.store.reconcile()
        cve = self.advisory(aliases=[ghsa["id"]])
        self.store.ingest({"advisories": [cve]})
        self.store.reconcile()
        self.assertEqual(self.store.events(kind="advisory_added")["total"], 1)
        self.assertEqual(self.store.events(kind="advisory_added")["items"][0]["canonical_id"], cve["id"])
        self.assertEqual(self.store.events(kind="warning_opened")["total"], 1)
        self.assertEqual(self.store.events(kind="warning_resolved")["total"], 0)
        self.assertEqual(self.store.alerts()["items"][0]["advisory_id"], cve["id"])

    def test_kev_events_require_real_membership_change(self):
        records = [{"cveID": "CVE-2025-11111", "vulnerabilityName": "First issue"}, {"cveID": "CVE-2025-22222", "vulnerabilityName": "Second issue"}]
        self.store.ingest({"kev_snapshot": records})
        self.assertEqual(self.store.events(kind="kev_added")["total"], 2)
        self.store.ingest({"kev_snapshot": records})
        self.store.ingest({"kev": [dict(records[0], notes="Catalog correction")]})
        self.assertEqual(self.store.events(kind="kev_added")["total"], 2)
        self.assertEqual(self.store.events(kind="kev_removed")["total"], 0)
        self.store.ingest({"kev_snapshot": [records[1]]})
        removed = self.store.events(kind="kev_removed")
        self.assertEqual(removed["total"], 1)
        self.assertEqual(removed["items"][0]["before"]["cveID"], records[0]["cveID"])
        self.assertIsNone(removed["items"][0]["after"])
        self.store.ingest({"kev_snapshot": records})
        self.assertEqual(self.store.events(kind="kev_added")["total"], 3)
        self.assertEqual(self.store.events(kind="advisory_added")["total"], 2)

    def test_warning_events_open_and_clear_without_reconcile_churn(self):
        self.store.ingest({"advisories": [self.advisory()], "observations": [self.observation()]})
        self.store.reconcile()
        self.store.reconcile()
        opened = self.store.events(kind="warning_opened")
        self.assertEqual(opened["total"], 1)
        self.assertEqual(opened["items"][0]["subject_id"], "domain:example.org")
        self.assertEqual(opened["items"][0]["after"]["version"], "1.5")
        self.store.ingest({"observations": [self.observation(version="3.0")]})
        self.store.reconcile()
        self.store.reconcile()
        resolved = self.store.events(kind="warning_resolved")
        self.assertEqual(resolved["total"], 1)
        self.assertEqual(resolved["items"][0]["subject_id"], "domain:example.org")
        self.assertEqual(resolved["items"][0]["before"]["version_state"], "affected_range")
        self.assertIsNone(resolved["items"][0]["after"])
        self.assertEqual(self.store.alerts()["total"], 0)

    def test_ingest_events_and_inventory_snapshot_roll_back_together(self):
        original = {"asset_id": "asset:sbom", "ecosystem": "PyPI", "package": "example-package", "version": "1.0", "origin": "sbom:test", "source_url": "https://inventory.example.org"}
        self.store.ingest({"observations": [original]})
        with self.assertRaises(KeyError):
            self.store.ingest({"observation_snapshots": [{"asset_id": original["asset_id"], "origin": original["origin"]}], "advisories": [self.advisory()], "observations": [{"asset_id": original["asset_id"], "ecosystem": "PyPI", "package": "replacement", "origin": original["origin"]}], "articles": [{}]})
        self.assertEqual(self.store.events()["total"], 0)
        self.assertEqual(self.store.stats()["advisory_documents"], 0)
        detail = self.store.detail(original["asset_id"])
        self.assertEqual(len(detail["observations"]), 1)
        self.assertEqual(detail["observations"][0]["product"], "example-package")

    def test_warning_events_roll_back_with_failed_alert_update(self):
        self.store.ingest({"advisories": [self.advisory()], "observations": [self.observation()]})
        with self.store.connection(write=True) as conn:
            conn.execute("CREATE TRIGGER reject_alert BEFORE INSERT ON alerts BEGIN SELECT RAISE(ABORT,'test failure'); END")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store.reconcile()
        self.assertEqual(self.store.events(kind="warning_opened")["total"], 0)
        self.assertEqual(self.store.alerts()["total"], 0)

    def test_event_retention_preserves_first_observation_ledger(self):
        records = [{"cveID": "CVE-2025-11111"}, {"cveID": "CVE-2025-22222"}]
        self.store.ingest({"kev_snapshot": records})
        total = self.store.events()["total"]
        self.assertEqual(total, 4)
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE events SET observed_at='2000-01-01T00:00:00Z' WHERE id=(SELECT min(id) FROM events)")
        self.assertEqual(self.store.prune_events(max_rows=2, days=90), 2)
        self.assertEqual(self.store.events()["total"], 2)
        self.assertEqual(self.store.prune_events(max_rows=0), 2)
        self.store.ingest({"kev_snapshot": []})
        self.store.ingest({"kev_snapshot": records})
        self.assertEqual(self.store.events(kind="advisory_added")["total"], 0)
        ordered = self.store.events()["items"]
        self.assertEqual([self.store.events("", "", 1, offset)["items"][0]["id"] for offset in range(len(ordered))], [event["id"] for event in ordered])

    def test_sbom_snapshot_preserves_multiple_versions_and_other_origins(self):
        base = {"asset_id": "asset:inventory", "ecosystem": "PyPI", "package": "example-package", "source_url": "https://inventory.example.org", "origin": "sbom:document-a"}
        versions = [dict(base, version="1.0"), dict(base, version="2.0")]
        manual = dict(base, version="3.0", origin="imported")
        other_document = dict(base, version="4.0", origin="sbom:document-b")
        other_asset = dict(base, asset_id="asset:other", version="5.0")
        self.store.ingest({"observation_snapshots": [{"asset_id": base["asset_id"], "origin": base["origin"]}], "observations": versions + [manual, other_document, other_asset]})
        observations = self.store.detail(base["asset_id"])["observations"]
        self.assertEqual({row["version"] for row in observations}, {"1.0", "2.0", "3.0", "4.0"})
        self.store.ingest({"observation_snapshots": [{"asset_id": base["asset_id"], "origin": base["origin"]}], "observations": [dict(base, package="replacement-package", version="6.0")]})
        observations = self.store.detail(base["asset_id"])["observations"]
        self.assertEqual({row["version"] for row in observations}, {"3.0", "4.0", "6.0"})
        self.assertEqual(self.store.detail("asset:other")["observations"][0]["version"], "5.0")
        self.store.ingest({"observation_snapshots": [{"asset_id": base["asset_id"], "origin": base["origin"]}], "observations": []})
        detail = self.store.detail(base["asset_id"])
        self.assertEqual({row["version"] for row in detail["observations"]}, {"3.0", "4.0"})
        self.assertFalse(any(edge["to_id"] == "package:pypi:replacement-package" for edge in detail["relationships"]))
        self.assertTrue(any(edge["to_id"] == "package:pypi:example-package" for edge in detail["relationships"]))

    def test_sbom_identity_distinguishes_cpe_parts(self):
        base = {"asset_id": "asset:inventory", "vendor": "acme", "product": "shared-product", "version": "1.0", "source_url": "https://inventory.example.org", "origin": "sbom:parts"}
        batch = {"observation_snapshots": [{"asset_id": base["asset_id"], "origin": base["origin"]}], "observations": [dict(base, part="a"), dict(base, part="h")]}
        self.store.ingest(batch)
        observations = self.store.detail(base["asset_id"])["observations"]
        self.assertEqual(len(observations), 2)
        self.assertEqual({row["part"] for row in observations}, {"a", "h"})
        self.store.ingest(batch)
        self.assertEqual(len(self.store.detail(base["asset_id"])["observations"]), 2)

    def test_sbom_explicit_unknown_version_is_not_restored_from_cpe_pattern(self):
        observation = {"asset_id": "asset:inventory", "vendor": "acme", "product": "router", "version": "", "cpe": "cpe:2.3:h:acme:router:1.*:*:*:*:*:*:*:*", "origin": "sbom:unknown"}
        self.store.ingest({"observations": [observation]})
        stored = self.store.detail(observation["asset_id"])["observations"][0]
        self.assertEqual(stored["version"], "")
        self.assertEqual(stored["cpe"], observation["cpe"])

    def test_source_state_and_concurrent_writers(self):
        def write(index):
            self.store.ingest({"entities": [{"id": f"domain:{index}", "kind": "domain", "name": f"{index}.example.org"}]})
            self.store.update_source("test", **{f"checkpoint{index}": index})
            return self.store.stats()["entities"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(write, range(20)))
        self.assertEqual(len(results), 20)
        self.assertEqual(self.store.stats()["entities"], 20)
        state = self.store.source_state("test")
        self.assertEqual(len(state), 20)
        self.store.update_source("test", feed_hashes={"recent": "abc"}, initialized=True)
        reopened = Store(self.path)
        self.assertTrue(reopened.source_state("test")["initialized"])
        self.assertEqual(reopened.source_state("test")["feed_hashes"], {"recent": "abc"})

    def test_company_detail_aggregates_direct_official_domain(self):
        self.store.ingest({"entities": [{"id": "company:a", "kind": "company", "name": "Acme"}], "edges": [{"from_id": "company:a", "to_id": "domain:example.org", "relation": "official_website", "source_url": "https://www.wikidata.org/entity/Q1"}], "observations": [self.observation()], "advisories": [self.advisory()], "articles": [{"url": "https://news.example.org/story", "title": "Acme Edge Router security news"}]})
        self.store.reconcile()
        detail = self.store.detail("company:a")
        self.assertEqual(detail["observations"][0]["asset_id"], "domain:example.org")
        self.assertEqual(detail["alerts"][0]["asset_id"], "domain:example.org")
        self.assertTrue(detail["related_articles"])

    def test_crawl_queue_prioritizes_explicit_seeds(self):
        self.store.enqueue_url("https://a.example.org", "nvd-reference")
        self.store.enqueue_url("https://b.example.org", "nvd-reference")
        self.store.enqueue_url("https://z.example.org", "wikidata", "company:a")
        self.store.enqueue_url("https://b.example.org", "user-seed")
        targets = self.store.crawl_targets(10, 24)
        self.assertEqual([item["url"] for item in targets], ["https://b.example.org", "https://z.example.org", "https://a.example.org"])

    def test_crawl_queue_leasing_and_refresh(self):
        self.store.enqueue_url("https://example.org", "https://seed.example.org", "company:a")
        self.store.enqueue_url("https://example.org")
        targets = self.store.crawl_targets(10, 24)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0]["company_id"], "company:a")
        self.assertEqual(self.store.crawl_targets(10, 24), [])
        self.store.finish_url(targets[0]["url"], "timeout")
        self.assertEqual(self.store.crawl_targets(10, 24), [])

