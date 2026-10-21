"""Regression cases from PHP CVE-2025-14180's published NVD/PHP rules."""
import tempfile
import unittest
from pathlib import Path

from signalwatch.collectors import _web_fingerprints
from signalwatch.store import Store
from signalwatch.matching import version_match


class ExposureAccuracyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "test.db")
        self.url = "https://example.test/"
        self.asset = "domain:example.test"
        affected = [{"vendor": "php", "product": "php", "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                     "versionStartIncluding": start, "versionEndExcluding": end}
                    for start, end in [("8.1.0", "8.1.34"), ("8.2.0", "8.2.30"), ("8.3.0", "8.3.29"), ("8.4.0", "8.4.16"), ("8.5.0", "8.5.1")]]
        self.store.ingest({"advisories": [{"id": "CVE-2025-14180", "source": "NVD", "severity": 7.5, "affected": affected}]})

    def observe(self, headers, html=""):
        _, observations, _ = _web_fingerprints(self.url, headers, html)
        self.store.ingest({"observation_pages": [{"asset_id": self.asset, "source_url": self.url}], "observations": observations})
        self.store.reconcile()
        return self.store.alerts()["items"]

    def test_fixed_versions_clear_previous_warning(self):
        for version in ("8.1.34", "8.2.30", "8.2.35", "8.3.29", "8.4.16", "8.4.24", "8.5.1"):
            with self.subTest(version=version):
                self.assertEqual(len(self.observe({"X-Powered-By": "PHP/8.2.29"})), 1)
                self.assertEqual(self.observe({"X-Powered-By": "PHP/" + version}), [])

    def test_partial_version_never_becomes_zero_patch_version(self):
        for version in ("8", "8.4"):
            self.assertEqual(self.observe({"X-Powered-By": "PHP/" + version}), [])
            _, state, reason = version_match(version, {"vendor": "php", "product": "php", "versionEndExcluding": "8.4.16"})
            self.assertEqual(state, "version_unverified")
            self.assertIn("patch level", reason)

    def test_affected_banner_does_not_prove_backports_or_runtime_prerequisites(self):
        row = self.observe({"X-Powered-By": "PHP/8.2.29"}, '<meta name="generator" content="WordPress 6.9">')[0]
        self.assertEqual(row["version_state"], "affected_range")
        exposure = row["assessment"]["exposure"]
        self.assertEqual(exposure["state"], "unverified")
        self.assertIsNone(exposure["reportable"])
        self.assertEqual(exposure["patch_status"], "unverified")
        self.assertEqual(len(exposure["prerequisites"]), 3)
        self.assertTrue(all(item["state"] == "unknown" for item in exposure["prerequisites"]))

    def test_distribution_package_suffix_is_not_silently_stripped(self):
        self.assertEqual(self.observe({"X-Powered-By": "PHP/8.2.29-1ubuntu1"}), [])
        with self.store.connection() as conn:
            row = conn.execute("SELECT version FROM observations WHERE asset_id=?", (self.asset,)).fetchone()
        self.assertIn("ubuntu", row["version"])

    def test_conflicting_php_headers_never_select_one_as_verified(self):
        self.assertEqual(self.observe({"Server": "Apache PHP/5.4.16", "X-Powered-By": "PHP/8.3.8"}), [])
        with self.store.connection() as conn:
            row = conn.execute("SELECT evidence FROM observations WHERE product='php' AND asset_id=?", (self.asset,)).fetchone()
        self.assertIn("Conflicting PHP", row["evidence"])

    def test_successful_response_without_php_removes_old_observation(self):
        self.assertEqual(len(self.observe({"X-Powered-By": "PHP/8.2.29"})), 1)
        self.assertEqual(self.observe({"Server": "Azure"}), [])

    def test_unknown_http_version_is_inventory_not_a_cve_warning(self):
        self.assertEqual(self.observe({"X-Powered-By": "PHP"}), [])
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM observations").fetchone()[0], 1)

    def test_unknown_secondary_page_cannot_resurrect_a_patched_warning(self):
        self.store.ingest({"observations": [{"asset_id": self.asset, "vendor": "php", "product": "php",
                           "version": "", "origin": "web", "source_url": self.url + "about"}]})
        self.assertEqual(self.observe({"X-Powered-By": "PHP/8.4.24"}), [])

    def test_unknown_inventory_context_is_not_falsely_marked_contradictory(self):
        self.store.ingest({"observations": [{"asset_id": self.asset, "vendor": "php", "product": "php",
                           "version": "", "origin": "web", "source_url": self.url + "about"}]})
        row = self.observe({"X-Powered-By": "PHP/8.2.29"})[0]
        self.assertEqual(row["assessment"]["evidence"]["contradicting"], [])
