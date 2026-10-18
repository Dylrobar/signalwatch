import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from signalwatch.store import Store


class ApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.config = cls.root / "config.json"
        cls.config.write_text(json.dumps({"db": "monitor.db", "cache_dir": "cache", "seed_urls": [], "sbom_max_mb": 0.5, "nvd_api_key": "private-nvd-value", "github_token": "private-github-value"}))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            cls.port = sock.getsockname()[1]
        cls.logs = tempfile.TemporaryFile()
        cls.process = subprocess.Popen([sys.executable, "-m", "signalwatch", "--config", str(cls.config), "serve", "--port", str(cls.port), "--no-collect"], stdout=cls.logs, stderr=cls.logs)
        cls.base = f"http://127.0.0.1:{cls.port}"
        for _ in range(100):
            try:
                cls.request("/api/status")
                return
            except (OSError, urllib.error.URLError):
                if cls.process.poll() is not None:
                    cls.logs.seek(0)
                    raise RuntimeError(cls.logs.read().decode())
                time.sleep(0.1)
        raise RuntimeError("API failed to start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=10)
        cls.logs.close()
        cls.temp.cleanup()

    @classmethod
    def request(cls, path, data=None):
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(cls.base + path, data=body, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=10) as response:
            return json.load(response)

    def test_status_keeps_provider_keys_private(self):
        result = json.dumps(self.request("/api/status"))
        self.assertNotIn("private-nvd-value", result)
        self.assertNotIn("private-github-value", result)

    def test_status_exposes_persisted_retry_time_without_clearing_source_error(self):
        store = Store(self.root / "monitor.db")
        retry_at = "2199-01-01T00:00:00+00:00"
        previous = store.update_source("wikidata", status="error", error="HTTP 429: rate limited",
                                       retry_at=retry_at, last_success="2026-10-18T00:00:00+00:00",
                                       cursor="saved-cursor", retry_failures=2)
        result = self.request("/api/status")
        source = next(row for row in result["sources"] if row["name"] == "wikidata")
        self.assertEqual(source["retry_at"], retry_at)
        self.assertEqual(source["status"], "error")
        self.assertEqual(source["error"], "HTTP 429: rate limited")
        self.assertEqual(source["last_success"], previous["last_success"])
        self.assertNotIn("cursor", source)
        self.assertNotIn("retry_failures", source)
        self.assertEqual(store.source_state("wikidata"), previous)

    def test_source_coverage_is_visible_without_private_backlog_records(self):
        store = Store(self.root / "monitor.db")
        store.update_source("csaf", counts={"pending": 17, "records": 2}, coverage_scope="feed_history",
                            pending_documents=[{"private_marker": "not-public-state"}], documents={"private_marker": "not-public-state"},
                            feed_health={"https://example.org/feed": {"name": "Example", "status": "ok", "last_success": "2026-10-18T00:00:00Z"}})
        result = self.request("/api/status")
        source = next(row for row in result["sources"] if row["name"] == "csaf")
        self.assertEqual(source["counts"]["pending"], 17)
        self.assertEqual(source["coverage_scope"], "feed_history")
        self.assertIn("feed_health", source)
        self.assertNotIn("not-public-state", json.dumps(source))

    def test_feed_persists_and_preserves_config(self):
        self.request("/api/sources/feed", {"name": "Public advisory feed", "url": "https://example.org/advisories.xml"})
        saved = json.loads(self.config.read_text())
        self.assertEqual(saved["nvd_api_key"], "private-nvd-value")
        self.assertEqual(saved["feeds"][-1]["url"], "https://example.org/advisories.xml")

    def test_observation_is_searchable_and_exportable(self):
        result = self.request("/api/observations", {"asset_url": "https://inventory.example.org", "vendor": "nginx", "product": "nginx", "version": "1.26.0", "evidence": "Imported inventory record"})
        self.assertTrue(result["saved"])
        records = self.request("/api/search?q=inventory.example.org")["items"]
        self.assertTrue(records)
        detail = self.request("/api/entity?id=domain:inventory.example.org")
        self.assertTrue(detail)
        exported = self.request("/api/export?kind=entities&q=inventory.example.org")
        self.assertTrue(exported)

    def test_invalid_requests_return_client_errors(self):
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request("/api/seeds", {"urls": ["file:///etc/passwd"]})
        self.assertEqual(raised.exception.code, 400)
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request("/api/collect", {"sources": ["unknown-source"]})
        self.assertEqual(raised.exception.code, 400)

    def test_filtered_exports_match_list_scope_and_order(self):
        store = Store(self.root / "monitor.db")
        store.ingest({
            "advisories": [
                {"id": "CVE-2026-91001", "title": "Exportscope affected product", "summary": "Exportscope", "severity": 7.0, "modified": "2026-10-17T00:00:00Z", "affected": [{"vendor": "exportscope", "product": "service", "version": "1.0"}]},
                {"id": "CVE-2026-91002", "title": "Exportscope affected product", "summary": "Exportscope", "severity": 9.0, "modified": "2026-10-18T00:00:00Z", "affected": [{"vendor": "exportscope", "product": "service", "version": "*"}]}
            ],
            "kev": [{"cveID": "CVE-2026-91001", "vendorProject": "exportscope", "product": "service"}],
            "entities": [
                {"id": "company:exportscope", "kind": "company", "name": "Exportscope", "value": "Exportscope"},
                {"id": "domain:exportscope.example", "kind": "domain", "name": "exportscope.example", "value": "exportscope.example"}
            ],
            "observations": [{"asset_id": "domain:exportscope.example", "vendor": "exportscope", "product": "service", "version": "1.0", "evidence": "Recorded inventory"}]
        })
        store.reconcile()
        listed = self.request("/api/advisories?q=exportscope&kev=true&sort=newest")["items"]
        exported = self.request("/api/export?kind=advisories&q=exportscope&kev=true&sort=newest")
        self.assertEqual([item["id"] for item in listed], [item["id"] for item in exported])
        self.assertEqual(len(exported), 1)
        entities = self.request("/api/export?kind=entities&q=exportscope&entity_kind=company")
        self.assertEqual([item["kind"] for item in entities], ["company"])
        warnings = self.request("/api/alerts?q=exportscope&kev=true&version_state=exact")["items"]
        exported_warnings = self.request("/api/export?kind=alerts&q=exportscope&kev=true&version_state=exact")
        self.assertEqual([item["id"] for item in warnings], [item["id"] for item in exported_warnings])
        self.assertEqual(len(warnings), 1)

    def test_unknown_sort_and_version_filter_are_rejected(self):
        for path in ("/api/advisories?sort=untrusted", "/api/alerts?version_state=untrusted", "/api/export?sort=untrusted"):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.request(path)
            self.assertEqual(raised.exception.code, 422)

    def test_change_history_detail_and_filtered_export(self):
        store = Store(self.root / "monitor.db")
        original = {"id": "CVE-2026-94001", "title": "Historyscope product", "severity": 5.0, "source": "NVD", "affected": []}
        store.ingest({"advisories": [original]})
        store.ingest({"advisories": [{**original, "severity": 9.0}]})
        listed = self.request("/api/events?q=historyscope&kind=advisory_changed")
        self.assertEqual(listed["total"], 1)
        row = listed["items"][0]
        self.assertEqual(row["before"]["severity"], 5.0)
        self.assertEqual(row["after"]["severity"], 9.0)
        self.assertEqual(self.request("/api/event?id=" + str(row["id"])), row)
        exported = self.request("/api/export?kind=events&q=historyscope&event_kind=advisory_changed")
        self.assertEqual(exported, listed["items"])
        for path in ("/api/events?kind=invalid", "/api/export?kind=events&event_kind=invalid"):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.request(path)
            self.assertEqual(raised.exception.code, 422)
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request("/api/event?id=-1")
        self.assertEqual(raised.exception.code, 404)

    def test_sbom_inventory_versions_replacement_and_warning_history(self):
        store = Store(self.root / "monitor.db")
        asset = "https://inventoryscope.example/app"
        store.ingest({"advisories": [{"id": "OSV:inventoryscope", "title": "Inventoryscope package", "source": "osv", "affected": [{"ecosystem": "PyPI", "package": "requests", "versions": ["2.30.0"]}]}]})
        document = {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [
            {"type": "library", "name": "requests", "version": "2.30.0", "purl": "pkg:pypi/requests@2.30.0"},
            {"type": "library", "name": "requests", "version": "2.32.0", "purl": "pkg:pypi/requests@2.32.0"}
        ]}
        payload = {"asset_url": asset, "source_key": "release", "document": document}
        result = self.request("/api/import/sbom", payload)
        self.assertTrue(result["saved"])
        self.assertEqual(result["report"]["imported"], 2)
        self.assertEqual(store.alerts(q="inventoryscope")["total"], 1)
        detail = store.detail(asset)
        self.assertEqual({row["version"] for row in detail["observations"]}, {"2.30.0", "2.32.0"})
        self.request("/api/import/sbom", payload)
        opened = self.request("/api/events?q=inventoryscope&kind=warning_opened")
        self.assertEqual(opened["total"], 1)
        store.ingest({"observations": [{"asset_id": asset, "vendor": "manual", "product": "service", "version": "1.0", "evidence": "Recorded inventory"}]})
        result = self.request("/api/import/sbom", {**payload, "document": {**document, "components": []}})
        self.assertEqual(store.alerts(q="inventoryscope")["total"], 0)
        self.assertEqual([row["origin"] for row in store.detail(asset)["observations"]], ["imported"])
        self.assertEqual(self.request("/api/events?q=inventoryscope&kind=warning_resolved")["total"], 1)
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request("/api/import/sbom", {**payload, "document": {"spdxVersion": "SPDX-3.0"}})
        self.assertEqual(raised.exception.code, 400)

    def test_sbom_body_limit_and_invalid_request_preserve_inventory(self):
        store = Store(self.root / "monitor.db")
        before = store.stats()["observations"]
        for payload, expected in (({"asset_url": "https://limit.example/", "document": []}, 422),
                                  ({"asset_url": "https://limit.example/", "document": {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": [], "padding": "x" * 600000}}, 413)):
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.request("/api/import/sbom", payload)
            self.assertEqual(raised.exception.code, expected)
        self.assertEqual(store.stats()["observations"], before)
