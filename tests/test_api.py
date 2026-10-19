import base64
import json
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from signalwatch.store import Store


class ApiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.config = cls.root / "config.json"
        cls.config.write_text(json.dumps({"db": "monitor.db", "cache_dir": "cache", "seed_urls": [], "sbom_max_mb": 0.5, "staging_max_payload_mb": 0.01, "nvd_api_key": "private-nvd-value", "github_token": "private-github-value"}))
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

    def test_source_catalog_exposes_capabilities_without_credentials(self):
        catalog = self.request("/api/sources/catalog")
        rows = {row["id"]: row for row in catalog["items"]}
        self.assertEqual(catalog["total"], len(rows))
        self.assertIn("wigle", rows)
        self.assertEqual(rows["shodan"]["status"], "unconfigured")
        encoded = json.dumps(catalog) + json.dumps(self.request("/api/sources/settings"))
        self.assertNotIn("private-nvd-value", encoded)
        self.assertNotIn("private-github-value", encoded)

    def test_source_settings_persist_and_invalid_updates_have_no_effect(self):
        before = self.request("/api/sources/settings")
        try:
            changed = self.request("/api/sources/settings", {"source_targets": [{"name": "Example", "domain": "Example.COM"}], "source_intervals": {"news": 17}, "watch_products": ["nginx"], "provider_settings": {"zdi_published": {"enabled": False}}})
            self.assertTrue(changed["saved"])
            self.assertEqual(changed["source_targets"][0]["domain"], "example.com")
            self.assertEqual(self.request("/api/status")["config"]["source_intervals"]["news"], 17)
            disk = json.loads(self.config.read_text())
            self.assertEqual(disk["watch_products"], ["nginx"])
            current = self.request("/api/sources/settings")
            for invalid in ({"source_intervals": {"news": 0}}, {"source_intervals": {"unknown": 5}}, {"source_targets": [{"domain": "bad/domain"}]}, {"source_targets": [{"domain": "bad\u0000domain"}]}, {"provider_settings": {"shodan": {"api_key": "must-not-store"}}}, {"provider_settings": {"shodan": {"token": "must-not-store"}}}, {"provider_credentials": {"shodan": "must-not-store"}}, {"provider_settings": {"shodan": {"url": " HTTPS://user:pass@example.test/"}}}, {"provider_settings": {"shodan": {"url": "https://example.test/?%61%70%69%5f%6b%65%79=must-not-store"}}}, {"provider_settings": {"shodan": {"url": []}}}, {"provider_settings": {"shodan": {"enabled": "yes"}}}):
                with self.subTest(invalid=invalid), self.assertRaises(urllib.error.HTTPError) as raised:
                    self.request("/api/sources/settings", invalid)
                self.assertEqual(raised.exception.code, 422)
                self.assertEqual(self.request("/api/sources/settings"), current)
        finally:
            self.request("/api/sources/settings", before)

    def test_source_settings_reject_credentials_in_every_url_field(self):
        before = self.request("/api/sources/settings")
        disk_before = self.config.read_bytes()
        urls = [
            "example.test/feed?token=must-not-store",
            "example.test/feed?%61uthorization=must-not-store",
            "https://example.test/feed?authorization=must-not-store",
            "example.test/feed?API_KEY=must-not-store",
            "user:must-not-store@example.test/feed",
        ]
        for location in urls:
            values = [
                {"provider_settings": {"zdi_published": {"url": location}}},
                {"provider_settings": {"zdi_published": {"urls": [location]}}},
                {"provider_settings": {"technographics": {"verifier_url": location}}},
                {"source_targets": [{"domain": "example.test", "document_urls": [location]}]},
                {"source_targets": [{"domain": "example.test", "javascript_urls": [location]}]},
                {"source_targets": [{"domain": "example.test", "sourcemap_urls": [location]}]},
                {"source_targets": [{"domain": "example.test", "feed_urls": [location]}]},
                {"source_targets": [{"domain": "example.test", "provider_urls": {"zdi_published": [location]}}]},
            ]
            for payload in values:
                with self.subTest(payload=payload):
                    with self.assertRaises(urllib.error.HTTPError) as raised:
                        self.request("/api/sources/settings", payload)
                    self.assertEqual(raised.exception.code, 422)
                    self.assertNotIn("must-not-store", raised.exception.read().decode())
                    self.assertEqual(self.request("/api/sources/settings"), before)
                    self.assertEqual(self.config.read_bytes(), disk_before)

    def test_source_targets_reject_stale_snapshot_without_changing_any_settings(self):
        before = self.request("/api/sources/settings")
        try:
            first = self.request("/api/sources/settings", {
                "source_targets": [{"domain": "Example.COM", "feed_urls": ["https://example.test/feed?topic=release%20notes"]}],
                "expected_source_targets": before["source_targets"],
            })
            self.assertEqual(first["source_targets"][0]["domain"], "example.com")
            self.assertIn("topic=release+notes", first["source_targets"][0]["feed_urls"][0])
            unchanged = self.request("/api/sources/settings", {
                "source_targets": first["source_targets"],
                "expected_source_targets": first["source_targets"],
            })
            self.assertEqual(first, unchanged)
            current = self.request("/api/sources/settings")
            disk_before = self.config.read_bytes()
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.request("/api/sources/settings", {
                    "source_targets": [{"domain": "stale.example.invalid"}],
                    "expected_source_targets": before["source_targets"],
                    "watch_products": ["must-not-replace"],
                })
            self.assertEqual(raised.exception.code, 409)
            self.assertIn("Reload before saving", raised.exception.read().decode())
            self.assertEqual(self.request("/api/sources/settings"), current)
            self.assertEqual(self.config.read_bytes(), disk_before)
            self.assertNotIn("expected_source_targets", current)
            self.assertNotIn("expected_source_targets", json.loads(disk_before))
        finally:
            self.request("/api/sources/settings", before)

    def test_competing_source_target_updates_have_exactly_one_winner(self):
        before = self.request("/api/sources/settings")
        try:
            self.request("/api/sources/settings", {"source_targets": []})

            def save(domain):
                try:
                    result = self.request("/api/sources/settings", {
                        "source_targets": [{"domain": domain}], "expected_source_targets": [],
                    })
                    return 200, result["source_targets"]
                except urllib.error.HTTPError as error:
                    error.close()
                    return error.code, None

            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(save, ["first.example.invalid", "second.example.invalid"]))
            self.assertEqual(sorted(status for status, _ in outcomes), [200, 409])
            winner = next(targets for status, targets in outcomes if status == 200)
            self.assertEqual(self.request("/api/sources/settings")["source_targets"], winner)
            self.assertEqual(json.loads(self.config.read_text())["source_targets"], winner)
        finally:
            self.request("/api/sources/settings", before)

    def test_expected_source_targets_require_a_replacement(self):
        disk_before = self.config.read_bytes()
        with self.assertRaises(urllib.error.HTTPError) as raised:
            self.request("/api/sources/settings", {"expected_source_targets": []})
        self.assertEqual(raised.exception.code, 422)
        self.assertEqual(self.config.read_bytes(), disk_before)

    def test_source_target_snapshot_does_not_reduce_settings_size_budget(self):
        before = self.request("/api/sources/settings")
        targets = [{"domain": f"target-{index}.example.invalid", "notes": "x" * 3900} for index in range(12)]
        try:
            self.request("/api/sources/settings", {"source_targets": targets})
            request = {"source_targets": targets, "expected_source_targets": targets}
            self.assertGreater(len(json.dumps(request)), 65536)
            self.assertTrue(self.request("/api/sources/settings", request)["saved"])
            disk_before = self.config.read_bytes()
            oversized = targets + [{"domain": f"extra-{index}.example.invalid", "notes": "x" * 3900} for index in range(5)]
            with self.assertRaises(urllib.error.HTTPError) as raised:
                self.request("/api/sources/settings", {"source_targets": oversized, "expected_source_targets": targets})
            self.assertEqual(raised.exception.code, 413)
            self.assertEqual(self.config.read_bytes(), disk_before)
        finally:
            self.request("/api/sources/settings", before)

    def test_source_settings_preserve_public_url_queries(self):
        before = self.request("/api/sources/settings")
        location = "example.test/feed?format=json&page=2&limit=20"
        try:
            result = self.request("/api/sources/settings", {
                "source_targets": [{"domain": "example.test", "feed_urls": [location]}],
            })
            self.assertTrue(result["saved"])
            self.assertEqual(result["source_targets"][0]["feed_urls"], [location])
            self.assertEqual(json.loads(self.config.read_text())["source_targets"][0]["feed_urls"], [location])
        finally:
            self.request("/api/sources/settings", before)

    def test_unified_staging_preserves_bytes_and_processes_in_background(self):
        raw = b"\x00\xff wireless export\r\n"
        request = {"source": "api-staging-bytes", "adapter": "opaque", "payload_encoding": "base64",
                   "payload": base64.b64encode(raw).decode(), "metadata": {"sensor": "local-import"}, "idempotency_key": "capture-1"}
        staged = self.request("/api/staging", request)
        duplicate = self.request("/api/staging", request)
        self.assertEqual(staged["id"], duplicate["id"])
        self.assertTrue(duplicate["duplicate"])
        with urllib.request.urlopen(self.base + f'/api/staging/{staged["id"]}/payload') as response:
            self.assertEqual(response.read(), raw)
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("attachment", response.headers["Content-Disposition"])
        for _ in range(100):
            detail = self.request(f'/api/staging/{staged["id"]}')
            if detail["status"] == "processed":
                break
            time.sleep(.05)
        self.assertEqual(detail["status"], "processed")
        self.assertNotIn("payload", detail)
        self.assertNotIn("lease_token", detail)
        listed = self.request("/api/staging?status=processed")["items"]
        self.assertIn(staged["id"], [item["id"] for item in listed])
        self.assertNotIn("payload", next(item for item in listed if item["id"] == staged["id"]))
        self.assertIn("counts", self.request("/api/staging/stats"))

    def test_staging_failed_adapter_can_be_retried_without_losing_raw_input(self):
        raw = "  imported text\r\n"
        staged = self.request("/api/staging", {"source": "api-staging-retry", "adapter": "not-installed", "payload": raw})
        for _ in range(100):
            detail = self.request(f'/api/staging/{staged["id"]}')
            if detail["status"] == "dead":
                break
            time.sleep(.05)
        self.assertEqual(detail["status"], "dead")
        self.request(f'/api/staging/{staged["id"]}/retry', {"adapter": "opaque"})
        for _ in range(100):
            detail = self.request(f'/api/staging/{staged["id"]}')
            if detail["status"] == "processed":
                break
            time.sleep(.05)
        self.assertEqual(detail["status"], "processed")
        with urllib.request.urlopen(self.base + f'/api/staging/{staged["id"]}/payload') as response:
            self.assertEqual(response.read(), raw.encode())

    def test_invalid_staging_requests_leave_queue_unchanged(self):
        before = self.request("/api/staging/stats")["total"]
        for payload, expected in [
            ({"source": "api-invalid", "payload": "x" * 12000}, 413),
            ({"source": "api-invalid", "payload_encoding": "base64", "payload": "***"}, 400),
            ({"source": "api-invalid", "payload": {"unexpected": "object"}}, 400),
            ({"source": " ", "payload": "data"}, 422),
            ({"source": "api-invalid", "payload": "data", "observed_at": "2026-10-19T00:00:00"}, 422),
        ]:
            with self.subTest(payload=payload):
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    self.request("/api/staging", payload)
                self.assertEqual(raised.exception.code, expected)
        self.assertEqual(self.request("/api/staging/stats")["total"], before)

    def test_company_profile_creation_edit_search_and_collector_refresh(self):
        profile = {"name": "Profile API Research", "legal_name": "Profile API Research Limited",
                   "aliases": ["  Profile Alias  ", "Profile Alias"], "brands": ["Profile Brand"],
                   "notes": "Identity supplied from a corporate page", "source_url": "https://profile-api.example/legal"}
        created = self.request("/api/companies/profile", profile)
        company_id = created["id"]
        self.assertEqual(created["kind"], "company")
        self.assertEqual(created["company_profile"]["aliases"], ["Profile Alias"])
        self.assertEqual(created["company_profile"]["legal_name"], profile["legal_name"])
        self.assertIn(company_id, [row["id"] for row in self.request("/api/search?kind=company&q=Profile%20Alias")["items"]])
        store = Store(self.root / "monitor.db")
        store.ingest({"entities": [{"id": company_id, "kind": "company", "name": "Collected label", "metadata": {"wikidata": "Q123"}}]})
        detail = self.request("/api/entity?id=" + company_id)
        self.assertEqual(detail["name"], profile["name"])
        self.assertEqual(detail["company_profile"]["notes"], profile["notes"])
        parent = self.request("/api/companies/profile", {"name": "Profile Parent"})
        edited = self.request("/api/companies/profile", {**profile, "company_id": company_id, "parent_company_id": parent["id"]})
        self.assertEqual(edited["company_profile"]["parent_company"]["id"], parent["id"])
        self.assertIn(company_id, [row["id"] for row in self.request("/api/entity?id=" + parent["id"])["company_profile"]["subsidiaries"]])

    def test_company_asset_decisions_rollup_and_queue_scope(self):
        company = self.request("/api/companies/profile", {"name": "Asset Decision API"})
        company_id = company["id"]
        store = Store(self.root / "monitor.db")
        self.request("/api/observations", {"asset_url": "https://asset-decision-api.example", "vendor": "decision-api",
                                           "product": "service", "version": "1.0", "evidence": "Supplied version record"})
        decision = {"company_id": company_id, "asset_url": "https://asset-decision-api.example/", "status": "candidate",
                    "role": "owned", "evidence": "Corporate inventory entry", "source_url": "https://asset-decision-api.example/legal"}
        candidate = self.request("/api/companies/assets", decision)
        self.assertFalse(candidate["company_profile"]["assets"][0]["included"])
        self.assertEqual(candidate["observations"], [])
        with store.connection() as conn:
            self.assertIsNone(conn.execute("SELECT url FROM crawl_urls WHERE company_id=?", (company_id,)).fetchone())
        confirmed = self.request("/api/companies/assets", {**decision, "status": "confirmed"})
        self.assertTrue(confirmed["company_profile"]["assets"][0]["included"])
        self.assertEqual(len(confirmed["observations"]), 1)
        with store.connection() as conn:
            self.assertEqual(conn.execute("SELECT url FROM crawl_urls WHERE company_id=?", (company_id,)).fetchone()[0], decision["asset_url"])
        rejected = self.request("/api/companies/assets", {**decision, "status": "rejected", "evidence": "Incorrect corporate association"})
        self.assertEqual(rejected["observations"], [])
        self.assertEqual(rejected["company_profile"]["assets"][0]["status"], "rejected")
        reset = self.request("/api/companies/assets", {"company_id": company_id, "asset_url": decision["asset_url"], "status": "automatic"})
        self.assertEqual(reset["company_profile"]["assets"], [])
        service = self.request("/api/companies/assets", {**decision, "asset_url": "https://service-decision-api.example/", "role": "service", "status": "confirmed"})
        self.assertFalse(service["company_profile"]["assets"][0]["included"])
        with store.connection() as conn:
            self.assertIsNone(conn.execute("SELECT url FROM crawl_urls WHERE url='https://service-decision-api.example/'").fetchone())

    def test_invalid_company_inputs_return_client_errors_without_creating_records(self):
        company = self.request("/api/companies/profile", {"name": "Validation API Company"})
        cases = [
            ("/api/companies/profile", {"name": "  "}, 422),
            ("/api/companies/profile", {"name": "Invalid", "source_url": "file:///etc/passwd"}, 400),
            ("/api/companies/profile", {"name": "Missing", "company_id": "company:missing-profile-api"}, 404),
            ("/api/companies/profile", {"name": "Invalid", "company_id": company["id"], "parent_company_id": company["id"]}, 400),
            ("/api/companies/assets", {"company_id": company["id"], "asset_url": "https://validation-api.example"}, 400),
            ("/api/companies/assets", {"company_id": company["id"], "asset_url": "file:///etc/passwd", "status": "automatic"}, 400),
            ("/api/companies/assets", {"company_id": company["id"], "asset_url": "https://validation-api.example", "status": "invalid"}, 422),
        ]
        store = Store(self.root / "monitor.db")
        before = store.stats()
        for path, payload, expected in cases:
            with self.subTest(payload=payload), self.assertRaises(urllib.error.HTTPError) as raised:
                self.request(path, payload)
            self.assertEqual(raised.exception.code, expected)
        self.assertEqual(store.stats(), before)

    def test_observations_share_canonical_identity_with_company_assets(self):
        cases = [
            ("https://canonical-api.example/", "https://CANONICAL-API.EXAMPLE./", "domain:canonical-api.example"),
            ("https://xn--bcher-kva.example/", "https://b\u00fccher.example/", "domain:xn--bcher-kva.example"),
            ("https://[2001:db8::1]/", "https://[2001:0db8:0:0:0:0:0:1]/", "domain:2001:db8::1"),
        ]
        for index, (asset_url, observation_url, asset_id) in enumerate(cases):
            with self.subTest(asset_url=asset_url):
                company = self.request("/api/companies/profile", {"name": f"Canonical Asset API {index}"})
                self.request("/api/companies/assets", {"company_id": company["id"], "asset_url": asset_url,
                             "evidence": "Supplied corporate inventory", "source_url": "https://canonical-api.example/legal"})
                result = self.request("/api/observations", {"asset_url": observation_url, "vendor": "canonical-api",
                                      "product": "service", "version": "1.0", "evidence": "Supplied version record"})
                self.assertEqual(result["id"], asset_id)
                detail = self.request("/api/entity?id=" + company["id"])
                self.assertEqual(len(detail["observations"]), 1)
                self.assertEqual(detail["observations"][0]["asset_id"], asset_id)
                self.assertEqual(detail["company_profile"]["assets"][0]["id"], asset_id)

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
