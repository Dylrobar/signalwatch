import asyncio
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from multidict import CIMultiDict

from signalwatch.web_fingerprint_catalog import CACHE_NAME, CATALOG_URL, Catalog, CatalogError, load_catalog


def payload(apps):
    return json.dumps({"apps": apps}).encode()


class CatalogMatchingTests(unittest.TestCase):
    def test_passive_vectors_extract_versions_without_trusting_cpe_or_vendor(self):
        catalog = Catalog(payload({
            "Example Server": {"headers": {"server": r"example/([\d.]+)\;version:\1"}, "cpe": "cpe:2.3:a:wrong:identity:*:*:*:*:*:*:*:*"},
            "Example CMS": {"meta": {"generator": [r"example ([\d.]+)\;version:\1"]}},
            "Example Library": {"scriptSrc": [r"/example-([\d.]+)\.js\;version:\1"]},
            "Example Session": {"cookies": {"example_session": ""}},
            "Example Markup": {"html": "data-example-widget"},
        }))
        headers = CIMultiDict([("Server", "Example/1.2.3 SECRET"), ("Set-Cookie", "unrelated=SECRET; Secure"),
                               ("Set-Cookie", "example_session=SECRET; HttpOnly")])
        html = '<meta content="Example 4.5.6" name="generator"><script src="/example-7.8.9.js?token=SECRET"></script><div data-example-widget>'
        findings, diagnostics = catalog.match("https://example.test/?token=SECRET", headers, html)
        rows = {row["product_name"]: row for row in findings}
        self.assertEqual(diagnostics, [])
        self.assertEqual(rows["Example Server"]["version"], "1.2.3")
        self.assertEqual(rows["Example CMS"]["version"], "4.5.6")
        self.assertEqual(rows["Example Library"]["version"], "7.8.9")
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(row["cpe"] is None and row["vendor"] == "unknown" for row in findings))
        self.assertNotIn("SECRET", json.dumps(findings))

    def test_cookie_values_cannot_forge_another_cookie_name(self):
        catalog = Catalog(payload({"Laravel": {"cookies": {"laravel_session": ""}}}))
        for value in ['unrelated="hello, laravel_session=SECRET"', "unrelated=hello, laravel_session=SECRET"]:
            with self.subTest(value=value):
                findings, _ = catalog.match("https://example.test", {"Set-Cookie": value}, "")
                self.assertEqual(findings, [])
        findings, _ = catalog.match("https://example.test", {}, "", cookie_names=("laravel_session",))
        self.assertEqual(findings[0]["product_name"], "Laravel")

    def test_unsupported_browser_patterns_and_cookie_values_are_visible(self):
        catalog = Catalog(payload({"Example": {"headers": {"x-example": ""}, "js": {"example.version": ""},
                                              "dom": {"#example": {"exists": ""}}, "css": [".example"],
                                              "scripts": ["example.init"], "cookies": {"session": "secret-value"}}}))
        messages = " ".join(catalog.diagnostics)
        for kind in ("unsupported js", "unsupported dom", "unsupported css", "unsupported scripts", "cookie-value patterns"):
            self.assertIn(kind, messages)
        findings, _ = catalog.match("https://example.test", {"Set-Cookie": "session=secret-value"}, "<div id='example'>example.init</div>")
        self.assertEqual(findings, [])

    def test_dependency_cycles_preserve_direct_evidence_and_never_copy_versions(self):
        catalog = Catalog(payload({"Example": {"headers": {"server": r"example/([\d.]+)\;version:\1"}, "implies": ["Runtime"]},
                                   "Runtime": {"implies": ["Example", "Database"]}, "Database": {"implies": ["Runtime"]}}))
        rows, _ = catalog.match("https://example.test", {"Server": "Example/1.2.3"}, "")
        by_name = {row["product_name"]: row for row in rows}
        self.assertEqual(len(rows), 3)
        self.assertEqual(by_name["Example"]["status"], "http_detected")
        self.assertEqual(by_name["Example"]["version"], "1.2.3")
        for name in ("Runtime", "Database"):
            self.assertEqual(by_name[name]["status"], "implied_dependency")
            self.assertEqual(by_name[name]["version"], "")
            self.assertIsNone(by_name[name]["cpe"])
            self.assertTrue(by_name[name]["implied_by"])

    def test_literal_or_conditional_versions_are_not_asserted_and_zero_confidence_is_ignored(self):
        catalog = Catalog(payload({"Literal": {"headers": {"x-literal": r"example\;version:2.0"}},
                                   "Conditional": {"headers": {"x-conditional": r"(example)\;version:\1?2:3"}},
                                   "Zero": {"headers": {"x-zero": r"\;confidence:0"}},
                                   "Composite": {"headers": {"x-composite": r"(\d+)_(\d+)\;version:\1.\2"}}}))
        rows, _ = catalog.match("https://example.test", {"x-literal": "example", "x-conditional": "example", "x-zero": "present", "x-composite": "1_2"}, "")
        by_name = {row["product_name"]: row for row in rows}
        self.assertNotIn("Zero", by_name)
        self.assertEqual(by_name["Literal"]["version"], "")
        self.assertEqual(by_name["Conditional"]["version"], "")
        self.assertEqual(by_name["Composite"]["version"], "1.2")
        self.assertTrue(any("unsupported version" in message for message in catalog.diagnostics))

    def test_ambiguous_catalog_identities_remain_curated(self):
        catalog = Catalog(payload({"Safe": {"headers": {"x-safe": ""}},
                                   "Sentry": {"html": r"release: '(\d+)'\;version:\1"},
                                   "Tomcat": {"cookies": {"JSESSIONID": ""}},
                                   "Laravel": {"cookies": {"XSRF-TOKEN": ""}},
                                   "IIS": {"cookies": {"ASP.NET_SessionId": ""}}}))
        rows, _ = catalog.match("https://example.test", {}, "release: '123456'", cookie_names=("JSESSIONID", "XSRF-TOKEN", "ASP.NET_SessionId"))
        self.assertEqual(rows, [])
        self.assertIn("4 ambiguous signatures", " ".join(catalog.diagnostics))

    def test_constraint_bearing_apps_are_not_matched_unconditionally(self):
        catalog = Catalog(payload({"Safe": {"headers": {"x-safe": ""}},
                                   "Requires": {"headers": {"x-match": ""}, "requires": ["Missing"]},
                                   "Category": {"headers": {"x-match": ""}, "requiresCategory": [1]},
                                   "Excludes": {"headers": {"x-match": ""}, "excludes": ["Safe"]}}))
        findings, _ = catalog.match("https://example.test", {"x-match": "present"}, "")
        self.assertEqual(findings, [])
        self.assertIn("3 apps with unsupported dependency constraints", " ".join(catalog.diagnostics))

    def test_implications_cannot_bypass_constraints_or_zero_confidence(self):
        catalog = Catalog(payload({"Parent": {"headers": {"x-parent": ""},
                                               "implies": ["Constrained", r"Zero\;confidence:0", r"Low\;confidence:20", r"UnknownModifier\;requires:Other"]},
                                   "Constrained": {"requires": ["Absent"]}, "Zero": {}, "Low": {}, "UnknownModifier": {}}))
        rows, _ = catalog.match("https://example.test", {"x-parent": "present"}, "")
        self.assertEqual({row["product_name"] for row in rows}, {"Parent", "Low"})
        self.assertEqual(next(row["confidence"] for row in rows if row["product_name"] == "Low"), 0.2)
        messages = " ".join(catalog.diagnostics)
        self.assertIn("dependency hints with unsupported constraints", messages)
        self.assertIn("zero-confidence dependency hints", messages)
        self.assertIn("unsupported dependency modifiers", messages)

    def test_real_catalog_findings_survive_collector_and_company_storage_without_alert_observations(self):
        from signalwatch.collectors import _web_evidence_entity, _web_fingerprints
        from signalwatch.store import Store

        catalog = Catalog(payload({"Example Widget": {"headers": {"x-widget": r"example/([\d.]+)\;version:\1"},
                                                      "implies": ["Example Runtime"]}, "Example Runtime": {}}))
        url = "https://example.test/"
        findings, observations, diagnostics = _web_fingerprints(url, {"x-widget": "example/1.2.3"}, "", catalog=catalog)
        self.assertEqual(observations, [])
        self.assertEqual(diagnostics, [])
        store = Store(":memory:")
        store.ingest({"entities": [{"id": "company:example", "kind": "company", "name": "Example"},
                                   {"id": "domain:example.test", "kind": "domain", "value": "example.test"}],
                      "edges": [{"from_id": "company:example", "to_id": "domain:example.test", "relation": "official_website"}]})
        store.ingest({"entities": [_web_evidence_entity(url, findings, "2026-10-20T00:00:00Z")], "observations": observations})
        rows = store.detail("company:example")["technographics"]["fingerprints"]
        self.assertEqual(len(rows), 2)
        by_name = {row["product_name"]: row for row in rows}
        self.assertEqual(by_name["Example Widget"]["version"], "1.2.3")
        self.assertEqual(by_name["Example Runtime"]["implied_by"], ["Example Widget"])
        self.assertTrue(all(row["vendor"] == "unknown" and row["cpe"] is None for row in rows))
        self.assertEqual(store.stats()["observations"], 0)

    def test_regex_timeouts_and_total_budget_are_visible(self):
        catalog = Catalog(payload({"Expensive": {"html": r"(a+)+$"}, "Header": {"headers": {"x-header": ""}}}))
        with patch("signalwatch.web_fingerprint_catalog.PATTERN_SECONDS", 0.0001):
            findings, diagnostics = catalog.match("https://example.test", {"x-header": ""}, "a" * 20_000 + "!")
        self.assertEqual([row["product_name"] for row in findings], ["Header"])
        self.assertTrue(any("regex evaluations" in message for message in diagnostics))
        with patch("signalwatch.web_fingerprint_catalog.MATCH_SECONDS", 0):
            findings, diagnostics = catalog.match("https://example.test", {"x-header": ""}, "")
        self.assertEqual(findings, [])
        self.assertTrue(any("response time budget" in message for message in diagnostics))

    def test_pattern_and_finding_limits_remain_visible(self):
        catalog = Catalog(payload({**{f"App {index}": {"headers": {"x-example": ""}} for index in range(105)},
                                   "Huge": {"html": "a{1,999999999}"}}))
        self.assertIn("oversized repetitions", " ".join(catalog.diagnostics))
        rows, diagnostics = catalog.match("https://example.test", {"x-example": "present"}, "")
        self.assertEqual(len(rows), 100)
        self.assertTrue(any("100 finding limit" in message for message in diagnostics))
        with patch("signalwatch.web_fingerprint_catalog.COMPILE_SECONDS", 0), self.assertRaises(CatalogError):
            Catalog(payload({"Example": {"headers": {"server": ""}}}))

    def test_invalid_or_browser_only_catalog_is_rejected(self):
        for raw in (b"not json", b"[]", b'{"apps":{}}', payload({"Example": {"headers": {"server": "("}}}),
                    payload({"Example": {"js": {"example": ""}}})):
            with self.subTest(raw=raw), self.assertRaises(CatalogError):
                Catalog(raw)


class CatalogCacheTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.download = self.root / "download.json"
        self.download.write_bytes(payload({"Example": {"headers": {"server": "example"}}}))
        self.http = SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(path=self.download)))

    async def asyncTearDown(self):
        self.temp.cleanup()

    async def test_initial_download_is_cached_with_provenance_and_license(self):
        catalog, diagnostics = await load_catalog(self.http, self.root)
        self.assertEqual(diagnostics, [])
        self.http.get.assert_awaited_once_with(CATALOG_URL, max_bytes=8 * 1024 * 1024, cache=True)
        saved = json.loads((self.root / CACHE_NAME).read_text())
        self.assertEqual(saved["digest"], catalog.metadata["digest"])
        self.assertIn("Copyright (c) 2021 ProjectDiscovery", saved["license"])
        self.http.get.reset_mock()
        cached, diagnostics = await load_catalog(self.http, self.root)
        self.http.get.assert_not_awaited()
        self.assertEqual(cached.metadata, catalog.metadata)
        self.assertEqual(diagnostics, [])

    async def test_invalid_refresh_preserves_last_good_catalog(self):
        original, _ = await load_catalog(self.http, self.root)
        before = (self.root / CACHE_NAME).read_bytes()
        self.download.write_text("{broken json")
        with patch("signalwatch.web_fingerprint_catalog.CACHE_TTL", 0):
            cached, diagnostics = await load_catalog(self.http, self.root)
        self.assertEqual(cached.metadata, original.metadata)
        self.assertEqual((self.root / CACHE_NAME).read_bytes(), before)
        self.assertTrue(any("using the last-good catalog" in message for message in diagnostics))

    async def test_non_utf8_refresh_preserves_last_good_catalog(self):
        original, _ = await load_catalog(self.http, self.root)
        before = (self.root / CACHE_NAME).read_bytes()
        self.download.write_bytes(payload({"Example": {"headers": {"server": "example"}}}).decode().encode("utf-16"))
        with patch("signalwatch.web_fingerprint_catalog.CACHE_TTL", 0):
            cached, diagnostics = await load_catalog(self.http, self.root)
        self.assertEqual(cached.metadata, original.metadata)
        self.assertEqual((self.root / CACHE_NAME).read_bytes(), before)
        self.assertTrue(any("using the last-good catalog" in message for message in diagnostics))

    async def test_corrupt_cache_and_failed_download_fall_back_visibly(self):
        await load_catalog(self.http, self.root)
        path = self.root / CACHE_NAME
        cached = json.loads(path.read_text())
        cached["digest"] = "incorrect"
        path.write_text(json.dumps(cached))
        self.http.get.side_effect = OSError("SECRET")
        catalog, diagnostics = await load_catalog(self.http, self.root)
        self.assertIsNone(catalog)
        self.assertTrue(any("cache is invalid" in message for message in diagnostics))
        self.assertTrue(any("using built-in fingerprints only" in message for message in diagnostics))
        self.assertNotIn("SECRET", " ".join(diagnostics))

    async def test_cache_write_failure_keeps_downloaded_catalog_usable(self):
        with patch("signalwatch.web_fingerprint_catalog._save", side_effect=OSError):
            catalog, diagnostics = await load_catalog(self.http, self.root)
        self.assertIsNotNone(catalog)
        self.assertTrue(any("could not be saved" in message for message in diagnostics))

    async def test_cancellation_propagates(self):
        self.http.get.side_effect = asyncio.CancelledError
        with self.assertRaises(asyncio.CancelledError):
            await load_catalog(self.http, self.root)
