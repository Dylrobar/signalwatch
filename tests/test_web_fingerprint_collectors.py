import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from multidict import CIMultiDict

from signalwatch.collectors import Collector, WEB_HTML_SAMPLE_BYTES, WEB_RESPONSE_BYTES, _web_fingerprints
from signalwatch.config import DEFAULTS
from signalwatch.http import FetchResult, HTTPError
from signalwatch.store import Store


def finding(product="next.js", vendor="vercel", status="http_detected", cpe=None, version=""):
    return {"vendor": vendor, "product": product, "vendor_name": vendor,
            "product_name": product, "category": "Framework", "part": "a",
            "version": version, "cpe": cpe, "status": status, "confidence": 0.9,
            "evidence_snippet": "Script path /_next/static/", "method": "http_fingerprint_v1",
            "evidence_type": "script"}


class WebFingerprintCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.store = Store(str(self.folder / "test.db"))
        self.collector = Collector({**DEFAULTS, "cache_dir": self.temp.name,
                                    "crawl_pages": 1, "crawl_depth": 0,
                                    "web_fingerprint_catalog": False}, self.store)
        self.collector._resolve = AsyncMock(return_value=([], []))
        self.collector._can_fetch = AsyncMock(return_value=True)
        self.response_index = 0

    def response(self, url, body="", headers=None, status=200, cookie_names=()):
        self.response_index += 1
        path = self.folder / f"page-{self.response_index}"
        path.write_text(body)
        return SimpleNamespace(path=path, status=status, headers=CIMultiDict(headers or {}),
                               url=url, changed=True, digest=hashlib.sha256(body.encode()).hexdigest(),
                               cookie_names=cookie_names)

    def observations(self):
        with self.store.connection() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM observations ORDER BY vendor,product")]

    def evidence(self):
        with self.store.connection() as conn:
            return [{**dict(row), "metadata": json.loads(row["metadata"])}
                    for row in conn.execute("SELECT * FROM entities WHERE kind='web_fingerprint' ORDER BY source_url")]

    async def test_direct_observations_and_labeled_non_deployment_evidence(self):
        url = "https://portal.example.test/"
        direct = finding(cpe="cpe:2.3:a:vercel:next.js:15.0.1:*:*:*:*:*:*:*", version="15.0.1")
        inferred = finding("react", "facebook", "implied_dependency")
        integration = finding("okta", "okta", "csp_integration")
        response = self.response(url, "<html></html>", {"Content-Type": "text/html"}, cookie_names=("__cf_bm",))
        self.collector.http.get = AsyncMock(return_value=response)
        with patch("signalwatch.collectors.analyze_http_response", return_value=[direct, inferred, integration]) as analyze:
            result = await self.collector._crawl({"url": url})

        self.assertEqual((result["pages"], result["observations"]), (1, 1))
        analyze.assert_called_once_with(url, response.headers, "<html></html>", cookie_names=("__cf_bm",))
        self.assertEqual([(row["vendor"], row["product"], row["version"]) for row in self.observations()], [("vercel", "next.js", "15.0.1")])
        evidence = self.evidence()[0]
        self.assertEqual(evidence["metadata"]["fingerprints"], [direct, inferred, integration])
        self.assertEqual(evidence["metadata"]["company_context"], {"domain": "portal.example.test"})
        with self.store.connection() as conn:
            edge = conn.execute("SELECT from_id FROM edges WHERE to_id=? AND relation='has_public_evidence'", (evidence["id"],)).fetchone()
        self.assertEqual(edge[0], "domain:portal.example.test")
        self.assertEqual(self.collector.http.get.await_args.kwargs["max_bytes"], WEB_RESPONSE_BYTES)

    async def test_header_only_non_html_does_not_fingerprint_document_contents(self):
        url = "https://api.example.test/"
        body = '<meta name="generator" content="WordPress 6.5.2">'
        self.collector.http.get = AsyncMock(return_value=self.response(url, body, {"Content-Type": "application/json", "Server": "nginx/1.24.0"}))
        from signalwatch.web_fingerprints import analyze_http_response
        with patch("signalwatch.collectors.analyze_http_response", wraps=analyze_http_response) as analyze:
            result = await self.collector._crawl({"url": url})

        self.assertEqual(result["pages"], 1)
        self.assertEqual(analyze.call_args.args[2], "")
        self.assertEqual({row["product"] for row in self.observations()}, {"nginx"})
        self.assertEqual({row["vendor"] for row in self.observations()}, {"f5", "nginx"})

    async def test_html_analysis_and_link_discovery_use_bounded_sample(self):
        url = "https://www.example.test/"
        body = " " * WEB_HTML_SAMPLE_BYTES + '<meta name="generator" content="WordPress 6.5.2"><a href="/outside">outside</a>'
        self.collector.config.update(crawl_pages=2, crawl_depth=1)
        self.collector.http.get = AsyncMock(return_value=self.response(url, body, {"Content-Type": "text/html"}))
        with patch("signalwatch.collectors.analyze_http_response", return_value=[]) as analyze:
            result = await self.collector._crawl({"url": url})

        self.assertEqual(len(analyze.call_args.args[2].encode()), WEB_HTML_SAMPLE_BYTES)
        self.assertEqual(result["observations"], 0)
        self.collector.http.get.assert_awaited_once()

    async def test_redirect_replaces_old_page_evidence_without_moving_findings_to_origin(self):
        origin, final = "https://company.example.test/", "https://service.example.test/login"
        first = finding(cpe="cpe:2.3:a:vercel:next.js:15.0.1:*:*:*:*:*:*:*", version="15.0.1")
        self.collector.http.get = AsyncMock(return_value=self.response(origin, "<html></html>"))
        with patch("signalwatch.collectors.analyze_http_response", return_value=[first]):
            await self.collector._crawl({"url": origin})
        original_id = self.evidence()[0]["id"]
        self.collector.http.get = AsyncMock(side_effect=[self.response(origin, headers={"Location": final}, status=302), self.response(final, "<html></html>")])
        with patch("signalwatch.collectors.analyze_http_response", return_value=[first]):
            result = await self.collector._crawl({"url": origin})

        self.assertIsNone(result["error"])
        self.assertEqual({row["asset_id"] for row in self.observations()}, {"domain:service.example.test"})
        original, destination = self.evidence()
        self.assertEqual(original["id"], original_id)
        self.assertEqual(original["metadata"]["fingerprints"], [])
        self.assertEqual(destination["metadata"]["company_context"], {"domain": "service.example.test"})
        self.assertEqual(destination["metadata"]["fingerprints"], [first])
        self.assertEqual([call.args[0] for call in self.collector._can_fetch.await_args_list][-2:], [origin, final])

    async def test_failed_fetch_retains_last_successful_page_evidence(self):
        url = "https://portal.example.test/"
        direct = finding(cpe="cpe:2.3:a:vercel:next.js:15.0.1:*:*:*:*:*:*:*", version="15.0.1")
        self.collector.http.get = AsyncMock(return_value=self.response(url, "<html></html>"))
        with patch("signalwatch.collectors.analyze_http_response", return_value=[direct]):
            await self.collector._crawl({"url": url})
        self.collector.http.get = AsyncMock(side_effect=HTTPError(403, url))
        result = await self.collector._crawl({"url": url})
        self.assertEqual(result["pages"], 0)
        self.assertIn("HTTP 403", result["error"])
        self.assertEqual(len(self.observations()), 1)
        self.assertEqual(self.evidence()[0]["metadata"]["fingerprints"], [direct])

    async def test_304_rechecks_preserve_direct_observation_and_follow_cached_links(self):
        url = "https://portal.example.test/"
        self.store.ingest({"entities": [{"id": "company:example", "kind": "company", "name": "Example"},
                                         {"id": "domain:portal.example.test", "kind": "domain", "value": "portal.example.test"}],
                           "edges": [{"from_id": "company:example", "to_id": "domain:portal.example.test", "relation": "official_website"}]})
        body = '<a href="/next">Next page</a>'
        direct = finding(cpe="cpe:2.3:a:vercel:next.js:15.0.1:*:*:*:*:*:*:*", version="15.0.1")
        self.collector.http.get = AsyncMock(return_value=self.response(url, body))
        with patch("signalwatch.collectors.analyze_http_response", return_value=[direct]), patch("signalwatch.collectors.utcnow", return_value="2026-01-01T00:00:00Z"):
            await self.collector._crawl({"url": url})
        before = self.store.detail("company:example")["technographics"]["fingerprints"][0]
        observations = self.observations()
        self.collector.config.update(crawl_pages=2, crawl_depth=1)
        self.collector.http.get = AsyncMock(side_effect=[self.response(url, body, status=304), self.response(url + "next", "<html></html>")])
        with patch("signalwatch.collectors.analyze_http_response", return_value=[]) as analyze, patch("signalwatch.collectors.utcnow", return_value="2026-01-02T00:00:00Z"):
            result = await self.collector._crawl({"url": url})
        after = self.store.detail("company:example")["technographics"]["fingerprints"][0]
        self.assertIsNone(result["error"])
        self.assertEqual(result["pages"], 2)
        self.assertEqual(result["observations"], 0)
        self.assertEqual(self.observations(), observations)
        self.assertEqual(after["last_observed_at"], before["last_observed_at"])
        self.assertEqual(after["last_checked_at"], "2026-01-02T00:00:00Z")
        self.assertEqual(after["direct_observed_at"], before["direct_observed_at"])
        self.assertEqual(analyze.call_count, 1)
        self.assertEqual(analyze.call_args.args[0], url + "next")

    async def test_redirect_to_304_clears_origin_without_refreshing_destination(self):
        origin, final = "https://company.example.test/", "https://service.example.test/login"
        direct = finding(cpe="cpe:2.3:a:vercel:next.js:15.0.1:*:*:*:*:*:*:*", version="15.0.1")
        for url in (origin, final):
            self.collector.http.get = AsyncMock(return_value=self.response(url, "<html></html>"))
            with patch("signalwatch.collectors.analyze_http_response", return_value=[direct]):
                await self.collector._crawl({"url": url})
        previous = next(row for row in self.observations() if row["asset_id"] == "domain:service.example.test")
        self.collector.http.get = AsyncMock(side_effect=[self.response(origin, headers={"Location": final}, status=302), self.response(final, "<html></html>", status=304)])
        with patch("signalwatch.collectors.analyze_http_response", side_effect=AssertionError("Do not parse a 304 as new evidence")):
            result = await self.collector._crawl({"url": origin})
        self.assertIsNone(result["error"])
        self.assertEqual(self.observations(), [previous])
        self.assertEqual(next(row for row in self.evidence() if row["source_url"] == origin)["metadata"]["fingerprints"], [])

    def test_merge_preserves_explicit_version_and_legacy_nginx_alias(self):
        _, observations, _ = _web_fingerprints("https://EXAMPLE.test./", {"Server": "nginx/1.24.0"}, "")
        self.assertEqual({row["vendor"] for row in observations}, {"f5", "nginx"})
        self.assertEqual({row["version"] for row in observations}, {"1.24.0"})
        self.assertEqual({row["asset_id"] for row in observations}, {"domain:example.test"})

    def test_tomcat_header_is_not_misclassified_as_apache_http_server(self):
        findings, observations, _ = _web_fingerprints("https://example.test/", {"Server": "Apache Tomcat/10.1.0"}, "")
        self.assertIn("tomcat", {row["product"] for row in findings})
        self.assertEqual({row["product"] for row in observations}, {"tomcat"})

    async def test_query_and_cookie_values_are_not_copied_to_finding_evidence(self):
        url = "https://example.test/"
        body = '<script src="/jquery-3.7.1.min.js?access_token=fixture-secret"></script>'
        headers = CIMultiDict([("Content-Type", "text/html"), ("Server", "nginx/1.24.0 fixture-secret"),
                              ("Set-Cookie", "laravel_session=fixture-secret; Secure")])
        self.collector.http.get = AsyncMock(return_value=self.response(url, body, headers))
        await self.collector._crawl({"url": url})
        self.assertNotIn("fixture-secret", json.dumps(self.evidence()))
        self.assertNotIn("fixture-secret", json.dumps(self.observations()))

    async def test_real_parser_keeps_csp_and_dependencies_out_of_observations(self):
        url = "https://example.test/"
        body = '<meta name="generator" content="WordPress 6.5.2">'
        headers = {"Content-Type": "text/html", "Content-Security-Policy": "connect-src https://tenant.okta.com"}
        self.collector.http.get = AsyncMock(return_value=self.response(url, body, headers))
        await self.collector._crawl({"url": url})
        self.assertEqual({row["product"] for row in self.observations()}, {"wordpress"})
        self.assertEqual({row["status"] for row in self.evidence()[0]["metadata"]["fingerprints"]},
                         {"http_detected", "implied_dependency", "csp_integration"})

    async def test_catalog_loads_once_per_collection_and_reports_diagnostics(self):
        urls = ["https://first.example.test/", "https://second.example.test/"]
        self.collector.config.update(seed_urls=urls, source_targets=[], web_fingerprint_catalog=True)
        catalog_finding = {**finding("Example service", "unknown"), "vendor_name": "Unknown", "method": "projectdiscovery_wappalyzer"}
        catalog = SimpleNamespace(metadata={"apps": 12, "digest": "fixture-digest"},
                                  match=Mock(return_value=([catalog_finding], ["One catalog pattern timed out."])))
        self.collector.http.get = AsyncMock(side_effect=lambda url, **kwargs: self.response(url, "<html></html>"))
        with patch("signalwatch.collectors.load_catalog", new=AsyncMock(return_value=(catalog, ["Using cached catalog."]))) as load:
            result = await self.collector.collect_web()

        load.assert_awaited_once_with(self.collector.http, self.temp.name)
        self.assertEqual(catalog.match.call_count, 2)
        self.assertEqual(result["fingerprints"], 2)
        self.assertEqual(result["observations"], 0)
        self.assertEqual(result["fingerprint_catalog"]["digest"], "fixture-digest")
        self.assertEqual(result["fingerprint_catalog"]["diagnostics"], ["Using cached catalog.", "One catalog pattern timed out."])

    def test_catalog_direct_detection_overrides_implication_without_replacing_curated_identity(self):
        direct = finding("next.js", "vercel", cpe="cpe:2.3:a:vercel:next.js:15.0.1:*:*:*:*:*:*:*", version="15.0.1")
        inferred = finding("React", "facebook", "implied_dependency")
        catalog = SimpleNamespace(match=Mock(return_value=([
            finding("next.js", ""), finding("React", ""), finding("Extra service", "")
        ], [])))
        with patch("signalwatch.collectors.analyze_http_response", return_value=[direct, inferred]):
            findings, observations, _ = _web_fingerprints("https://example.test/", {}, "", catalog=catalog)

        self.assertEqual(len(findings), 3)
        self.assertTrue(all(row["status"] == "http_detected" for row in findings))
        self.assertEqual(findings[0], direct)
        self.assertEqual([(row["vendor"], row["product"]) for row in observations], [("vercel", "next.js")])

    def test_combined_catalog_findings_are_bounded_and_report_truncation(self):
        direct = finding("next.js", "vercel")
        catalog = SimpleNamespace(match=Mock(return_value=([finding(f"Catalog {index}", "") for index in range(100)], [])))
        with patch("signalwatch.collectors.analyze_http_response", return_value=[direct]):
            findings, observations, diagnostics = _web_fingerprints("https://example.test/", {}, "", catalog=catalog)
        self.assertEqual(len(findings), 100)
        self.assertEqual(findings[0], direct)
        self.assertEqual(observations, [])
        self.assertIn("capped at 100", diagnostics[0])
