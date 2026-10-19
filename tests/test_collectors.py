import asyncio
import gzip
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock
from pathlib import Path

from aiohttp import web

from signalwatch.collectors import Collector, KEV_MIRROR_URL, KEV_URL, github_timestamp, next_link, parse_github
from signalwatch.config import DEFAULTS
from signalwatch.extract import canonical_url, cpe_parts, fingerprint_page, parse_feed, parse_nvd, read_json
from signalwatch.http import FetchResult, HTTPError, PublicHTTP, PublicRequestError, retry_delay


class CaptureStore:
    def __init__(self):
        self.batches = []
        self.sources = {}
        self.urls = []
        self.finished = {}

    def ingest(self, batch):
        self.batches.append(batch)

    def source_state(self, name):
        return self.sources.get(name, {})

    def update_source(self, name, **fields):
        self.sources.setdefault(name, {}).update(fields)

    def enqueue_url(self, url, **fields):
        self.urls.append(url)

    def company_crawl_candidates(self, *args):
        return []

    def finish_url(self, url, error=None):
        self.finished[url] = error


class ParsingTests(unittest.TestCase):
    def test_nvd_nested_conditions_excludes_nonvulnerable_and_preserves_ranges(self):
        cve = {
            "id": "CVE-2026-12345", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "test"}],
            "metrics": {"cvssMetricV31": [{"type": "Secondary", "cvssData": {"baseScore": 8.0}}, {"type": "Primary", "cvssData": {"baseScore": 9.8}}]},
            "configurations": [{"operator": "AND", "nodes": [
                {"operator": "OR", "cpeMatch": [{"vulnerable": True, "criteria": r"cpe:2.3:a:vendor:foo\:bar:*:*:*:*:*:*:*:*", "versionEndExcluding": "4.2"}]},
                {"cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*"}]},
            ]}],
        }
        result = parse_nvd(cve)
        self.assertEqual(result["severity"], 9.8)
        self.assertEqual(len(result["affected"]), 1)
        self.assertEqual(result["affected"][0]["product"], "foo:bar")
        self.assertEqual(result["affected"][0]["versionEndExcluding"], "4.2")
        self.assertEqual(result["configurations"], cve["configurations"])

    def test_gzip_nvd_stream_batches_and_rejected(self):
        store = CaptureStore()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "feed.gz"
            records = [{"cve": {"id": f"CVE-2026-{10000 + index}", "vulnStatus": "Rejected" if index == 500 else "Analyzed"}} for index in range(501)]
            with gzip.open(path, "wt") as stream:
                json.dump({"vulnerabilities": records}, stream)
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            result = collector._ingest_nvd_path(path)
            self.assertEqual(result["advisories"], 501)
            self.assertEqual([len(batch["advisories"]) for batch in store.batches], [500, 1])
            self.assertTrue(store.batches[-1]["advisories"][0]["rejected"])
            self.assertEqual(len(read_json(path)["vulnerabilities"]), 501)

    def test_rss_guid_canonical_link_and_cve_dedup(self):
        feed = '''<rss version="2.0"><channel><title>News</title><item><guid>urn:story:1</guid><title>CVE-2026-12345 fixed</title><link>https://news.example/story?utm_source=x&amp;id=2#fragment</link><description>&lt;p&gt;CVE-2026-12345 vulnerability&lt;/p&gt;</description><pubDate>Sun, 18 Oct 2026 12:00:00 GMT</pubDate></item></channel></rss>'''
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "feed.xml"
            path.write_text(feed)
            articles = parse_feed(path, "News", "https://news.example/rss")
        self.assertEqual(articles[0]["url"], "https://news.example/story?id=2")
        self.assertEqual(articles[0]["guid"], "urn:story:1")
        self.assertEqual(articles[0]["cves"], ["CVE-2026-12345"])
        self.assertEqual(articles[0]["published"], "2026-10-18T12:00:00+00:00")

    def test_fingerprints_require_deployment_evidence_and_extract_versions(self):
        html = '<html><head><meta name="generator" content="WordPress 6.7.2"><script src="/js/jquery-3.7.1.min.js"></script></head><body>Microsoft Windows Cisco Fortinet</body></html>'
        observations = fingerprint_page("https://host.example/", html, {"Server": "nginx/1.26.3", "X-Powered-By": "PHP/8.3.5"})
        products = {(row["vendor"], row["product"]): row["version"] for row in observations}
        self.assertEqual(products[("f5", "nginx")], "1.26.3")
        self.assertEqual(products[("php", "php")], "8.3.5")
        self.assertEqual(products[("wordpress", "wordpress")], "6.7.2")
        self.assertEqual(products[("jquery", "jquery")], "3.7.1")
        self.assertEqual(products[("nginx", "nginx")], "1.26.3")
        self.assertEqual(len(products), 5)
        self.assertTrue(all(row["asset_id"] == "domain:host.example" for row in observations))

    def test_github_alias_ranges_and_withdrawal(self):
        record = parse_github({"ghsa_id": "GHSA-2345-6789-abcd", "cve_id": "CVE-2026-12345", "withdrawn_at": "2026-10-18", "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "@example/parser"}, "vulnerable_version_range": ">= 1.0.0, < 1.2.3", "first_patched_version": "1.2.3"}]})
        self.assertIn("CVE-2026-12345", record["aliases"])
        self.assertTrue(record["rejected"])
        self.assertEqual(record["affected"][0]["version_range"], ">= 1.0.0, < 1.2.3")
        self.assertEqual(next_link('<https://api.github.com/advisories?after=next>; rel="next", <https://api.github.com/advisories?before=prev>; rel="prev"'), "https://api.github.com/advisories?after=next")

    def test_epss_gzip_metadata(self):
        store = CaptureStore()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "epss.gz"
            with gzip.open(path, "wt") as stream:
                stream.write("#model_version:v2025.03.14,score_date:2026-10-18T00:00:00+0000\ncve,epss,percentile\nCVE-2026-12345,0.5,0.99\n")
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            count, date = collector._ingest_epss(path)
        self.assertEqual(count, 1)
        self.assertTrue(date.startswith("2026-10-18"))
        self.assertEqual(store.batches[0]["epss"][0]["epss"], 0.5)

    def test_github_timestamp_uses_utc_seconds(self):
        self.assertEqual(github_timestamp("2026-10-16T06:22:31.904005+00:00"), "2026-10-16T06:22:31Z")
        self.assertEqual(github_timestamp("2026-10-16T02:22:31-04:00"), "2026-10-16T06:22:31Z")

    def test_url_and_retry_normalization(self):
        self.assertEqual(canonical_url("HTTPS://EXAMPLE.COM:443/a?utm_source=x&x=1#y"), "https://example.com/a?x=1")
        self.assertEqual(canonical_url("javascript:alert(1)"), "")
        self.assertEqual(retry_delay("120", 0), 120)
        self.assertEqual(retry_delay("0", 0), 0)
        self.assertIsNone(cpe_parts("not-cpe"))


class HTTPTests(unittest.IsolatedAsyncioTestCase):
    async def test_persistent_conditional_cache_and_reused_payload(self):
        calls = []
        async def handler(request):
            calls.append(request.headers.get("If-None-Match"))
            if calls[-1] == '"version1"':
                return web.Response(status=304)
            return web.json_response({"value": "test"}, headers={"ETag": '"version1"'})
        app = web.Application()
        app.router.add_get("/feed", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        try:
            with tempfile.TemporaryDirectory() as folder:
                config = {**DEFAULTS, "cache_dir": folder}
                async with PublicHTTP(config) as http:
                    first = await http.get(f"http://127.0.0.1:{port}/feed")
                    self.assertTrue(first.changed)
                    self.assertEqual(read_json(first.path)["value"], "test")
                async with PublicHTTP(config) as http:
                    second = await http.get(f"http://127.0.0.1:{port}/feed")
                    self.assertEqual(second.status, 304)
                    self.assertFalse(second.changed)
                    self.assertEqual(first.digest, second.digest)
                    self.assertEqual(read_json(second.path)["value"], "test")
            self.assertEqual(calls, [None, '"version1"'])
        finally:
            await runner.cleanup()


class CrawlTests(unittest.IsolatedAsyncioTestCase):
    async def test_redirect_robots_checked_before_target_fetch(self):
        requested = []
        async def handler(request):
            requested.append(request.path)
            if request.path == "/robots.txt":
                return web.Response(text="User-agent: *\nDisallow: /blocked\n")
            if request.path == "/":
                raise web.HTTPFound("/blocked")
            return web.Response(text='<meta name="generator" content="WordPress 6.7.2">', content_type="text/html")
        app = web.Application()
        app.router.add_get("/{path:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/"
        try:
            with tempfile.TemporaryDirectory() as folder:
                store = CaptureStore()
                async with Collector({**DEFAULTS, "cache_dir": folder}, store) as collector:
                    result = await collector._crawl({"url": url})
                self.assertEqual(result["pages"], 0)
                self.assertIn("robots.txt disallows", result["error"])
                self.assertNotIn("/blocked", requested)
                self.assertIn("robots.txt disallows", store.finished[url])
        finally:
            await runner.cleanup()


class NVDContinuityTests(unittest.IsolatedAsyncioTestCase):
    async def test_bulk_feed_access_errors_use_api_only_without_active_cooldown(self):
        for status, retry_after in ((403, None), (404, None), (403, 120), (404, 0.5)):
            with self.subTest(status=status, retry_after=retry_after), tempfile.TemporaryDirectory() as folder:
                store = CaptureStore()
                store.sources["nvd"] = {"initialized": True, "watermark": datetime.now(timezone.utc).isoformat()}
                previous_state = dict(store.sources["nvd"])
                collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
                error = HTTPError(status, "https://nvd.nist.gov/feed", retry_after=retry_after)
                collector._nvd_feed = AsyncMock(side_effect=error)
                collector._nvd_api = AsyncMock(return_value={"advisories": 7, "mode": "api_fallback"})
                if retry_after is None:
                    self.assertEqual(await collector.collect_nvd(), {"advisories": 7, "mode": "api_fallback"})
                    collector._nvd_api.assert_awaited_once_with(previous_state)
                else:
                    with self.assertRaises(HTTPError) as raised:
                        await collector.collect_nvd()
                    self.assertIs(raised.exception, error)
                    collector._nvd_api.assert_not_awaited()
                    self.assertEqual(store.sources["nvd"], previous_state)
                collector._nvd_feed.assert_awaited_once_with("modified", None)

    async def test_stale_watermark_catches_up_before_modified_feed(self):
        store = CaptureStore()
        store.sources["nvd"] = {"initialized": True, "watermark": (datetime.now(timezone.utc) - timedelta(days=9)).isoformat()}
        with tempfile.TemporaryDirectory() as folder:
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            collector._nvd_api = AsyncMock(return_value={"advisories": 7})
            collector._nvd_feed = AsyncMock(return_value=({"advisories": 2, "entities": 1}, "sha"))
            result = await collector.collect_nvd()
            collector._nvd_api.assert_awaited_once()
            collector._nvd_feed.assert_awaited_once_with("modified", None)
            self.assertEqual(result["advisories"], 9)
            self.assertEqual(result["backfill_advisories"], 7)
            self.assertTrue(result["catch_up"])

    async def test_fresh_watermark_uses_bulk_feed_without_api(self):
        store = CaptureStore()
        store.sources["nvd"] = {"initialized": True, "watermark": datetime.now(timezone.utc).isoformat()}
        with tempfile.TemporaryDirectory() as folder:
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            collector._nvd_api = AsyncMock()
            collector._nvd_feed = AsyncMock(return_value=({"advisories": 0, "entities": 0}, "sha"))
            await collector.collect_nvd()
            collector._nvd_api.assert_not_awaited()


class SourceSnapshotTests(unittest.IsolatedAsyncioTestCase):
    async def test_kev_uses_official_mirror_after_proxy_or_direct_transport_failure(self):
        for error in (PublicRequestError("Proxy HTTP 403", KEV_URL),
                      PublicRequestError("Connection timed out", KEV_URL),
                      PublicRequestError("DNS lookup failed", KEV_URL),
                      HTTPError(404, KEV_URL)):
            with self.subTest(error=str(error)), tempfile.TemporaryDirectory() as folder:
                records = [{"cveID": "CVE-2026-12345"}]
                path = Path(folder) / "kev.json"
                path.write_text(json.dumps({"count": 1, "catalogVersion": "2026.10.19", "vulnerabilities": records}))
                store = CaptureStore()
                collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
                collector.http.get = AsyncMock(side_effect=[
                    error, FetchResult(path, 200, {}, KEV_MIRROR_URL, True, "mirror-digest"),
                ])

                self.assertEqual(await collector.collect_kev(), {"kev": 1})

                self.assertEqual([call.args[0] for call in collector.http.get.await_args_list], [KEV_URL, KEV_MIRROR_URL])
                self.assertEqual(store.batches, [{"kev_snapshot": records}])
                self.assertEqual(store.sources["kev"], {"digest": "mirror-digest", "catalog_version": "2026.10.19"})

    async def test_kev_retains_origin_and_gateway_retry_after_without_fetching_mirror(self):
        for error in (HTTPError(403, KEV_URL, retry_after=120),
                      HTTPError(429, KEV_URL, retry_after=0.5),
                      HTTPError(503, KEV_URL, retry_after=120),
                      PublicRequestError("Proxy HTTP 403", KEV_URL, retry_after=120),
                      PublicRequestError("Proxy HTTP 429", KEV_URL, retry_after=120)):
            with self.subTest(error=str(error)), tempfile.TemporaryDirectory() as folder:
                store = CaptureStore()
                store.sources["kev"] = {"digest": "previous"}
                collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
                collector.http.get = AsyncMock(side_effect=error)

                with self.assertRaises(type(error)) as raised:
                    await collector.collect_kev()

                self.assertIs(raised.exception, error)
                collector.http.get.assert_awaited_once_with(KEV_URL)
                self.assertEqual(store.sources["kev"], {"digest": "previous"})
                self.assertEqual(store.batches, [])

    async def test_kev_does_not_mask_cancellation_or_ingestion_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            store = CaptureStore()
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            collector.http.get = AsyncMock(side_effect=asyncio.CancelledError)
            with self.assertRaises(asyncio.CancelledError):
                await collector.collect_kev()
            collector.http.get.assert_awaited_once_with(KEV_URL)

            path = Path(folder) / "kev.json"
            path.write_text(json.dumps({"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-12345"}]}))
            collector.http.get = AsyncMock(return_value=FetchResult(path, 200, {}, KEV_URL, True, "valid"))
            collector.emit = AsyncMock(side_effect=RuntimeError("ingestion failed"))
            with self.assertRaisesRegex(RuntimeError, "ingestion failed"):
                await collector.collect_kev()
            collector.http.get.assert_awaited_once_with(KEV_URL)
            self.assertEqual(store.sources, {})

    async def test_kev_validated_snapshot_and_invalid_response_preserve_checkpoint(self):
        store = CaptureStore()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "kev.json"
            path.write_text(json.dumps({"count": 1, "vulnerabilities": [{"cveID": "CVE-2026-12345"}]}))
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            collector.http.get = AsyncMock(return_value=FetchResult(path, 200, {}, "https://www.cisa.gov/", True, "valid"))
            await collector.collect_kev()
            self.assertIn("kev_snapshot", store.batches[0])
            path.write_text(json.dumps({"count": 1, "vulnerabilities": [{"cveID": "invalid"}]}))
            collector.http.get = AsyncMock(return_value=FetchResult(path, 200, {}, "https://www.cisa.gov/", True, "invalid"))
            with self.assertRaises(ValueError):
                await collector.collect_kev()
            collector.http.get.assert_awaited_once_with(KEV_URL)
            self.assertEqual(len(store.batches), 1)
            self.assertEqual(store.sources["kev"]["digest"], "valid")

    async def test_wikidata_public_ownership_evidence_and_incremental_cursor(self):
        store = CaptureStore()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "wiki.json"
            path.write_text(json.dumps({"results": {"bindings": [
                {"company": {"value": "http://www.wikidata.org/entity/Q123"}, "companyLabel": {"value": "Example Company"}, "website": {"value": "https://example.com"}},
                {"company": {"value": "http://www.wikidata.org/entity/Q124"}, "companyLabel": {"value": "Other Company"}, "website": {"value": "https://other.example"}},
            ]}}))
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            collector.http.get = AsyncMock(return_value=FetchResult(path, 200, {}, "https://query.wikidata.org/", True, "wiki"))
            counts = await collector.collect_wikidata()
            self.assertEqual(counts["companies"], 2)
            self.assertEqual(store.sources["wikidata"]["cursor"], "http://www.wikidata.org/entity/Q124")
            self.assertEqual(store.batches[0]["edges"][0]["relation"], "official_website")
            self.assertEqual(store.batches[0]["edges"][0]["source_url"], "http://www.wikidata.org/entity/Q123")
            self.assertNotIn("observations", store.batches[0])
            path.write_text(json.dumps({"results": {"bindings": []}}))
            await collector.collect_wikidata()
            self.assertEqual(store.sources["wikidata"]["type_index"], 1)
            self.assertEqual(store.sources["wikidata"]["cursor"], "")
