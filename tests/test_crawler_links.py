import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

from signalwatch.collectors import Collector, crawl_link_url
from signalwatch.config import DEFAULTS
from signalwatch.http import FetchResult, HTTPError


class CrawlLinkTests(unittest.TestCase):
    def test_email_protection_anchors_are_not_pages(self):
        for href in (
            "/cdn-cgi/l/email-protection",
            "/cdn-cgi/l/email-protection#encoded-address",
            "/cdn-cgi/l/email-protection/?address=encoded",
            "https://example.test/cdn-cgi/l/email-protection#encoded-address",
        ):
            with self.subTest(href=href):
                self.assertEqual(crawl_link_url("https://example.test/", href), "")

    def test_nonweb_and_malformed_links_are_ignored(self):
        for href in (
            "mailto:team@example.test",
            "tel:+15551234567",
            "javascript:void(0)",
            "data:text/html,hello",
            "ftp://example.test/readme",
            "//[broken/path",
            "https://example.test:bad-port/path",
        ):
            with self.subTest(href=href):
                self.assertEqual(crawl_link_url("https://example.test/", href), "")

    def test_valid_page_paths_fragments_and_queries_are_canonicalized(self):
        for href, expected in (
            (" ../about#team ", "https://example.test/about"),
            ("?page=2#results", "https://example.test/docs/index?page=2"),
            ("#section", "https://example.test/docs/index"),
            ("//example.test/status", "https://example.test/status"),
            ("http://example.test/status", "http://example.test/status"),
            ("/cdn-cgi/l/email-protection-guide", "https://example.test/cdn-cgi/l/email-protection-guide"),
            ("/help?topic=email-protection", "https://example.test/help?topic=email-protection"),
        ):
            with self.subTest(href=href):
                self.assertEqual(crawl_link_url("https://example.test/docs/index", href), expected)


class CrawlDiscoveredLinkTests(unittest.IsolatedAsyncioTestCase):
    async def test_junk_links_do_not_abort_or_use_the_page_budget(self):
        root = "https://example.test/"
        html = '''<html><body>
            <a href="/cdn-cgi/l/email-protection#encoded">Contact</a>
            <a href="//[broken/path">Malformed</a>
            <a href="mailto:team@example.test">Email</a>
            <a href="/about?page=2#team">About</a>
            <a href="/about?page=2#history">About again</a>
            <a href="https://other.test/">Other site</a>
            <a href="/download.pdf">Download</a>
            </body></html>'''
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "page.html"
            path.write_text(html)
            store = SimpleNamespace(finish_url=Mock())
            collector = Collector({**DEFAULTS, "cache_dir": folder, "crawl_pages": 2, "crawl_depth": 1}, store)
            collector._resolve = AsyncMock(return_value=([], []))
            collector._can_fetch = AsyncMock(return_value=True)
            collector.emit = AsyncMock()

            async def fetch(url, **kwargs):
                return FetchResult(path, 200, {"Content-Type": "text/html"}, url, True, "fixture")

            collector.http.get = AsyncMock(side_effect=fetch)
            result = await collector._crawl({"url": root})

        requested = [call.args[0] for call in collector.http.get.await_args_list]
        self.assertEqual(requested, [root, root + "about?page=2"])
        self.assertEqual(result["pages"], 2)
        self.assertIsNone(result["error"])
        store.finish_url.assert_called_once_with(root, error=None)

    async def test_denied_robots_still_prevent_page_fetches(self):
        root = "https://example.test/"
        for status in (401, 403):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as folder:
                store = SimpleNamespace(finish_url=Mock())
                collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
                collector._resolve = AsyncMock(return_value=([], []))
                collector.emit = AsyncMock()
                collector.http.get = AsyncMock(side_effect=HTTPError(status, root + "robots.txt"))
                result = await collector._crawl({"url": root})
                collector.http.get.assert_awaited_once_with(root + "robots.txt", max_bytes=2 * 1024 * 1024)
                self.assertEqual(result["pages"], 0)
                self.assertIn("robots.txt disallows", result["error"])


if __name__ == "__main__":
    unittest.main()
