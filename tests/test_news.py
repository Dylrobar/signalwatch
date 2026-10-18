import asyncio
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock
from xml.sax.saxutils import escape

from signalwatch.collectors import Collector
from signalwatch.config import DEFAULTS
from signalwatch.extract import parse_feed
from signalwatch.http import FetchResult, HTTPError
from signalwatch.store import Store


def rss(summary="", title="Security update", url="https://vendor.example/advisory"):
    item = f"<item><title>{escape(title)}</title><link>{escape(url)}</link><description>{escape(summary)}</description></item>" if summary or title else ""
    return f'<rss version="2.0"><channel><title>News</title>{item}</channel></rss>'


class NewsStore:
    def __init__(self):
        self.state = {}
        self.batches = []

    def source_state(self, name):
        return self.state.get(name, {})

    def update_source(self, name, **fields):
        self.state.setdefault(name, {}).update(fields)

    def ingest(self, batch):
        self.batches.append(batch)


class FeedFormatTests(unittest.TestCase):
    def test_rejects_html_and_accepts_empty_rss_atom(self):
        bodies = [
            ('<html><head><title>Access denied</title></head><body>Challenge required</body></html>', False),
            ('<html><body>Maintenance</body></html>', False),
            ('<rss version="2.0"><channel><title>Empty</title></channel></rss>', True),
            ('<feed xmlns="http://www.w3.org/2005/Atom"><title>Empty</title><id>urn:empty</id><updated>2026-10-18T00:00:00Z</updated></feed>', True),
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "feed"
            for body, valid in bodies:
                with self.subTest(body=body):
                    path.write_text(body)
                    if valid:
                        self.assertEqual(parse_feed(path, "Source", "https://news.example/feed"), [])
                    else:
                        with self.assertRaisesRegex(ValueError, "RSS or Atom"):
                            parse_feed(path, "Source", "https://news.example/feed")


class NewsCollectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.store = NewsStore()
        self.config = {**DEFAULTS, "cache_dir": str(self.root / "cache"), "news_concurrency": 2, "feeds": []}
        self.collector = Collector(self.config, self.store)

    def tearDown(self):
        self.directory.cleanup()

    def result(self, name, body, status=200):
        path = self.root / name
        path.write_text(body)
        return FetchResult(path, status, {}, f"https://news.example/{name}", status != 304, hashlib.sha256(body.encode()).hexdigest())

    async def test_workers_merge_duplicates_and_record_partial_health(self):
        names = ["detailed", "headlines", "blocked", "empty"]
        self.config["feeds"] = [{"name": name, "url": f"https://news.example/{name}"} for name in names]
        results = {
            "detailed": self.result("detailed", rss("CVE-2026-12345 affects this product. " * 5)),
            "headlines": self.result("headlines", rss("Brief report", "CVE-2026-23456 advisory")),
            "blocked": self.result("blocked", "<html><body>Access denied</body></html>"),
            "empty": self.result("empty", rss("", "")),
        }
        active = 0
        maximum = 0
        async def get(url):
            nonlocal active, maximum
            active += 1
            maximum = max(maximum, active)
            try:
                await asyncio.sleep(.01)
                return results[url.rsplit("/", 1)[-1]]
            finally:
                active -= 1
        self.collector.http.get = get
        counts = await self.collector.collect_news()
        self.assertEqual(maximum, 2)
        self.assertEqual({key: counts[key] for key in ("configured", "attempted", "successful", "unchanged", "failed", "articles")},
                         {"configured": 4, "attempted": 4, "successful": 3, "unchanged": 0, "failed": 1, "articles": 1})
        self.assertEqual(len(self.store.batches), 1)
        article = self.store.batches[0]["articles"][0]
        self.assertEqual(article["cves"], ["CVE-2026-12345", "CVE-2026-23456"])
        self.assertEqual(article["source"], "detailed")
        self.assertEqual(article["feed_sources"], ["detailed", "headlines"])
        self.assertEqual(article["feed_urls"], ["https://news.example/detailed", "https://news.example/headlines"])
        self.assertEqual(article["feed_records"]["https://news.example/headlines"]["cves"], ["CVE-2026-23456"])
        state = self.store.state["news"]
        self.assertNotIn("https://news.example/blocked", {key for key, digest in state["feed_digests"].items() if digest})
        blocked = state["feed_health"]["https://news.example/blocked"]
        self.assertEqual(blocked["status"], "error")
        self.assertIsNone(blocked["last_success"])
        self.assertIn("RSS or Atom", blocked["error"])
        self.assertEqual(state["feed_health"]["https://news.example/empty"]["articles"], 0)
        self.assertEqual(state["coverage"]["failed"], 1)
        self.assertTrue(state["coverage"]["started_at"])
        self.assertTrue(state["coverage"]["finished_at"])

    async def test_unchanged_validated_feed_skips_ingestion_and_keeps_entry_count(self):
        url = "https://news.example/feed"
        self.config["feeds"] = [{"name": "Feed", "url": url}]
        first = self.result("feed", rss("CVE-2026-12345 fixed"))
        self.collector.http.get = AsyncMock(return_value=first)
        await self.collector.collect_news()
        self.collector.http.get.return_value = FetchResult(first.path, 304, {}, url, False, first.digest)
        counts = await self.collector.collect_news()
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(counts["successful"], 1)
        self.assertEqual(counts["articles"], 0)
        self.assertEqual(len(self.store.batches), 1)
        health = self.store.state["news"]["feed_health"][url]
        self.assertEqual(health["status"], "unchanged")
        self.assertEqual(health["articles"], 1)
        self.assertTrue(health["last_attempt"])
        self.assertTrue(health["last_success"])
        self.assertIsNone(health["error"])

    async def test_legacy_digest_does_not_hide_unvalidated_html(self):
        url = "https://news.example/feed"
        self.config["feeds"] = [{"name": "Feed", "url": url}]
        result = self.result("feed", "<html><body>Maintenance</body></html>", 304)
        self.store.state["news"] = {"feed_digests": {url: result.digest}}
        self.collector.http.get = AsyncMock(return_value=result)
        with self.assertRaisesRegex(RuntimeError, "RSS or Atom"):
            await self.collector.collect_news()
        self.assertEqual(self.store.state["news"]["coverage"]["failed"], 1)
        self.assertEqual(self.store.state["news"]["feed_health"][url]["status"], "error")
        self.assertEqual(self.store.batches, [])

    async def test_failed_refresh_preserves_last_success_and_entry_count(self):
        url = "https://news.example/feed"
        self.config["feeds"] = [{"name": "Feed", "url": url}]
        self.collector.http.get = AsyncMock(return_value=self.result("feed", rss("CVE-2026-12345 fixed")))
        await self.collector.collect_news()
        prior = dict(self.store.state["news"]["feed_health"][url])
        self.collector.http.get = AsyncMock(side_effect=HTTPError(503, url))
        with self.assertRaisesRegex(RuntimeError, "HTTP 503"):
            await self.collector.collect_news()
        health = self.store.state["news"]["feed_health"][url]
        self.assertEqual(health["last_success"], prior["last_success"])
        self.assertEqual(health["articles"], 1)
        self.assertEqual(health["status"], "error")
        self.assertEqual(self.store.state["news"]["coverage"]["successful"], 0)

    async def test_ingestion_failure_does_not_advance_digest_or_health_checkpoint(self):
        url = "https://news.example/feed"
        self.config["feeds"] = [{"name": "Feed", "url": url}]
        self.collector.http.get = AsyncMock(return_value=self.result("feed", rss("CVE-2026-12345 fixed")))
        self.collector.emit = AsyncMock(side_effect=RuntimeError("Database failure"))
        with self.assertRaisesRegex(RuntimeError, "Database failure"):
            await self.collector.collect_news()
        self.assertNotIn("news", self.store.state)

    async def test_no_configured_feeds_reports_zero_attempts(self):
        self.collector.http.get = AsyncMock()
        counts = await self.collector.collect_news()
        self.assertEqual({key: counts[key] for key in ("configured", "attempted", "successful", "unchanged", "failed")},
                         {"configured": 0, "attempted": 0, "successful": 0, "unchanged": 0, "failed": 0})
        self.collector.http.get.assert_not_awaited()

    async def test_cross_cycle_merge_preserves_unchanged_feed_and_applies_corrections(self):
        store = Store(self.root / "news.sqlite")
        collector = Collector(self.config, store)
        self.config["feeds"] = [{"name": name, "url": f"https://news.example/{name}"} for name in ("detailed", "headlines")]
        results = {
            "detailed": self.result("detailed", rss("CVE-2026-12345 affects this product. " * 5)),
            "headlines": self.result("headlines", rss("CVE-2026-23456 fixed")),
        }
        async def get(url):
            return results[url.rsplit("/", 1)[-1]]
        collector.http.get = get
        await collector.collect_news()
        self.assertEqual(store.articles()["items"][0]["cves"], ["CVE-2026-12345", "CVE-2026-23456"])
        results["headlines"] = self.result("headlines", rss("Corrected headline without CVE reference"))
        counts = await collector.collect_news()
        article = store.articles()["items"][0]
        self.assertEqual(counts["unchanged"], 1)
        self.assertEqual(article["cves"], ["CVE-2026-12345"])
        self.assertIn("CVE-2026-12345", article["summary"])
        self.assertEqual(article["feed_sources"], ["detailed", "headlines"])
        results["detailed"] = self.result("detailed", rss("Corrected detailed report without CVE reference. " * 5))
        await collector.collect_news()
        article = store.articles()["items"][0]
        self.assertEqual(article["cves"], [])
        with store.connection() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM article_links").fetchone()[0], 0)
