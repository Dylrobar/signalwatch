import json
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock

from signalwatch.collectors import Collector
from signalwatch.config import DEFAULTS
from signalwatch.http import FetchResult, HTTPError
from signalwatch.store import Store


class WikidataBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_rate_limit_persists_retry_after_without_advancing_cursor(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "db.sqlite")
            store.update_source("wikidata", cursor="http://www.wikidata.org/entity/Q123", cursor_website="https://a.example/", type_index=1)
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            collector.http.get = AsyncMock(side_effect=HTTPError(429, "https://query.wikidata.org/sparql?query=long", retry_after=7200))
            start = time.time()
            with self.assertRaises(HTTPError):
                await collector.collect_wikidata()
            state = store.source_state("wikidata")
            self.assertEqual(state["cursor"], "http://www.wikidata.org/entity/Q123")
            self.assertEqual(state["cursor_website"], "https://a.example/")
            self.assertEqual(state["type_index"], 1)
            self.assertEqual(state["retry_failures"], 1)
            retry = datetime.fromisoformat(state["retry_at"]).timestamp()
            self.assertGreaterEqual(retry, start + 7200)
            self.assertLess(retry, time.time() + 7201)
            self.assertEqual(collector.http.get.await_args.kwargs["max_attempts"], 1)
            restarted = Collector({**DEFAULTS, "cache_dir": folder}, store)
            restarted.http.get = AsyncMock()
            with self.assertRaises(HTTPError) as raised:
                await restarted.collect_wikidata()
            self.assertEqual(raised.exception.status, 429)
            restarted.http.get.assert_not_awaited()
            self.assertEqual(store.source_state("wikidata"), state)

    async def test_repeated_throttle_increases_backoff_and_keeps_progress(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "db.sqlite")
            store.update_source("wikidata", cursor="saved", retry_failures=1, retry_at="2000-01-01T00:00:00+00:00")
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            collector.http.get = AsyncMock(side_effect=HTTPError(503, "https://query.wikidata.org/sparql"))
            start = time.time()
            with self.assertRaises(HTTPError):
                await collector.collect_wikidata()
            state = store.source_state("wikidata")
            self.assertEqual(state["retry_failures"], 2)
            self.assertEqual(state["retry_status"], 503)
            self.assertEqual(state["cursor"], "saved")
            self.assertGreaterEqual(datetime.fromisoformat(state["retry_at"]).timestamp(), start + 7200)

    async def test_success_clears_expired_retry_state(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "db.sqlite")
            store.update_source("wikidata", retry_failures=3, retry_status=429, retry_at="2000-01-01T00:00:00+00:00")
            collector = Collector({**DEFAULTS, "cache_dir": folder}, store)
            path = Path(folder) / "page.json"
            path.write_text(json.dumps({"results": {"bindings": []}}))
            collector.http.get = AsyncMock(return_value=FetchResult(path, 200, {}, "https://query.wikidata.org/sparql", True, "wiki"))
            await collector.collect_wikidata()
            state = store.source_state("wikidata")
            self.assertIsNone(state["retry_at"])
            self.assertIsNone(state["retry_status"])
            self.assertEqual(state["retry_failures"], 0)
            self.assertEqual(state["type_index"], 1)

    async def test_company_website_pair_cursor_and_discovery_limit(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "db.sqlite")
            config = {**DEFAULTS, "cache_dir": folder, "wikidata_batch": 1, "max_discovered_domains": 1}
            collector = Collector(config, store)
            path = Path(folder) / "page.json"
            company = "http://www.wikidata.org/entity/Q123"
            def page(website):
                path.write_text(json.dumps({"results": {"bindings": [{"company": {"value": company}, "website": {"value": website}}]}}))
            collector.http.get = AsyncMock(return_value=FetchResult(path, 200, {}, "https://query.wikidata.org/", True, "wiki"))
            page("https://a.example/")
            first = await collector.collect_wikidata()
            self.assertEqual(first["queued"], 1)
            self.assertEqual(store.source_state("wikidata")["cursor_website"], "https://a.example/")
            page("https://b.example/")
            second = await collector.collect_wikidata()
            query = collector.http.get.await_args.kwargs["params"]["query"]
            self.assertIn('STR(?company) = "' + company + '"', query)
            self.assertIn('STR(?website) > "https://a.example/"', query)
            self.assertIn("ORDER BY STR(?company) STR(?website)", query)
            self.assertEqual(second["queue_rejected"], 1)
            self.assertEqual(store.source_state("wikidata")["cursor_website"], "https://b.example/")
            self.assertEqual(store.search(kind="domain")["total"], 2)


if __name__ == "__main__":
    unittest.main()
