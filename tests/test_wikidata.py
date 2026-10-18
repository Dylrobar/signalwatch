import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from signalwatch.collectors import Collector
from signalwatch.config import DEFAULTS
from signalwatch.http import FetchResult
from signalwatch.store import Store


class WikidataBoundaryTests(unittest.IsolatedAsyncioTestCase):
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
