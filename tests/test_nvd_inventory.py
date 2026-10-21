"""Inventory-driven historical lookup uses explicit product IDs and bounded pages."""
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from signalwatch.collectors import Collector
from signalwatch.config import DEFAULTS
from signalwatch.http import HTTPError
from signalwatch.store import Store


CPE = "cpe:2.3:a:acme:router:1.5:*:*:*:*:*:*:*"
TARGET = "cpe:2.3:a:acme:router:*:*:*:*:*:*:*:*"


def cve(number=12345):
    return {"cve": {"id": f"CVE-2018-{number}", "published": "2018-01-01T00:00:00Z", "vulnStatus": "Analyzed",
        "configurations": [{"nodes": [{"operator": "OR", "cpeMatch": [{"criteria": TARGET, "vulnerable": True,
                           "versionStartIncluding": "1.0", "versionEndExcluding": "2.0"}]}]}]}}


class NVDInventoryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "test.sqlite3")
        self.store.ingest({"observations": [{"asset_id": "domain:example.test", "vendor": "acme", "product": "router",
                           "version": "1.5", "cpe": CPE, "source_url": "https://example.test", "origin": "web"}]})
        self.collector = Collector({**DEFAULTS, "cache_dir": self.temp.name, "nvd_inventory_requests": 1}, self.store)

    def response(self, rows, total=None, index=0):
        path = Path(self.temp.name) / "response.json"
        path.write_text(json.dumps({"vulnerabilities": rows, "totalResults": len(rows) if total is None else total,
                                   "startIndex": index, "resultsPerPage": len(rows)}))
        return SimpleNamespace(path=path)

    async def test_finds_older_vulnerability_without_recent_update_date_filter(self):
        self.collector.http.get = AsyncMock(return_value=self.response([cve()]))
        result = await self.collector._nvd_inventory()
        params = self.collector.http.get.call_args.kwargs["params"]
        self.assertEqual(params, {"virtualMatchString": TARGET, "resultsPerPage": 200, "startIndex": 0})
        self.assertEqual(result["advisories"], 1)
        self.store.reconcile()
        warning = self.store.alerts()["items"][0]
        self.assertEqual(warning["advisory_id"], "CVE-2018-12345")
        self.assertEqual(warning["version_state"], "affected_range")
        self.assertEqual((await self.collector._nvd_inventory())["requests"], 0)
        self.assertEqual(self.collector.http.get.await_count, 1)

    async def test_pages_resume_after_ingestion_and_preserve_update_watermark(self):
        self.store.update_source("nvd", watermark="2026-01-01T00:00:00Z")
        self.collector.http.get = AsyncMock(return_value=self.response([cve()], total=2))
        await self.collector._nvd_inventory()
        self.assertEqual(self.store.source_state("nvd")["inventory_lookup"][TARGET]["next_index"], 1)
        self.collector.http.get.return_value = self.response([cve(12346)], total=2, index=1)
        self.collector.nvd_next_request = 0
        second = await self.collector._nvd_inventory()
        self.assertEqual(self.collector.http.get.call_args.kwargs["params"]["startIndex"], 1)
        self.assertEqual(second["completed_products"], 1)
        self.assertEqual(self.store.source_state("nvd")["watermark"], "2026-01-01T00:00:00Z")
        self.assertEqual(self.store.advisories()["total"], 2)

    async def test_malformed_page_and_ingestion_failure_never_advance_cursor(self):
        self.collector.http.get = AsyncMock(return_value=self.response([], total=2))
        result = await self.collector._nvd_inventory()
        self.assertTrue(result["errors"])
        self.assertNotIn("inventory_lookup", self.store.source_state("nvd"))
        self.collector.http.get.return_value = self.response([cve()])
        self.collector.nvd_next_request = 0
        with patch.object(self.collector, "emit", AsyncMock(side_effect=RuntimeError("write failed"))):
            result = await self.collector._nvd_inventory()
        self.assertTrue(result["errors"])
        self.assertNotIn("inventory_lookup", self.store.source_state("nvd"))

    async def test_request_budget_and_auth_rate_failures_stop_additional_requests(self):
        self.collector.config["nvd_inventory_requests"] = 4
        with patch.object(self.store, "nvd_product_targets", return_value=[TARGET, TARGET.replace("router", "switch")]):
            self.collector.http.get = AsyncMock(side_effect=HTTPError(429, "https://services.nvd.nist.gov", "rate limited"))
            result = await self.collector._nvd_inventory()
        self.assertEqual(result["requests"], 1)
        self.assertEqual(self.collector.http.get.await_count, 1)
        self.assertTrue(result["errors"])

    async def test_budget_moves_to_next_product_after_completed_lookup(self):
        targets = [TARGET, TARGET.replace("router", "switch")]
        self.collector.http.get = AsyncMock(return_value=self.response([]))
        with patch.object(self.store, "nvd_product_targets", return_value=targets):
            first = await self.collector._nvd_inventory()
            self.assertEqual(first["requests"], 1)
            self.collector.nvd_next_request = 0
            second = await self.collector._nvd_inventory()
        self.assertEqual(second["requests"], 1)
        self.assertEqual([call.kwargs["params"]["virtualMatchString"] for call in self.collector.http.get.call_args_list], targets)

    async def test_can_disable_lookup_without_changing_recent_update_collection(self):
        self.collector.config["nvd_inventory_requests"] = 0
        self.collector._collect_nvd_updates = AsyncMock(return_value={"advisories": 3})
        self.collector._nvd_inventory = AsyncMock()
        self.assertEqual(await self.collector.collect_nvd(), {"advisories": 3})
        self.collector._nvd_inventory.assert_not_awaited()
