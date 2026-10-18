import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from signalwatch.http import FetchResult
from signalwatch.network import collect_network, parse_network
from signalwatch.store import Store


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    def target(self, address="1.1.1.1"):
        return {"id": "ip:" + address, "kind": "ip", "name": address, "value": address,
                "source_url": "https://example.com/", "metadata": {"existing": "preserved"}}

    def test_multi_origin_route_context_has_no_company_ownership(self):
        target = self.target()
        batch = parse_network({"status": "ok", "data": {"prefix": "1.1.1.0/24", "asns": [13335, "13336", 13335]}}, target, "https://stat.ripe.net/", "2026-10-18T00:00:00+00:00")
        self.assertEqual({item["kind"] for item in batch["entities"]}, {"ip", "prefix", "asn"})
        self.assertEqual([row["relation"] for row in batch["edges"]], ["routed_in", "announced_by", "announced_by"])
        self.assertEqual(batch["entities"][0]["metadata"]["announcing_asns"], [13335, 13336])
        self.assertEqual(batch["entities"][0]["metadata"]["existing"], "preserved")

    def test_mismatched_prefix_or_bad_schema_is_not_ingested(self):
        for payload in ({"status": "error", "data": {}}, {"status": "ok", "data": {"prefix": "8.8.8.0/24", "asns": [15169]}},
                        {"status": "ok", "data": {"prefix": None, "asns": [15169]}},
                        {"status": "ok", "data": {"prefix": "1.1.1.0/24", "asns": [True]}}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                parse_network(payload, self.target(), "https://stat.ripe.net/", "2026-10-18T00:00:00+00:00")

    async def test_budget_refresh_and_no_route_success(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "db.sqlite")
            store.ingest({"entities": [self.target(), self.target("8.8.8.8")]})
            path = Path(folder) / "network.json"
            path.write_text(json.dumps({"status": "ok", "data": {"prefix": None, "asns": []}}))
            http = type("HTTP", (), {})()
            http.get = AsyncMock(return_value=FetchResult(path, 200, {}, "https://stat.ripe.net/", True, "1"))
            counts = await collect_network({"network_batch": 1}, store, http)
            self.assertEqual(counts["enriched"], 1)
            self.assertEqual(counts["pending"], 1)
            self.assertEqual(counts["routed"], 0)
            counts = await collect_network({"network_batch": 1}, store, http)
            self.assertEqual(counts["pending"], 0)
            counts = await collect_network({"network_batch": 1}, store, http)
            self.assertEqual(counts["targets"], 0)
            self.assertEqual(http.get.await_count, 2)

    async def test_failed_enrichment_remains_pending_without_freshness(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "db.sqlite")
            store.ingest({"entities": [self.target()]})
            http = type("HTTP", (), {})()
            http.get = AsyncMock(side_effect=RuntimeError("temporary unavailable"))
            with self.assertRaisesRegex(RuntimeError, "All RIPEstat targets failed"):
                await collect_network({}, store, http)
            self.assertEqual(store.network_pending_count(), 1)


if __name__ == "__main__":
    unittest.main()
