import unittest
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from signalwatch.data_quality import ambiguous_aliases, freshness, register_quality_routes
from signalwatch.store import Store


class QualityTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.ingest({"entities": [{"id": "company:one", "kind": "company", "name": "Acme, Inc."},
                                         {"id": "company:two", "kind": "company", "name": "Acme LLC"},
                                         {"id": "domain:one.test", "kind": "domain", "value": "one.test"},
                                         {"id": "domain:two.test", "kind": "domain", "value": "two.test"}],
                           "edges": [{"from_id": "company:one", "to_id": "domain:one.test", "relation": "official_website"},
                                     {"from_id": "company:two", "to_id": "domain:two.test", "relation": "official_website"}],
                           "observations": [{"asset_id": "domain:two.test", "vendor": "apache", "product": "http_server", "version": "2.4.1"}]})
        app = FastAPI()
        self.config = {"sources": {"kev": True, "nvd": True, "disabled": False}, "source_intervals": {"kev": 360, "nvd": 360}}
        register_quality_routes(app, self.store, self.config)
        self.client = TestClient(app)

    def test_aliases_use_actual_legal_suffix_normalization(self):
        data = ambiguous_aliases(self.store)
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["items"][0]["term"], "acme")
        self.assertEqual({row["id"] for row in data["items"][0]["companies"]}, {"company:one", "company:two"})

    def test_company_coverage_counts_only_its_included_assets(self):
        first = self.client.get("/api/quality/company", params={"id": "company:one"}).json()
        second = self.client.get("/api/quality/company", params={"id": "company:two"}).json()
        self.assertEqual(first["observations"], 0)
        self.assertIn("no_software_observations", first["gaps"])
        self.assertEqual(second["observations"], 1)
        self.assertEqual(second["versioned_observations"], 1)
        self.assertEqual(second["gaps"], [])
        self.assertEqual(self.client.get("/api/quality/company", params={"id": "missing"}).status_code, 404)

    def test_freshness_preserves_failed_recent_attempt(self):
        self.store.update_source("kev", last_success="2026-10-19T00:00:00Z", status="partial", error="Feed request blocked")
        rows = {row["source"]: row for row in freshness(self.store, self.config, datetime(2026, 10, 20, tzinfo=timezone.utc))}
        self.assertEqual(rows["kev"]["status"], "stale")
        self.assertTrue(rows["kev"]["has_errors"])
        self.assertEqual(rows["nvd"]["status"], "never_collected")
        self.assertEqual(rows["disabled"]["status"], "disabled")

    def test_routes_are_read_only_and_include_window_limits(self):
        self.store.ingest({"articles": [{"url": "https://news.test/a", "title": "Same  News", "source": "a"},
                                         {"url": "https://news.test/b", "title": "same news", "source": "b"}]})
        before = self.store.stats()
        response = self.client.get("/api/quality/summary")
        self.assertEqual(response.status_code, 200, response.text)
        summary = response.json()
        self.assertEqual(summary["duplicate_articles"]["groups"], 1)
        self.assertEqual(summary["duplicate_articles"]["action"], "reported_not_merged")
        for kind in ("freshness", "duplicate_articles", "ambiguous_alias", "coverage_gap", "missing_version"):
            result = self.client.get("/api/quality/issues", params={"kind": kind, "limit": 1})
            self.assertEqual(result.status_code, 200, result.text)
            self.assertLessEqual(len(result.json()["items"]), 1)
        self.assertEqual(self.store.stats(), before)
        self.assertEqual(self.client.get("/api/quality/issues", params={"kind": "bad"}).status_code, 422)
        self.assertEqual(self.client.post("/api/quality/summary").status_code, 405)
