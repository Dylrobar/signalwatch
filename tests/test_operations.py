import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from fastapi.testclient import TestClient

from signalwatch.config import load_config
from signalwatch.jobs import Jobs, LeaseLost, stamp
from signalwatch.operations import heartbeat, operations_status
from signalwatch.store import Store


class OperationsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        path = Path(self.temp.name) / "config.json"
        path.write_text(json.dumps({"db": "test.db", "sources": {"kev": True}}))
        self.config = load_config(path)
        self.config["sources"] = {"kev": True}
        self.store = Store(self.config["db"])
        self.jobs = Jobs(self.store)

    def test_progress_is_durable_and_execution_fenced(self):
        item = self.jobs.enqueue("web_probe", {"company_id": "company:one"})
        claimed = self.jobs.claim(item["id"])
        self.jobs.record_progress(item["id"], "collecting", completed=2, total=5, unit="targets", lease_token=claimed["lease_token"])
        reloaded = Jobs(Store(self.config["db"]))
        self.assertEqual(reloaded.get(item["id"])["progress"]["completed"], 2)
        with self.assertRaises(LeaseLost):
            self.jobs.record_progress(item["id"], "collecting", completed=5, total=5, lease_token="old")
        self.jobs.finish(item["id"], "failed", result={"sources": [{"ok": True, "counts": {"pages": 2}}, {"ok": False}]}, lease_token=claimed["lease_token"])
        saved = reloaded.get(item["id"])
        self.assertEqual(saved["progress"]["stage"], "failed")
        self.assertTrue(saved["progress"]["partial"])
        self.jobs.retry(item["id"])
        self.assertFalse(self.jobs.get(item["id"])["progress"]["partial"])
        with self.assertRaises(LeaseLost):
            self.jobs.record_progress(item["id"], "completed", lease_token=claimed["lease_token"])

    def test_company_history_filters_exact_identity_and_page(self):
        for company_id in ("company:one", "company:one-extra", "company:two", "company:one"):
            self.jobs.enqueue("web_probe", {"company_id": company_id})
        self.jobs.enqueue("collect", {"sources": ["company:one"]})
        self.assertEqual(self.jobs.count(company_id="company:one"), 2)
        rows = self.jobs.list(company_id="company:one", kind="web_probe", status="queued", limit=1, offset=1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["payload"]["company_id"], "company:one")
        self.assertEqual(self.jobs.list(company_id="company:one", offset=2), [])

    def test_heartbeat_queue_age_and_source_health_are_separate(self):
        clock = time.time()
        job = self.jobs.enqueue("collect", {})
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE collection_jobs SET created_at=? WHERE id=?", (stamp(clock - 7200), job["id"]))
        self.store.update_source("kev", status="error", last_success=stamp(clock - 3 * 86400))
        before = operations_status(self.store, self.config, self.jobs, enabled=True, clock=clock)
        self.assertEqual(before["workers"]["status"], "unknown")
        self.assertAlmostEqual(before["queue"]["oldest_active_seconds"], 7200, delta=1)
        self.assertEqual(before["sources"]["errors"], 1)
        heartbeat(self.store, "worker", clock=clock)
        ready = operations_status(self.store, self.config, self.jobs, enabled=True, clock=clock)
        self.assertEqual(ready["workers"]["status"], "ready")
        self.assertEqual(ready["status"], "degraded")
        self.assertEqual(operations_status(self.store, self.config, self.jobs, enabled=True, clock=clock + 91)["workers"]["status"], "stale")
        self.assertNotIn(self.config["db"], json.dumps(ready))

    def test_operations_requires_auth_and_does_not_change_public_liveness(self):
        from signalwatch.api import create_app
        self.config["api_token"] = "operations-test-token"
        self.store.update_source("kev", status="error", error="Upstream unavailable")
        with TestClient(create_app(self.config, auto_collect=False)) as client:
            self.assertEqual(client.get("/health").status_code, 200)
            self.assertEqual(client.get("/api/operations").status_code, 401)
            response = client.get("/api/operations", headers={"Authorization": "Bearer operations-test-token"})
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["sources"]["errors"], 1)
            self.assertEqual(response.json()["status"], "degraded")

