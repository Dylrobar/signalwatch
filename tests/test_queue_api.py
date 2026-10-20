import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from signalwatch.api import create_app
from signalwatch.config import load_config


class QueueAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / "config.json")
        self.config["seed_urls"] = []
        self.config["api_token"] = "test-secret"
        self.env = patch.dict(os.environ, {"CELERY_BROKER_URL": "redis://localhost:6399/0"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.app = create_app(self.config, auto_collect=False)
        # No lifespan: these tests prove durable acceptance without any broker
        # or task execution. Real worker delivery is covered by integration tests.
        self.client = TestClient(self.app, headers={"Authorization": "Bearer test-secret"})
        self.addCleanup(self.client.close)

    def test_collect_commits_receipt_without_broker_and_normalizes_sources(self):
        response = self.client.post("/api/collect", json={"sources": ["kev", "news", "kev"]})
        self.assertEqual(response.status_code, 200)
        result = response.json()
        self.assertTrue(result["queued"])
        self.assertEqual(result["sources"], ["kev", "news"])
        self.assertEqual(result["job"]["status"], "queued")
        job_id = result["job"]["id"]
        self.assertEqual(self.client.get("/api/jobs/" + job_id).json()["id"], job_id)
        listed = self.client.get("/api/jobs").json()
        self.assertTrue(listed["enabled"])
        self.assertEqual(listed["jobs"][0]["id"], job_id)

    def test_idempotency_reuses_job_and_rejects_different_request(self):
        payload = {"sources": ["kev"], "idempotency_key": "one-click"}
        first = self.client.post("/api/collect", json=payload).json()
        second = self.client.post("/api/collect", json=payload).json()
        self.assertEqual(first["job"]["id"], second["job"]["id"])
        payload["sources"] = ["news"]
        self.assertEqual(self.client.post("/api/collect", json=payload).status_code, 409)

    def test_job_endpoints_require_existing_auth(self):
        for method, path, payload in [("get", "/api/jobs", None), ("get", "/api/jobs/missing", None),
                                      ("post", "/api/jobs", {"kind": "cve_match"}),
                                      ("post", "/api/jobs/missing/retry", {})]:
            with self.subTest(path=path):
                response = self.client.request(method, path, json=payload, headers={"Authorization": ""})
                self.assertEqual(response.status_code, 401)

    def test_validation_never_persists_invalid_job(self):
        for payload in [{"kind": "collect", "sources": ["unknown"]}, {"kind": "web_probe"},
                        {"kind": "cve_match", "sources": ["news"]},
                        {"kind": "collect", "company_id": "other"},
                        {"kind": "passive_scan", "company_id": "missing"},
                        {"kind": "execute", "command": "example"}]:
            with self.subTest(payload=payload):
                response = self.client.post("/api/jobs", json=payload)
                self.assertIn(response.status_code, (400, 404, 422))
        self.assertEqual(self.client.get("/api/jobs").json()["jobs"], [])

    def test_scope_validation_runs_before_company_acceptance(self):
        with patch.object(self.app.state.engine, "company_scope", side_effect=ValueError("Outside company scope")):
            response = self.client.post("/api/jobs", json={"kind": "web_probe", "company_id": "company:a",
                                                          "primary_domain": "outside.test"})
        self.assertEqual(response.status_code, 422)
        self.assertEqual(self.app.state.jobs.list(), [])
        with patch.object(self.app.state.engine, "company_scope", return_value=["approved.test"]) as scope:
            response = self.client.post("/api/jobs", json={"kind": "passive_scan", "company_id": "company:a"})
        scope.assert_called_once_with("company:a", None)
        self.assertEqual(response.json()["job"]["payload"], {"company_id": "company:a"})

    def test_retry_rejects_active_jobs_and_missing_ids(self):
        job = self.client.post("/api/jobs", json={"kind": "cve_match"}).json()["job"]
        self.assertEqual(self.client.post(f'/api/jobs/{job["id"]}/retry').status_code, 409)
        self.assertEqual(self.client.post("/api/jobs/missing/retry").status_code, 404)

    def test_full_queue_is_a_retryable_service_error(self):
        self.app.state.jobs.max_active = 1
        self.client.post("/api/jobs", json={"kind": "cve_match"})
        response = self.client.post("/api/collect", json={"sources": []})
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["retry-after"], "30")

    def test_disabled_queue_preserves_readable_history_and_refuses_new_jobs(self):
        with patch.dict(os.environ, {"CELERY_BROKER_URL": ""}):
            app = create_app(self.config, auto_collect=False)
        with TestClient(app, headers={"Authorization": "Bearer test-secret"}) as client:
            self.assertFalse(client.get("/api/jobs").json()["enabled"])
            self.assertEqual(client.post("/api/jobs", json={"kind": "cve_match"}).status_code, 503)


if __name__ == "__main__":
    unittest.main()
