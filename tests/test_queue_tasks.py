import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from signalwatch.celery_app import app
from signalwatch.config import DEFAULTS, load_config
from signalwatch.jobs import Jobs
from signalwatch.store import Store
from signalwatch.tasks import enqueue_scheduled, execute_job


class FakeEngine:
    result = {"sources": [{"source": "kev", "ok": True, "counts": {"records": 1}}]}
    instances = []

    def __init__(self, config, store):
        self.config = config
        self.store = store
        self.calls = []
        self.loop = None
        self.closed = False
        self.__class__.instances.append(self)

    async def __aenter__(self):
        self.loop = asyncio.get_running_loop()
        return self

    async def __aexit__(self, *args):
        self.closed = True

    async def run(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if isinstance(self.result, Exception):
            raise self.result
        return self.result

    async def run_company(self, *args, **kwargs):
        return await self.run(*args, **kwargs)


class QueueTaskTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.path = self.root / "config.json"
        self.path.write_text(json.dumps({"db": "jobs.db", "seed_urls": [], "concurrency": 2}))
        self.config = load_config(self.path)
        self.store = Store(self.config["db"])
        self.jobs = Jobs(self.store)
        self.env = patch.dict(os.environ, {"SIGNALWATCH_CONFIG": str(self.path), "CELERY_BROKER_URL": "redis://localhost:6379/15"})
        self.env.start()
        self.addCleanup(self.env.stop)
        FakeEngine.instances = []
        FakeEngine.result = {"sources": [{"source": "kev", "ok": True, "counts": {"records": 1}}]}
        self.engine_patch = patch("signalwatch.tasks.Engine", FakeEngine)
        self.engine_patch.start()
        self.addCleanup(self.engine_patch.stop)

    def test_id_only_task_claims_persists_and_ignores_duplicate_delivery(self):
        job = self.jobs.enqueue("collect", {"sources": ["kev"], "scheduled": False})
        self.assertEqual(execute_job.run(job["id"])["status"], "succeeded")
        saved = self.jobs.get(job["id"])
        self.assertEqual((saved["status"], saved["attempts"]), ("succeeded", 1))
        self.assertEqual(saved["result"], FakeEngine.result)
        self.assertEqual(FakeEngine.instances[0].calls, [((["kev"],), {"scheduled": False})])
        self.assertEqual(execute_job.run(job["id"])["status"], "not_available")
        self.assertEqual(len(FakeEngine.instances), 1)
        self.assertTrue(FakeEngine.instances[0].closed)

    def test_each_task_reloads_configuration_and_owns_a_fresh_event_loop(self):
        first = self.jobs.enqueue("collect", {"sources": ["kev"]})
        execute_job.run(first["id"])
        self.path.write_text(json.dumps({"db": "jobs.db", "seed_urls": [], "concurrency": 7}))
        second = self.jobs.enqueue("collect", {"sources": ["kev"]})
        execute_job.run(second["id"])
        self.assertEqual([engine.config["concurrency"] for engine in FakeEngine.instances], [2, 7])
        self.assertIsNot(FakeEngine.instances[0].loop, FakeEngine.instances[1].loop)
        self.assertTrue(all(engine.loop.is_closed() and engine.closed for engine in FakeEngine.instances))

    def test_company_jobs_and_cve_match_select_the_expected_engine_operations(self):
        self.path.write_text(json.dumps({"db": "jobs.db", "seed_urls": ["https://unrelated.test/"]}))
        for kind in ("passive_scan", "web_probe"):
            job = self.jobs.enqueue(kind, {"company_id": "company:example", "primary_domain": "example.test"})
            execute_job.run(job["id"])
            self.assertEqual(FakeEngine.instances[-1].calls, [((kind, "company:example", "example.test"), {})])
            self.assertEqual(FakeEngine.instances[-1].config["seed_urls"], [])
        job = self.jobs.enqueue("cve_match", {})
        execute_job.run(job["id"])
        self.assertEqual(FakeEngine.instances[-1].calls, [((["kev"],), {})])

    def test_source_failure_and_partial_coverage_are_not_reported_as_success(self):
        cases = [{"sources": [{"source": "kev", "ok": False, "error": "HTTP 429", "retry_at": "2099-01-01T00:00:00Z"}]},
                 {"sources": [{"source": "web", "ok": True, "counts": {"errors": ["One page failed"]}}]},
                 {"sources": [{"source": "kev", "ok": True, "counts": {"records": 2}}, {"source": "nvd", "ok": False}]},
                 None]
        for result in cases:
            with self.subTest(result=result):
                FakeEngine.result = result
                job = self.jobs.enqueue("collect", {"sources": ["kev"]})
                self.assertEqual(execute_job.run(job["id"])["status"], "failed")
                saved = self.jobs.get(job["id"])
                self.assertEqual(saved["attempts"], 1)
                self.assertEqual(saved["result"], result)
                self.assertTrue(saved["error"])
                self.assertNotIn(job["id"], [row["id"] for row in self.jobs.pending_dispatch()])

    def test_busy_job_is_deferred_without_spending_an_execution_attempt(self):
        FakeEngine.result = {"busy": True}
        job = self.jobs.enqueue("collect", {"sources": ["kev"]})
        self.assertEqual(execute_job.run(job["id"])["status"], "retrying")
        saved = self.jobs.get(job["id"])
        self.assertEqual((saved["status"], saved["attempts"]), ("retrying", 0))
        self.assertGreater(saved["available_at"], saved["updated_at"])
        self.assertEqual(execute_job.run(job["id"])["status"], "not_available")
        self.assertEqual(len(FakeEngine.instances), 1)

    def test_per_job_lock_prevents_a_concurrent_duplicate_before_claim(self):
        job = self.jobs.enqueue("collect", {"sources": ["kev"]})
        with self.jobs.worker_lock(job["id"]) as acquired:
            self.assertTrue(acquired)
            self.assertEqual(execute_job.run(job["id"])["status"], "already_running")
        self.assertEqual(self.jobs.get(job["id"])["attempts"], 0)
        self.assertFalse(FakeEngine.instances)

    def test_abandoned_execution_is_recovered_and_repeated_worker_losses_are_bounded(self):
        job = self.jobs.enqueue("collect", {"sources": ["kev"]})
        self.jobs.claim(job["id"])
        self.assertEqual(execute_job.run(job["id"])["status"], "succeeded")
        self.assertEqual(self.jobs.get(job["id"])["attempts"], 2)
        other = self.jobs.enqueue("collect", {"sources": ["kev"]})
        for _ in range(3):
            self.jobs.claim(other["id"])
            self.jobs.recover()
        before = len(FakeEngine.instances)
        self.assertEqual(execute_job.run(other["id"])["status"], "failed")
        self.assertEqual(len(FakeEngine.instances), before)
        self.assertIn("interruptions", self.jobs.get(other["id"])["error"])

    def test_worker_error_is_redacted_and_oversized_result_does_not_repeat_network_work(self):
        FakeEngine.result = RuntimeError("broker://user:SECRET@host")
        job = self.jobs.enqueue("collect", {"sources": ["kev"]})
        execute_job.run(job["id"])
        self.assertNotIn("SECRET", self.jobs.get(job["id"])["error"])
        FakeEngine.result = {"sources": [], "large": "x" * (1024 * 1024)}
        oversized = self.jobs.enqueue("collect", {"sources": ["kev"]})
        self.assertEqual(execute_job.run(oversized["id"])["status"], "failed")
        self.assertIn("could not be recorded", self.jobs.get(oversized["id"])["error"])
        self.assertEqual(execute_job.run(oversized["id"])["status"], "not_available")

    def test_beat_checks_due_sources_and_deduplicates_active_scheduled_work(self):
        with patch("signalwatch.tasks._due", new=AsyncMock(return_value=[])):
            self.assertFalse(enqueue_scheduled.run()["queued"])
        self.assertEqual(self.jobs.list(), [])
        with patch("signalwatch.tasks._due", new=AsyncMock(return_value=["kev"])):
            first = enqueue_scheduled.run()
            second = enqueue_scheduled.run()
        self.assertEqual(first["job_id"], second["job_id"])
        self.assertEqual(self.jobs.get(first["job_id"])["payload"], {"sources": None, "scheduled": True})
        self.assertEqual(len(self.jobs.list()), 1)

    def test_worker_transport_defaults_are_json_only_bounded_and_prefork(self):
        self.assertEqual(app.conf.accept_content, ["json"])
        self.assertEqual(app.conf.worker_pool, "prefork")
        self.assertEqual(app.conf.worker_concurrency, 1)
        self.assertEqual(app.conf.worker_prefetch_multiplier, 1)
        self.assertTrue(app.conf.task_acks_late)
        self.assertTrue(app.conf.task_reject_on_worker_lost)
        self.assertTrue(app.conf.task_ignore_result)
        self.assertFalse(app.conf.task_publish_retry)
        self.assertEqual(app.conf.broker_connection_max_retries, 3)
        self.assertEqual(app.conf.beat_schedule["collect-due-sources"]["options"]["expires"], 60)


if __name__ == "__main__":
    unittest.main()
