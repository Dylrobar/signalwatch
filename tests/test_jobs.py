import concurrent.futures
import fcntl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.jobs import IdempotencyConflict, InvalidJobState, Jobs, LeaseLost, QueueFull
from signalwatch.store import Store


class JobsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "jobs.db"
        self.store = Store(self.path)
        self.jobs = Jobs(self.store)
        self.clock = 1_800_000_000.0
        self.timer = patch("signalwatch.jobs.time.time", side_effect=lambda: self.clock)
        self.timer.start()
        self.addCleanup(self.timer.stop)

    def enqueue(self, **kwargs):
        return self.jobs.enqueue("collect", {"sources": ["kev"]}, **kwargs)

    def finish(self, job, status="succeeded"):
        claim = self.jobs.claim(job["id"])
        self.assertIsNotNone(claim)
        return self.jobs.finish(job["id"], status, {"sources": [{"source": "kev", "ok": status == "succeeded"}]}, lease_token=claim["lease_token"])

    def test_durable_acceptance_idempotency_and_conflicts(self):
        first = self.enqueue(idempotency_key="one")
        reopened = Jobs(Store(self.path))
        self.assertEqual(reopened.get(first["id"])["payload"], {"sources": ["kev"]})
        self.assertEqual(reopened.enqueue("collect", {"sources": ["kev"]}, "one")["id"], first["id"])
        for kind, payload in (("company", {"sources": ["kev"]}), ("collect", {"sources": ["nvd"]})):
            with self.subTest(kind=kind, payload=payload), self.assertRaises(IdempotencyConflict):
                reopened.enqueue(kind, payload, "one")
        self.assertEqual(len(reopened.list()), 1)
        self.assertNotIn("lease_token", first)

    def test_canonical_json_keys_deduplicate_and_parallel_admission_is_atomic(self):
        queues = [Jobs(Store(self.path)) for _ in range(3)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda index: queues[index % 3].enqueue("collect", {"sources": [], "scheduled": True}, "same"), range(12)))
        self.assertEqual(len({job["id"] for job in results}), 1)
        self.assertEqual(self.jobs.enqueue("collect", {"scheduled": True, "sources": []}, "same")["id"], results[0]["id"])
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(pool.map(lambda index: queues[index % 3].claim(results[0]["id"]), range(12)))
        self.assertEqual(sum(claim is not None for claim in claims), 1)

    def test_outbox_recovers_publish_crash_and_lost_unclaimed_delivery(self):
        job = self.enqueue()
        self.assertEqual([item["id"] for item in self.jobs.pending_dispatch()], [job["id"]])
        self.jobs.dispatched(job["id"])
        self.assertEqual(self.jobs.pending_dispatch(), [])
        self.clock += 299
        self.assertEqual(self.jobs.pending_dispatch(), [])
        self.clock += 1
        self.assertEqual([item["id"] for item in self.jobs.pending_dispatch()], [job["id"]])
        self.jobs.claim(job["id"])
        self.clock += 1000
        self.assertEqual(self.jobs.pending_dispatch(), [])

    def test_worker_lock_and_claim_prevent_duplicate_execution(self):
        job = self.enqueue()
        with self.jobs.worker_lock(job["id"]) as first:
            self.assertTrue(first)
            claim = self.jobs.claim(job["id"])
            with Jobs(Store(self.path)).worker_lock(job["id"]) as duplicate:
                self.assertFalse(duplicate)
            self.assertIsNone(self.jobs.claim(job["id"]))
            done = self.jobs.finish(job["id"], "succeeded", {"count": 2}, lease_token=claim["lease_token"])
            self.assertEqual(done["status"], "succeeded")
            self.assertNotIn("lease_token", done)
        self.assertIsNone(self.jobs.claim(job["id"]))

    def test_broker_failure_defers_without_execution_and_busy_does_not_spend_attempt(self):
        job = self.enqueue()
        queued = self.jobs.defer(job["id"], "Broker unavailable", delay=30, attempted=False)
        self.assertEqual((queued["status"], queued["attempts"]), ("retrying", 0))
        self.assertIsNone(self.jobs.claim(job["id"]))
        self.assertEqual(self.jobs.pending_dispatch(), [])
        self.clock += 30
        claim = self.jobs.claim(job["id"])
        with self.assertRaises(LeaseLost):
            self.jobs.defer(job["id"], "A publisher cannot reset a running worker", attempted=False)
        busy = self.jobs.defer(job["id"], "Collection already running", lease_token=claim["lease_token"], attempted=False)
        self.assertEqual((busy["status"], busy["attempts"]), ("retrying", 0))
        self.clock += 30
        self.assertEqual(self.jobs.claim(job["id"])["attempts"], 1)

    def test_stale_execution_tokens_cannot_complete_or_reset_new_attempt(self):
        job = self.enqueue()
        first = self.jobs.claim(job["id"])
        self.jobs.defer(job["id"], delay=0, lease_token=first["lease_token"])
        second = self.jobs.claim(job["id"])
        self.assertNotEqual(first["lease_token"], second["lease_token"])
        for action in (lambda: self.jobs.finish(job["id"], "failed", lease_token=first["lease_token"]),
                       lambda: self.jobs.defer(job["id"], lease_token=first["lease_token"])):
            with self.assertRaises(LeaseLost):
                action()
        self.assertEqual(self.jobs.get(job["id"])["status"], "running")
        self.assertNotIn("lease_token", self.jobs.get(job["id"]))

    def test_recovery_requires_both_collection_and_job_locks_to_be_idle(self):
        job = self.enqueue()
        with self.jobs.worker_lock(job["id"]) as acquired:
            self.assertTrue(acquired)
            first = self.jobs.claim(job["id"])
            self.assertEqual(self.jobs.recover(), 0)
            self.assertEqual(self.jobs.get(job["id"])["status"], "running")
        with self.jobs.collector_lock.open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.jobs.recover(), 0)
        self.assertEqual(Jobs(Store(self.path)).recover(), 1)
        recovered = self.jobs.get(job["id"])
        self.assertEqual((recovered["status"], recovered["attempts"]), ("retrying", 1))
        self.assertEqual(len(self.jobs.pending_dispatch()), 1)
        second = self.jobs.claim(job["id"])
        self.assertNotEqual(first["lease_token"], second["lease_token"])
        self.assertEqual(self.jobs.recover(), 1)  # No live worker owns this synthetic claim.

    def test_retry_only_accepts_failed_terminal_jobs_and_resets_recovery_budget(self):
        job = self.enqueue()
        with self.assertRaises(InvalidJobState):
            self.jobs.retry(job["id"])
        failed = self.finish(job, "failed")
        self.assertEqual(failed["attempts"], 1)
        retry = self.jobs.retry(job["id"])
        self.assertEqual((retry["status"], retry["attempts"], retry["result"]), ("queued", 0, None))
        self.assertEqual(self.finish(job)["attempts"], 1)
        with self.assertRaises(InvalidJobState):
            self.jobs.retry(job["id"])
        with self.assertRaises(LookupError):
            self.jobs.retry("missing")

    def test_active_schedule_dedup_stops_backlog_but_allows_later_runs(self):
        payload = {"sources": None, "scheduled": True}
        first = self.jobs.enqueue("collect", payload, "tick:1", deduplicate_active=True)
        duplicate = self.jobs.enqueue("collect", payload, "tick:2", deduplicate_active=True)
        self.assertEqual(first["id"], duplicate["id"])
        self.finish(first)
        later = self.jobs.enqueue("collect", payload, "tick:3", deduplicate_active=True)
        self.assertNotEqual(first["id"], later["id"])
        # A distinct manual request is never folded into the scheduled run.
        self.assertNotEqual(self.jobs.enqueue("collect", {"sources": None})["id"], later["id"])

    def test_capacity_retains_active_jobs_and_idempotent_duplicates(self):
        jobs = Jobs(self.store, max_active=1)
        first = jobs.enqueue("collect", {}, "first")
        self.assertEqual(jobs.enqueue("collect", {}, "first")["id"], first["id"])
        with self.assertRaises(QueueFull):
            jobs.enqueue("collect", {}, "second")
        self.finish(first)
        second = jobs.enqueue("collect", {}, "second")
        self.assertIsNotNone(second)
        self.finish(second, "failed")
        jobs.enqueue("collect", {}, "third")
        with self.assertRaises(QueueFull):
            jobs.retry(second["id"])
        self.assertEqual(jobs.get(second["id"])["status"], "failed")

    def test_history_and_lock_files_are_bounded_without_pruning_active_jobs(self):
        jobs = Jobs(self.store, max_completed=1, retention_days=30)
        first = jobs.enqueue("collect", {}, "first")
        with jobs.worker_lock(first["id"]):
            self.finish(first)
        self.clock += 1
        second = jobs.enqueue("collect", {}, "second")
        self.finish(second)
        third = jobs.enqueue("collect", {}, "third")
        self.assertIsNone(jobs.get(first["id"]))
        self.assertTrue(jobs._lock_path(first["id"]).exists())
        self.assertIsNotNone(jobs.get(second["id"]))
        self.assertIsNotNone(jobs.get(third["id"]))
        self.clock += 31 * 86400
        jobs.recover()
        self.assertIsNone(jobs.get(second["id"]))
        self.assertIsNotNone(jobs.get(third["id"]))
        with jobs.worker_lock(first["id"]) as acquired:
            self.assertFalse(acquired)
        self.assertLessEqual(len({jobs._lock_path(str(number)) for number in range(10000)}), 1024)

    def test_pruning_finished_job_does_not_replace_a_still_locked_inode(self):
        jobs = Jobs(self.store, max_completed=0)
        first = jobs.enqueue("collect", {})
        first_path = jobs._lock_path(first["id"])
        with jobs.worker_lock(first["id"]) as acquired:
            self.assertTrue(acquired)
            self.finish(first)
            second = jobs.enqueue("collect", {})
            self.assertIsNone(jobs.get(first["id"]))
            with patch.object(jobs, "_lock_path", return_value=first_path):
                with jobs.worker_lock(second["id"]) as locked:
                    self.assertFalse(locked)

    def test_invalid_values_do_not_leave_partial_jobs_or_results(self):
        for payload in ([], {"value": float("nan")}, {"data": "x" * 65536}):
            with self.subTest(payload=type(payload)), self.assertRaises(ValueError):
                self.jobs.enqueue("collect", payload)
        self.assertEqual(self.jobs.list(), [])
        job = self.enqueue()
        claim = self.jobs.claim(job["id"])
        with self.assertRaises(ValueError):
            self.jobs.finish(job["id"], "succeeded", {"value": float("inf")}, lease_token=claim["lease_token"])
        self.assertEqual(self.jobs.get(job["id"])["status"], "running")
        for delay in (-1, float("nan"), float("inf"), True):
            with self.subTest(delay=delay), self.assertRaises(ValueError):
                self.jobs.defer(job["id"], delay=delay, lease_token=claim["lease_token"])


if __name__ == "__main__":
    unittest.main()
