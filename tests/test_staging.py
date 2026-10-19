import concurrent.futures
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.staging import LeaseLost, QueueFull, StagingQueue
from signalwatch.store import Store


class StagingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "staging.db"
        self.store = Store(self.path)
        self.queue = StagingQueue(self.store)
        self.clock = 1000.0
        self.timer = patch("signalwatch.staging.time.time", side_effect=lambda: self.clock)
        self.timer.start()
        self.addCleanup(self.timer.stop)

    def enqueue(self, payload=b"raw", **changes):
        return self.queue.enqueue(payload, source="upload", **changes)

    def finish(self, queue=None, batch=None):
        queue = queue or self.queue
        item = queue.claim()
        self.assertIsNotNone(item)
        queue.complete(item["id"], item["lease_token"], {} if batch is None else batch)
        return item

    def test_exact_raw_bytes_and_envelope_survive_restart_without_listing_payload_or_token(self):
        raw = b"\x00\xff\nraw upload\r\n"
        admitted = self.enqueue(raw, adapter="normalized_batch", content_type="application/json", source_url="https://example.test/feed",
                                metadata={"logical_asset": "example.test"}, observed_at="2026-10-18T10:00:00-04:00", stream_key="feed", idempotency_key="request-1")
        self.assertFalse(admitted["duplicate"])
        self.assertEqual(admitted["payload_hash"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(admitted["payload_size"], len(raw))
        self.assertEqual(admitted["observed_at"], "2026-10-18T14:00:00.000000+00:00")
        reopened = StagingQueue(Store(self.path))
        self.assertEqual(reopened.get(admitted["id"], include_payload=True)["payload"], raw)
        for item in (admitted, reopened.get(admitted["id"]), reopened.list()["items"][0]):
            self.assertNotIn("payload", item)
            self.assertNotIn("lease_token", item)
            self.assertEqual(item["metadata"], {"logical_asset": "example.test"})
        claimed = reopened.claim()
        self.assertEqual(claimed["payload"], raw)
        self.assertTrue(claimed["lease_token"])
        self.assertNotIn("lease_token", reopened.get(admitted["id"], include_payload=True))
        self.assertIsNone(reopened.get(999999))

    def test_idempotency_is_explicit_scoped_and_validates_payload_and_semantic_context(self):
        arguments = {"source": "sensor", "stream_key": "asset-1", "adapter": "json", "idempotency_key": "one",
                     "metadata": {"logical": 1}, "source_url": "https://evidence.test/", "content_type": "application/json"}
        first = self.queue.enqueue(b"same", **arguments)
        self.clock += 30
        duplicate = self.queue.enqueue(b"same", **arguments)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(duplicate["id"], first["id"])
        for changed in ({"payload": b"other"}, {"metadata": {"logical": 2}}, {"source_url": "https://different.test/"},
                        {"content_type": "text/plain"}, {"observed_at": "2026-01-01T00:00:00Z"}):
            values = {"payload": b"same", **arguments, **changed}
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.queue.enqueue(**values)
        for changed in ({"source": "different"}, {"stream_key": "asset-2"}, {"adapter": "text"}):
            different = self.queue.enqueue(b"same", **{**arguments, **changed})
            self.assertNotEqual(different["id"], first["id"])
        plain = self.enqueue(b"same")
        repeated = self.enqueue(b"same")
        self.assertNotEqual(plain["id"], repeated["id"])
        self.assertFalse(repeated["duplicate"])
        # Equivalent explicit instants compare canonically, ignoring receive time.
        one = self.enqueue(idempotency_key="instant", observed_at="2026-01-01T00:00:00Z")
        two = self.enqueue(idempotency_key="instant", observed_at="2025-12-31T19:00:00-05:00")
        self.assertEqual(one["id"], two["id"])

    def test_parallel_admission_and_claiming_across_store_instances(self):
        queues = [StagingQueue(Store(self.path)) for _ in range(4)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            admissions = list(executor.map(lambda index: queues[index % 4].enqueue(b"same", source="parallel", idempotency_key="same"), range(12)))
        self.assertEqual(len({item["id"] for item in admissions}), 1)
        self.assertEqual(sum(not item["duplicate"] for item in admissions), 1)
        for index in range(19):
            self.enqueue(stream_key=str(index))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            claimed = list(executor.map(lambda index: queues[index % 4].claim(), range(20)))
        self.assertEqual(len({item["id"] for item in claimed}), 20)
        self.assertEqual(len({item["lease_token"] for item in claimed}), 20)
        self.assertIsNone(self.queue.claim())
        self.assertEqual(self.queue.stats()["counts"]["processing"], 20)

    def test_complete_fences_wrong_or_expired_tokens_before_any_ingest(self):
        row = self.enqueue()
        claimed = self.queue.claim(lease_seconds=10)
        batch = {"entities": [{"id": "domain:should-not-exist", "kind": "domain", "name": "Wrong worker"}]}
        with self.assertRaises(LeaseLost):
            self.queue.complete(row["id"], "wrong-token", batch)
        with self.assertRaises(LeaseLost):
            self.queue.fail(row["id"], "wrong-token", "not my lease")
        self.assertIsNone(self.store.detail("domain:should-not-exist"))
        self.clock += 11
        with self.assertRaises(LeaseLost):
            self.queue.complete(row["id"], claimed["lease_token"], batch)
        self.assertEqual(self.queue.get(row["id"])["status"], "processing")
        self.assertIsNone(self.store.detail("domain:should-not-exist"))

    def test_ingest_failure_rolls_back_outputs_and_does_not_acknowledge_raw_record(self):
        row = self.enqueue()
        claimed = self.queue.claim()
        with self.assertRaises(KeyError):
            self.queue.complete(row["id"], claimed["lease_token"], {
                "entities": [{"id": "domain:partial.example", "kind": "domain", "name": "Partial"}],
                "edges": [{"from_id": "domain:partial.example"}],
            })
        self.assertIsNone(self.store.detail("domain:partial.example"))
        self.assertEqual(self.queue.get(row["id"])["status"], "processing")
        self.assertIsNone(self.queue.get(row["id"])["result"])
        outcome = self.queue.fail(row["id"], claimed["lease_token"], "Invalid normalized relationship", retryable=False)
        self.assertEqual(outcome["status"], "dead")

    def test_ack_and_normalized_snapshot_replacements_are_atomic(self):
        self.store.ingest({"kev_snapshot": [{"cveID": "CVE-2026-12345"}], "observations": [{
            "asset_id": "domain:example.test", "vendor": "acme", "product": "test", "version": "1.0",
            "source_url": "https://example.test/page", "origin": "web",
        }]})
        self.assertEqual(self.store.stats()["kev"], 1)
        self.assertEqual(self.store.stats()["observations"], 1)
        row = self.enqueue(b'{"kev_snapshot":[],"observations":[]}', adapter="normalized_batch")
        claimed = self.queue.claim()
        batch = {"kev_snapshot": [], "observations": [], "observation_pages": [{"asset_id": "domain:example.test", "source_url": "https://example.test/page"}]}
        result = self.queue.complete(row["id"], claimed["lease_token"], batch)
        self.assertEqual(result["status"], "processed")
        self.assertEqual(result["result"]["observations"], 0)
        self.assertEqual(self.store.stats()["kev"], 0)
        self.assertEqual(self.store.stats()["observations"], 0)
        reopened = StagingQueue(Store(self.path))
        self.assertEqual(reopened.get(row["id"])["status"], "processed")
        self.assertEqual(reopened.get(row["id"])["result"], result["result"])
        with self.assertRaises(LeaseLost):
            reopened.complete(row["id"], claimed["lease_token"], {"entities": [{"id": "duplicate"}]})

    def test_expired_leases_recover_with_new_tokens_and_stop_after_three_attempts(self):
        row = self.enqueue()
        first = self.queue.claim(lease_seconds=10)
        for expected in (2, 3):
            self.clock += 10
            self.queue = StagingQueue(Store(self.path))
            self.assertEqual(self.queue.stats()["expired_leases"], 1)
            claimed = self.queue.claim(lease_seconds=10)
            self.assertEqual(claimed["attempts"], expected)
            self.assertNotEqual(claimed["lease_token"], first["lease_token"])
            with self.assertRaises(LeaseLost):
                self.queue.fail(row["id"], first["lease_token"], "Stale worker")
        self.clock += 10
        self.assertIsNone(self.queue.claim())
        dead = self.queue.get(row["id"])
        self.assertEqual((dead["status"], dead["attempts"]), ("dead", 3))
        self.assertEqual(dead["error"], "Worker lease expired")

    def test_retry_backoff_blocks_later_stream_items_but_not_other_streams(self):
        first = self.enqueue(adapter="json")
        later = self.enqueue(adapter="text")  # Same source and empty stream key.
        separate = self.enqueue(stream_key="independent")
        claimed = self.queue.claim()
        self.assertEqual(claimed["id"], first["id"])
        failed = self.queue.fail(claimed["id"], claimed["lease_token"], "Temporary issue")
        self.assertEqual(failed["available_at"], self.clock + 30)
        self.assertEqual(self.finish()["id"], separate["id"])
        self.assertIsNone(self.queue.claim())
        for attempt, delay in ((2, 60), (3, None)):
            self.clock = failed["available_at"]
            claimed = self.queue.claim()
            self.assertEqual(claimed["id"], first["id"])
            self.assertEqual(claimed["attempts"], attempt)
            failed = self.queue.fail(claimed["id"], claimed["lease_token"], "Still failing")
            self.assertEqual(failed["status"], "pending" if delay else "dead")
            if delay:
                self.assertEqual(failed["available_at"], self.clock + delay)
        self.assertEqual(self.finish()["id"], later["id"])
        with self.assertRaisesRegex(ValueError, "older"):
            self.queue.retry(first["id"])

    def test_retry_preserves_order_after_newer_processed_raw_is_pruned(self):
        old = self.enqueue()
        claimed = self.queue.claim()
        self.queue.fail(old["id"], claimed["lease_token"], "Unsupported old record", retryable=False)
        self.enqueue(b"newer")
        self.finish()
        self.queue.prune(retention_days=0, max_completed=0)
        self.assertEqual(self.queue.stats()["total"], 1)
        with self.assertRaisesRegex(ValueError, "older"):
            StagingQueue(Store(self.path)).retry(old["id"])

    def test_explicit_idempotency_expires_with_processed_raw_retention_or_capacity_eviction(self):
        for removal in ("retention", "capacity"):
            with self.subTest(removal=removal):
                queue = StagingQueue(Store(Path(self.temp.name) / (removal + ".db")), max_records=1)
                original = queue.enqueue(b"same bytes", source="feed", idempotency_key="request-1")
                self.finish(queue)
                if removal == "retention":
                    queue.prune(max_completed=0)
                else:
                    queue.enqueue(b"replacement", source="other-feed")
                    self.finish(queue)
                self.assertIsNone(queue.get(original["id"]))
                # Keys are retained with the bounded raw row, not as permanent
                # tombstones; replay after removal is a new observation.
                replay = queue.enqueue(b"same bytes", source="feed", idempotency_key="request-1")
                self.assertFalse(replay["duplicate"])
                self.assertNotEqual(replay["id"], original["id"])
                self.assertEqual(replay["payload_hash"], original["payload_hash"])

    def test_retry_never_steals_a_lease_and_adapter_scope_collisions_are_rejected(self):
        first = self.enqueue(adapter="json", idempotency_key="request")
        second = self.enqueue(adapter="text", idempotency_key="request")
        claimed = self.queue.claim()
        with self.assertRaisesRegex(ValueError, "processing"):
            self.queue.retry(first["id"])
        self.queue.fail(first["id"], claimed["lease_token"], "Unknown adapter", retryable=False)
        with self.assertRaisesRegex(ValueError, "scope"):
            self.queue.retry(first["id"], adapter="text")
        newer = self.queue.claim()
        self.assertEqual(newer["id"], second["id"])
        with self.assertRaisesRegex(ValueError, "processing"):
            self.queue.retry(first["id"], adapter="auto")
        self.queue.fail(newer["id"], newer["lease_token"], "Unknown format", retryable=False)
        retried = self.queue.retry(first["id"], adapter="auto")
        self.assertEqual((retried["status"], retried["attempts"], retried["adapter"]), ("pending", 0, "auto"))
        self.assertEqual(self.queue.claim()["id"], first["id"])
        with self.assertRaises(LookupError):
            self.queue.retry(999999)

    def test_capacity_evicts_only_processed_rows_and_never_exceeds_either_limit(self):
        self.queue = StagingQueue(self.store, max_bytes=10, max_records=3, max_payload_bytes=10)
        first = self.enqueue(b"aaaa", stream_key="a")
        second = self.enqueue(b"bbbb", stream_key="b")
        with self.assertRaises(QueueFull):
            self.enqueue(b"ccc", stream_key="c")
        self.assertEqual(self.queue.stats()["bytes"], 8)
        self.finish()
        third = self.enqueue(b"ccc", stream_key="c")
        self.assertIsNone(self.queue.get(first["id"]))
        self.assertEqual(self.queue.stats()["bytes"], 7)
        claimed = self.queue.claim()
        self.assertEqual(claimed["id"], second["id"])
        self.queue.fail(second["id"], claimed["lease_token"], "Dead data stays", retryable=False)
        with self.assertRaises(QueueFull):
            self.enqueue(b"dddd", stream_key="d")
        self.assertIsNotNone(self.queue.get(second["id"]))
        self.assertIsNotNone(self.queue.get(third["id"]))
        with self.assertRaises(ValueError):
            self.enqueue(b"01234567890")
        self.queue.enqueue(b"", source="empty", stream_key="1")
        with self.assertRaises(QueueFull):
            self.queue.enqueue(b"", source="empty", stream_key="2")

    def test_failed_admission_rolls_back_any_attempted_processed_pruning(self):
        self.queue = StagingQueue(self.store, max_bytes=8, max_records=3, max_payload_bytes=8)
        first = self.enqueue(b"aa", stream_key="a")
        self.finish()
        self.enqueue(b"bbbbbb", stream_key="b")
        with self.assertRaises(QueueFull):
            self.enqueue(b"ccc", stream_key="c")
        self.assertEqual(self.queue.stats()["bytes"], 8)
        self.assertIsNotNone(self.queue.get(first["id"]))

    def test_retention_and_completed_count_prune_only_processed_records(self):
        old = self.enqueue(stream_key="old")
        self.finish()
        dead = self.enqueue(stream_key="dead")
        claimed = self.queue.claim()
        self.queue.fail(dead["id"], claimed["lease_token"], "Needs review", retryable=False)
        self.clock += 8 * 86400
        middle = self.enqueue(stream_key="middle")
        self.finish()
        newest = self.enqueue(stream_key="newest")
        self.finish()
        pending = self.enqueue(stream_key="pending")
        outcome = self.queue.prune(retention_days=7, max_completed=1)
        self.assertEqual(outcome["removed_records"], 2)
        self.assertEqual(outcome["removed_bytes"], 6)
        self.assertIsNone(self.queue.get(old["id"]))
        self.assertIsNone(self.queue.get(middle["id"]))
        self.assertIsNotNone(self.queue.get(newest["id"]))
        self.assertIsNotNone(self.queue.get(dead["id"]))
        self.assertIsNotNone(self.queue.get(pending["id"]))

    def test_small_diagnostics_and_invalid_envelopes(self):
        for changes in ({"source": ""}, {"metadata": []}, {"metadata": {"value": "x" * 17000}}, {"observed_at": "invalid"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.queue.enqueue(b"raw", **{"source": "test", **changes})
        row = self.enqueue()
        claimed = self.queue.claim()
        failed = self.queue.fail(row["id"], claimed["lease_token"], "x" * 10000, retryable=False)
        self.assertEqual(len(failed["error"]), 2000)
        self.assertNotIn("payload", failed)
        self.assertNotIn("lease_token", failed)
        with self.assertRaises(ValueError):
            self.queue.list(status="unknown")


if __name__ == "__main__":
    unittest.main()
