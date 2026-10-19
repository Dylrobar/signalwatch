import asyncio
import csv
import gzip
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.config import DEFAULTS
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.staging import QueueFull
from signalwatch.store import Store
from signalwatch.wireless import iter_wigle_chunks, normalize_wigle, register_dataset, stats
from signalwatch.wireless_import import WirelessImports


def export_bytes():
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["WigleWifi-1.6", "appRelease=2.111"])
    writer.writerow(["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "Frequency", "RSSI", "CurrentLatitude", "CurrentLongitude", "AltitudeMeters", "AccuracyMeters", "RCOIs", "MfgrId", "Type"])
    row = ["02:00:00:00:00:01", "Example network", "[WPA2]", "2026-01-01 12:00:00", "6", "2437", "-60", "44", "-73", "50", "5", "", "", "WIFI"]
    writer.writerow(row)
    writer.writerow(row)
    writer.writerow([*row[:7], "44.01", *row[8:]])
    writer.writerow(["C2:00:00:00:00:02", "Example beacon", "Misc", "1970-01-01 00:00:00", "", "7936", "127", "44", "-73", "50", "5", "", "76", "BLE"])
    writer.writerow(["310260_100_200", "Example carrier", "LTE", "2026-01-02 12:00:00", "100", "100", "-100", "44", "-73", "50", "5", "", "", "LTE"])
    return output.getvalue().encode()


class WirelessImportTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.config = {**json.loads(json.dumps(DEFAULTS)), "db": str(self.root / "monitor.db"),
                       "cache_dir": str(self.root / "cache"), "wireless_chunk_rows": 2,
                       "staging_poll_seconds": 0.01}
        self.store = Store(self.config["db"])
        self.imports = WirelessImports(self.store, self.config)
        self.worker = StagingWorker(self.store, self.config)
        self.worker_task = asyncio.create_task(self.worker.run())

    async def asyncTearDown(self):
        await self.imports.stop()
        self.worker_task.cancel()
        await asyncio.gather(self.worker_task, return_exceptions=True)

    def archive(self, payload=None):
        compressed = gzip.compress(export_bytes() if payload is None else payload, mtime=0)
        path = self.imports.directory / "example.csv.gz"
        path.write_bytes(compressed)
        return path

    async def finished(self, dataset_id, expected="complete"):
        deadline = asyncio.get_running_loop().time() + 8
        while asyncio.get_running_loop().time() < deadline:
            state = self.imports.state(dataset_id)
            if state.get("status") in {"complete", "failed"}:
                self.assertEqual(state["status"], expected, state.get("error"))
                return state
            await asyncio.sleep(0.02)
        self.fail("Wireless import did not reach a terminal state")

    async def test_chunked_ingestion_preserves_repeats_and_complete_reupload_is_idempotent(self):
        path = self.archive()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        started = await self.imports.start(path, "Example export.csv.gz", digest, "https://example.test/export")
        state = await self.finished(started["dataset_id"])
        self.assertEqual((state["queued_rows"], state["expected_rows"], state["chunks"]), (5, 5, 3))
        summary = stats(self.store)
        self.assertEqual((summary["observations"], summary["devices"]), (5, 3))
        self.assertEqual(self.imports.archive(started["dataset_id"]).read_bytes(), path.read_bytes())
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM wireless_observation_geo").fetchone()[0], 5)
            self.assertEqual(conn.execute("SELECT count(*) FROM raw_ingress WHERE status='processed'").fetchone()[0], 3)
            self.assertIsNone(conn.execute("SELECT observed_at FROM wireless_observations WHERE radio_type='BLE'").fetchone()[0])
        repeated = await self.imports.start(path, "Renamed.csv.gz", digest)
        self.assertTrue(repeated["duplicate"])
        self.assertEqual(repeated["status"], "complete")
        self.assertEqual(stats(self.store)["observations"], 5)

    async def test_resume_recovers_partial_import_after_staging_history_is_absent(self):
        path = self.archive()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        identity = "wireless:" + digest
        first = next(iter_wigle_chunks(path, rows_per_chunk=2))
        self.store.ingest(normalize_wigle(first))
        self.store.update_source("wireless-import:" + identity, status="processing", archive_path=str(path),
                                 dataset_name="Recovered.csv.gz", source_hash=digest,
                                 source_url="https://example.test/recovered", queued_rows=2)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM raw_ingress").fetchone()[0], 0)
        await self.imports.resume()
        await self.finished(identity)
        self.assertEqual(stats(self.store)["observations"], 5)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM wireless_observations WHERE source_row IN (1,2)").fetchone()[0], 2)
            self.assertEqual(conn.execute("SELECT status FROM wireless_datasets WHERE id=?", (identity,)).fetchone()[0], "complete")

    async def test_backpressure_can_be_stopped_and_resumed_without_losing_the_archive(self):
        path = self.archive()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        queue = staging_queue(self.store, self.config)
        with patch("signalwatch.wireless_import.staging_queue", return_value=queue), patch.object(queue, "enqueue", side_effect=QueueFull("full")) as enqueue:
            started = await self.imports.start(path, "Backpressure.csv.gz", digest)
            deadline = asyncio.get_running_loop().time() + 3
            while not enqueue.called and asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(0.01)
            self.assertTrue(enqueue.called)
            await self.imports.stop()
        self.assertEqual(stats(self.store)["observations"], 0)
        self.assertTrue(self.imports.archive(started["dataset_id"]).is_file())
        await self.imports.resume()
        await self.finished(started["dataset_id"])
        self.assertEqual(stats(self.store)["observations"], 5)

    async def test_concurrent_start_schedules_one_import(self):
        path = self.archive()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        results = await asyncio.gather(self.imports.start(path, "First.csv.gz", digest),
                                       self.imports.start(path, "Second.csv.gz", digest))
        self.assertEqual(sorted(row["duplicate"] for row in results), [False, True])
        self.assertEqual(len(self.imports.tasks), 1)
        await self.finished(results[0]["dataset_id"])
        self.assertEqual(stats(self.store)["observations"], 5)

    async def test_archive_lookup_rejects_missing_outside_and_symlink_paths(self):
        outside = self.root / "outside.csv"
        outside.write_bytes(b"outside")
        symlink = self.imports.directory / "linked.csv"
        symlink.symlink_to(outside)
        for value in (str(outside), str(symlink), str(self.imports.directory / "missing.csv")):
            with self.subTest(path=value):
                self.store.update_source("wireless-import:bad", archive_path=value)
                with self.assertRaises(LookupError):
                    self.imports.archive("bad")
        valid = self.archive()
        self.store.update_source("wireless-import:valid", archive_path=str(valid))
        self.assertEqual(self.imports.archive("valid"), valid.resolve())

    async def test_resume_missing_archive_records_failure_without_creating_queue_records(self):
        digest = "a" * 64
        identity = "wireless:" + digest
        register_dataset(self.store, {"source_hash": digest})
        self.store.update_source("wireless-import:" + identity, status="importing", source_hash=digest,
                                 dataset_name="Missing.csv.gz", archive_path=str(self.imports.directory / "missing.gz"))
        await self.imports.resume()
        state = self.imports.state(identity)
        self.assertEqual(state["status"], "failed")
        self.assertIn("archive", state["error"].lower())
        self.assertFalse(self.imports.tasks)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT status FROM wireless_datasets WHERE id=?", (identity,)).fetchone()[0], "failed")
        self.assertEqual(staging_queue(self.store, self.config).stats()["total"], 0)

    async def test_empty_and_bad_header_exports_fail_without_partial_observations(self):
        for content in (b"WigleWifi-1.6\nMAC,Type\n", b"not,a,wigle,export\n"):
            with self.subTest(content=content):
                path = self.archive(content)
                started = await self.imports.start(path, "Invalid.csv.gz", hashlib.sha256(path.read_bytes()).hexdigest())
                state = await self.finished(started["dataset_id"], expected="failed")
                self.assertTrue(state["error"])
                self.assertTrue(self.imports.archive(started["dataset_id"]).is_file())
        self.assertEqual(stats(self.store)["observations"], 0)
