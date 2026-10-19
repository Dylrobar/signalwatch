import asyncio
import hashlib
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.config import load_config
from signalwatch.ingestion import staging_queue
from signalwatch.store import Store
from signalwatch.wireless_api import _sqlite_write
from signalwatch.wireless_import import WirelessImports
from tests.test_wireless_import import export_bytes


class WirelessCancellationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / "config.json")
        self.store = Store(self.config["db"])
        self.imports = WirelessImports(self.store, self.config)
        self.archive = self.imports.directory / "export.csv"
        self.archive.write_bytes(export_bytes())
        self.digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def blocked(self, function):
        loop = asyncio.get_running_loop()
        started, finished = asyncio.Event(), asyncio.Event()
        release = threading.Event()

        def work(*args, **kwargs):
            loop.call_soon_threadsafe(started.set)
            try:
                if not release.wait(5):
                    raise RuntimeError("Test did not release the worker")
                return function(*args, **kwargs)
            finally:
                loop.call_soon_threadsafe(finished.set)

        return work, started, finished, release

    async def test_cancelled_enrichment_write_finishes_before_the_task_exits(self):
        work, started, finished, release = self.blocked(self.store.update_source)
        running = asyncio.create_task(_sqlite_write(work, "wireless_enrichment", status="running"))
        try:
            await asyncio.wait_for(started.wait(), 2)
            running.cancel()
            await asyncio.sleep(0.02)
            running.cancel()
            await asyncio.sleep(0.02)
            self.assertFalse(running.done())
            self.assertFalse(finished.is_set())
        finally:
            release.set()
            result = (await asyncio.wait_for(asyncio.gather(running, return_exceptions=True), 3))[0]
            await asyncio.wait_for(finished.wait(), 2)
        self.assertIsInstance(result, asyncio.CancelledError)
        self.assertEqual(self.store.source_state("wireless_enrichment")["status"], "running")

    async def test_stop_joins_an_inflight_enqueue_and_keeps_import_resumable(self):
        queue = staging_queue(self.store, self.config)
        work, started, finished, release = self.blocked(queue.enqueue)
        with patch("signalwatch.wireless_import.staging_queue", return_value=queue), patch.object(queue, "enqueue", side_effect=work) as enqueue:
            result = await self.imports.start(self.archive, "Export.csv", self.digest)
            running = self.imports.tasks[result["dataset_id"]]
            stopping = None
            try:
                await asyncio.wait_for(started.wait(), 2)
                stopping = asyncio.create_task(self.imports.stop())
                await asyncio.sleep(0.02)
                running.cancel()
                await asyncio.sleep(0.02)
                self.assertFalse(stopping.done())
                self.assertFalse(running.done())
                self.assertFalse(finished.is_set())
            finally:
                release.set()
                await asyncio.wait_for(stopping or self.imports.stop(), 3)
                await asyncio.wait_for(finished.wait(), 2)
        self.assertEqual(enqueue.call_count, 1)
        self.assertEqual(queue.stats()["total"], 1)
        self.assertEqual(self.imports.state(result["dataset_id"])["status"], "importing")
        self.assertTrue(self.imports.archive(result["dataset_id"]).is_file())

    async def test_repeated_cancellation_does_not_close_an_iterator_still_reading(self):
        work, started, finished, release = self.blocked(lambda: None)
        closed = []

        class Reader:
            def __next__(self):
                return work()

            def close(self):
                closed.append(finished.is_set())

        with patch("signalwatch.wireless.iter_wigle_chunks", return_value=Reader()):
            result = await self.imports.start(self.archive, "Export.csv", self.digest)
            running = self.imports.tasks[result["dataset_id"]]
            try:
                await asyncio.wait_for(started.wait(), 2)
                running.cancel()
                await asyncio.sleep(0.02)
                running.cancel()
                await asyncio.sleep(0.02)
                self.assertFalse(running.done())
                self.assertFalse(closed)
            finally:
                release.set()
                outcome = (await asyncio.wait_for(asyncio.gather(running, return_exceptions=True), 3))[0]
                await asyncio.wait_for(finished.wait(), 2)
        self.assertIsInstance(outcome, asyncio.CancelledError)
        self.assertEqual(closed, [True])


if __name__ == "__main__":
    unittest.main()
