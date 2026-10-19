import asyncio
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from signalwatch.async_utils import gather, to_thread
from signalwatch.collectors import Collector
from signalwatch.config import load_config
from signalwatch.engine import Engine
from signalwatch.ingestion import StagingWorker
from signalwatch.store import Store


class EngineCancellationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / "config.json")
        self.store = Store(self.config["db"])
        self.engine = Engine(self.config, self.store)

    def blocked_worker(self, result=None, *, error=None):
        loop = asyncio.get_running_loop()
        started, finished = asyncio.Event(), asyncio.Event()
        release = threading.Event()

        def work(*args, **kwargs):
            loop.call_soon_threadsafe(started.set)
            if not release.wait(5):
                raise RuntimeError("Test did not release the worker")
            try:
                if error is not None:
                    raise error
                # A real write establishes that cancellation does not close the
                # collection's ownership before its last database operation.
                self.store.update_source("worker-finished", status="ok")
                return result
            finally:
                loop.call_soon_threadsafe(finished.set)

        return work, started, finished, release

    async def assert_guard_held(self, running):
        await asyncio.sleep(0)
        self.assertFalse(running.done())
        self.assertTrue(self.engine.running)
        self.assertTrue(self.engine.busy())
        self.assertEqual(await self.engine.run([]), {"busy": True})
        competing = Engine(self.config, self.store)
        self.assertTrue((await competing.run([]))["busy"])

    async def check_cancelled_worker(self, running, started, finished, release):
        try:
            await asyncio.wait_for(started.wait(), 2)
            running.cancel()
            await self.assert_guard_held(running)
            running.cancel()  # Repeated shutdown requests must not detach it.
            await self.assert_guard_held(running)
            self.assertFalse(finished.is_set())
        finally:
            release.set()
            result = (await asyncio.wait_for(asyncio.gather(running, return_exceptions=True), 3))[0]
        self.assertIsInstance(result, asyncio.CancelledError)
        self.assertTrue(finished.is_set())
        self.assertFalse(self.engine.running)
        self.assertFalse(self.engine.busy())
        self.assertFalse(self.engine.current_sources)

    async def test_cancel_during_reconciliation_keeps_guards_until_worker_finishes(self):
        work, started, finished, release = self.blocked_worker({})
        self.engine._drain_staging = AsyncMock(return_value={})
        with patch.object(self.store, "reconcile", side_effect=work), patch.object(self.store, "prune_events") as prune:
            running = asyncio.create_task(self.engine.run([]))
            await self.check_cancelled_worker(running, started, finished, release)
        prune.assert_not_called()

    async def test_cancel_during_staging_keeps_guards_until_worker_finishes(self):
        work, started, finished, release = self.blocked_worker({"claimed": 0})
        with patch.object(StagingWorker, "drain", side_effect=work), patch.object(self.store, "reconcile") as reconcile:
            running = asyncio.create_task(self.engine.run([]))
            await self.check_cancelled_worker(running, started, finished, release)
        reconcile.assert_not_called()

    async def test_cancel_during_collector_ingest_keeps_guards_until_worker_finishes(self):
        work, started, finished, release = self.blocked_worker({"records": 1})
        collector = Collector(self.config, self.store)

        async def collect(name):
            return await collector.emit({"advisories": []})

        self.engine._collect_source = AsyncMock(side_effect=collect)
        with patch.object(self.store, "ingest", side_effect=work):
            running = asyncio.create_task(self.engine.run(["news"]))
            await self.check_cancelled_worker(running, started, finished, release)
        self.assertEqual(self.store.source_state("news")["status"], "interrupted")

    async def test_cancelled_background_staging_worker_finishes_its_current_batch(self):
        work, started, finished, release = self.blocked_worker({"claimed": 1})
        worker = StagingWorker(self.store, self.config)
        with patch.object(worker, "drain", side_effect=work) as drain:
            running = asyncio.create_task(worker.run())
            try:
                await asyncio.wait_for(started.wait(), 2)
                running.cancel()
                await asyncio.sleep(0)
                running.cancel()
                await asyncio.sleep(0)
                self.assertFalse(running.done())
                self.assertFalse(finished.is_set())
            finally:
                release.set()
                result = (await asyncio.wait_for(asyncio.gather(running, return_exceptions=True), 3))[0]
        self.assertIsInstance(result, asyncio.CancelledError)
        self.assertTrue(finished.is_set())
        self.assertEqual(drain.call_count, 1)

    async def test_cancelled_source_siblings_are_all_joined_before_unlocking(self):
        workers = [self.blocked_worker({"records": 1}) for _ in range(2)]

        async def collect(name):
            return await to_thread(workers[0 if name == "news" else 1][0])

        self.engine._collect_source = AsyncMock(side_effect=collect)
        running = asyncio.create_task(self.engine.run(["news", "kev"]))
        try:
            await asyncio.wait_for(asyncio.gather(*(worker[1].wait() for worker in workers)), 2)
            running.cancel()
            await self.assert_guard_held(running)
            workers[0][3].set()
            await asyncio.wait_for(workers[0][2].wait(), 2)
            running.cancel()
            await self.assert_guard_held(running)
        finally:
            for worker in workers:
                worker[3].set()
            result = (await asyncio.wait_for(asyncio.gather(running, return_exceptions=True), 3))[0]
        self.assertIsInstance(result, asyncio.CancelledError)
        self.assertTrue(all(worker[2].is_set() for worker in workers))
        self.assertFalse(self.engine.busy())
        self.assertFalse(self.engine.current_sources)
        for name in ("news", "kev"):
            self.assertEqual(self.store.source_state(name)["status"], "interrupted")

    async def test_worker_error_does_not_replace_cancellation(self):
        work, started, finished, release = self.blocked_worker(error=RuntimeError("late worker failure"))
        self.engine._drain_staging = AsyncMock(return_value={})
        with patch.object(self.store, "reconcile", side_effect=work):
            running = asyncio.create_task(self.engine.run([]))
            await self.check_cancelled_worker(running, started, finished, release)

    async def test_sibling_exception_waits_for_started_worker(self):
        work, started, finished, release = self.blocked_worker("done")

        async def fail():
            await started.wait()
            raise ValueError("collector failed")

        running = asyncio.create_task(gather(fail(), to_thread(work)))
        try:
            await asyncio.wait_for(started.wait(), 2)
            await asyncio.sleep(0)
            self.assertFalse(running.done())
        finally:
            release.set()
            result = (await asyncio.wait_for(asyncio.gather(running, return_exceptions=True), 3))[0]
        self.assertIsInstance(result, ValueError)
        self.assertTrue(finished.is_set())


if __name__ == "__main__":
    unittest.main()
