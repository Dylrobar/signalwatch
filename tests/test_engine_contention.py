import asyncio
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from signalwatch.config import load_config
from signalwatch.engine import Engine
from signalwatch.store import Store


class EngineContentionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / "config.json")
        self.store = Store(self.config["db"])
        self.engine = Engine(self.config, self.store)

    async def check_sibling_guard(self, failing_status):
        loop = asyncio.get_running_loop()
        failed = asyncio.Event()
        sibling_started = asyncio.Event()
        sibling_finished = asyncio.Event()
        release = threading.Event()
        update = self.store.update_source

        def status_write(name, **fields):
            if name == "news" and fields.get("status") == failing_status:
                loop.call_soon_threadsafe(failed.set)
                raise sqlite3.OperationalError("database is locked")
            return update(name, **fields)

        def slow_database_work():
            loop.call_soon_threadsafe(sibling_started.set)
            if not release.wait(5):
                raise RuntimeError("Test did not release sibling database work")
            loop.call_soon_threadsafe(sibling_finished.set)
            return {"records": 1}

        async def collect(name):
            if name == "news":
                raise RuntimeError("Source collection failed")
            return await asyncio.to_thread(slow_database_work)

        self.engine._collect_source = AsyncMock(side_effect=collect)
        with patch.object(self.store, "update_source", side_effect=status_write), self.assertLogs("signalwatch", level="ERROR"):
            running = asyncio.create_task(self.engine.run(["news", "kev"]))
            try:
                await asyncio.wait_for(asyncio.gather(failed.wait(), sibling_started.wait()), 2)
                # Let the failure propagate while the sibling's worker thread remains blocked.
                await asyncio.sleep(0)
                self.assertFalse(running.done())
                self.assertTrue(self.engine.running)
                self.assertTrue(self.engine.busy())
                self.assertEqual(await self.engine.run(["kev"]), {"busy": True})
                competing = Engine(self.config, self.store)
                competing._collect_source = AsyncMock()
                self.assertTrue((await competing.run(["kev"]))["busy"])
                competing._collect_source.assert_not_awaited()
            finally:
                release.set()
                outcomes = await asyncio.wait_for(asyncio.gather(running, return_exceptions=True), 3)
                await asyncio.wait_for(sibling_finished.wait(), 1)
        self.assertFalse(self.engine.running)
        self.assertFalse(self.engine.busy())
        self.assertFalse(self.engine.current_sources)
        self.assertEqual(self.store.source_state("kev")["status"], "ok")
        return outcomes[0]

    async def test_failed_start_cleans_state_and_waits_for_sibling_database_work(self):
        outcome = await self.check_sibling_guard("running")
        self.engine._collect_source.assert_awaited_once_with("kev")
        failure = next(row for row in outcome["sources"] if row["source"] == "news")
        self.assertFalse(failure["ok"])
        self.assertEqual(failure["error"], "database is locked")
        self.assertEqual(self.store.source_state("news")["status"], "error")

    async def test_failed_error_state_write_propagates_only_after_sibling_finishes(self):
        outcome = await self.check_sibling_guard("error")
        self.assertIsInstance(outcome, sqlite3.OperationalError)
        self.assertEqual(self.engine.last_error, "database is locked")
        self.assertEqual(self.engine.last_result["error"], "database is locked")

    async def test_interrupted_status_write_does_not_replace_cancellation(self):
        update = self.store.update_source

        def status_write(name, **fields):
            if fields.get("status") == "interrupted":
                raise sqlite3.OperationalError("database is locked")
            return update(name, **fields)

        self.engine._collect_source = AsyncMock(side_effect=asyncio.CancelledError)
        with patch.object(self.store, "update_source", side_effect=status_write):
            with self.assertLogs("signalwatch", level="ERROR"), self.assertRaises(asyncio.CancelledError):
                await self.engine.run(["news"])
        self.assertFalse(self.engine.current_sources)
        self.assertFalse(self.engine.running)
        self.assertFalse(self.engine.busy())

    async def test_bootstrap_failed_start_clears_current_source(self):
        update = self.store.update_source

        def status_write(name, **fields):
            if fields.get("status") == "running":
                raise sqlite3.OperationalError("database is locked")
            return update(name, **fields)

        self.engine.collector = SimpleNamespace(bootstrap_year=AsyncMock())
        with patch.object(self.store, "update_source", side_effect=status_write):
            with self.assertRaisesRegex(sqlite3.OperationalError, "database is locked"):
                await self.engine.run(years=[2025])
        self.engine.collector.bootstrap_year.assert_not_awaited()
        self.assertFalse(self.engine.current_sources)
        self.assertFalse(self.engine.busy())

    async def test_scheduler_retries_after_sixty_seconds_following_database_lock(self):
        self.engine.run = AsyncMock(side_effect=[sqlite3.OperationalError("database is locked"), {"skipped": True}])
        self.engine._due = AsyncMock(return_value=([], 60))
        sleep = AsyncMock(side_effect=[None, asyncio.CancelledError])
        with patch("signalwatch.engine.asyncio.sleep", new=sleep):
            with self.assertLogs("signalwatch", level="ERROR"), self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule()
        self.assertEqual(self.engine.run.await_count, 2)
        self.assertEqual([call.args for call in sleep.await_args_list], [(60.0,), (60,)])


if __name__ == "__main__":
    unittest.main()
