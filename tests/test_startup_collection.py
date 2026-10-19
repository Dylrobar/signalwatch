import asyncio
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

from signalwatch.api import create_app
from signalwatch.config import load_config
from signalwatch.engine import Engine, parse_startup_sources
from signalwatch.store import Store


class StartupSourceParsingTests(unittest.TestCase):
    def test_exact_known_names_are_deduplicated_in_requested_order(self):
        self.assertEqual(parse_startup_sources(" nvd,kev,nvd ", {"nvd": True, "kev": False}), ["nvd", "kev"])

    def test_unset_or_empty_selection_does_not_request_collection(self):
        for value in (None, ""):
            self.assertEqual(parse_startup_sources(value, {"nvd": True}), [])

    def test_invalid_names_and_malformed_values_are_rejected_without_echo(self):
        for value in ("NVD", "unknown-private-value", "*", "nvd,,kev", "nvd;kev", " ", 42, "x" * 4097):
            with self.subTest(value=str(value)[:30]), self.assertRaises(ValueError) as raised:
                parse_startup_sources(value, {"nvd": True, "kev": True})
            self.assertNotIn("unknown-private-value", str(raised.exception))


class StartupScheduleTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.engine = Engine({"sources": {"nvd": True, "kev": True}}, Mock())
        self.engine._due = AsyncMock(return_value=([], 60.0))

    async def test_requested_subset_runs_before_normal_schedule_and_logs_outcome(self):
        self.engine.run = AsyncMock(side_effect=[{"sources": [{"source": "kev", "ok": True}]}, {"skipped": True}])
        with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)), self.assertLogs("signalwatch", level="INFO") as logs:
            with self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule(startup_sources=["kev"])
        self.assertEqual(self.engine.run.await_args_list, [call(sources=["kev"]), call(scheduled=True)])
        self.assertTrue(any("Startup collection requested for: kev" in row for row in logs.output))
        self.assertTrue(any("kev=ok" in row for row in logs.output))

    async def test_unset_startup_selection_keeps_normal_schedule(self):
        self.engine.run = AsyncMock(return_value={"skipped": True})
        with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)) as sleep:
            with self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule()
        self.engine.run.assert_awaited_once_with(scheduled=True)
        sleep.assert_awaited_once_with(60.0)

    async def test_busy_startup_retries_same_subset_before_normal_schedule(self):
        self.engine.run = AsyncMock(side_effect=[{"busy": True}, {"sources": []}, {"skipped": True}])
        with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=[None, asyncio.CancelledError])) as sleep:
            with self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule(startup_sources=["nvd", "kev"])
        self.assertEqual(self.engine.run.await_args_list, [call(sources=["nvd", "kev"]), call(sources=["nvd", "kev"]), call(scheduled=True)])
        self.assertEqual(sleep.await_args_list, [call(5), call(60.0)])

    async def test_permanently_busy_startup_is_bounded_then_normal_schedule_resumes(self):
        self.engine.run = AsyncMock(return_value={"busy": True})

        async def sleep(delay):
            if delay == 60.0:
                raise asyncio.CancelledError

        with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=sleep)) as waiting, self.assertLogs("signalwatch", level="WARNING") as logs:
            with self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule(startup_sources=["kev"])
        self.assertEqual(self.engine.run.await_args_list, [call(sources=["kev"])] * 60 + [call(scheduled=True)])
        self.assertEqual(waiting.await_args_list, [call(5)] * 59 + [call(60.0)])
        self.assertTrue(any("collection lock remained busy" in row for row in logs.output))

    async def test_cancellation_while_waiting_for_busy_lock_stops_startup(self):
        self.engine.run = AsyncMock(return_value={"busy": True})
        with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)):
            with self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule(startup_sources=["kev"])
        self.engine.run.assert_awaited_once_with(sources=["kev"])

    async def test_startup_error_does_not_stop_normal_schedule(self):
        self.engine.run = AsyncMock(side_effect=[RuntimeError("temporary database failure"), {"skipped": True}])
        with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)), self.assertLogs("signalwatch", level="ERROR"):
            with self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule(startup_sources=["kev"])
        self.assertEqual(self.engine.run.await_args_list, [call(sources=["kev"]), call(scheduled=True)])

    async def test_startup_preserves_active_source_retry_deadline(self):
        with tempfile.TemporaryDirectory() as folder:
            config = load_config(Path(folder) / "config.json")
            config["sources"] = {"kev": True}
            store = Store(config["db"])
            retry_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
            store.update_source("kev", status="error", retry_at=retry_at, last_run=datetime.now(timezone.utc).isoformat())
            before = store.source_state("kev")
            engine = Engine(config, store)
            engine.collector = SimpleNamespace(run_source=AsyncMock())
            with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)):
                with self.assertRaises(asyncio.CancelledError):
                    await engine.schedule(startup_sources=["kev"])
            engine.collector.run_source.assert_not_awaited()
            state = store.source_state("kev")
            for field in ("status", "retry_at", "last_run"):
                self.assertEqual(state[field], before[field])


class StartupAPITests(unittest.IsolatedAsyncioTestCase):
    async def test_lifespan_passes_operator_selection_without_persisting_it(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "config.json"
            path.write_text(json.dumps({"seed_urls": []}))
            before = path.read_bytes()
            config = load_config(path)
            with patch.dict(os.environ, {"SIGNALWATCH_STARTUP_SOURCES": "nvd,kev"}), patch("signalwatch.api.Engine") as engine_class, patch("signalwatch.api.StagingWorker.run", new=AsyncMock()), patch("signalwatch.wireless_import.WirelessImports.resume", new=AsyncMock()), patch("signalwatch.wireless_import.WirelessImports.stop", new=AsyncMock()):
                engine = engine_class.return_value
                engine.schedule = AsyncMock()
                app = create_app(config)
                async with app.router.lifespan_context(app):
                    await asyncio.sleep(0)
                engine.schedule.assert_awaited_once_with(startup_sources=["nvd", "kev"])
            self.assertEqual(path.read_bytes(), before)
            self.assertNotIn("startup_sources", config)

    async def test_no_collect_ignores_even_invalid_startup_selection(self):
        with tempfile.TemporaryDirectory() as folder:
            config = load_config(Path(folder) / "config.json")
            with patch.dict(os.environ, {"SIGNALWATCH_STARTUP_SOURCES": "invalid-private-value"}), patch("signalwatch.api.Engine") as engine_class, patch("signalwatch.api.StagingWorker.run", new=AsyncMock()), patch("signalwatch.wireless_import.WirelessImports.resume", new=AsyncMock()), patch("signalwatch.wireless_import.WirelessImports.stop", new=AsyncMock()):
                engine = engine_class.return_value
                engine.schedule = AsyncMock()
                app = create_app(config, auto_collect=False)
                async with app.router.lifespan_context(app):
                    await asyncio.sleep(0)
                engine.schedule.assert_not_called()

    async def test_auto_collect_rejects_invalid_startup_selection_before_store_creation(self):
        with patch.dict(os.environ, {"SIGNALWATCH_STARTUP_SOURCES": "unknown"}), patch("signalwatch.api.Store") as store:
            with self.assertRaisesRegex(ValueError, "SIGNALWATCH_STARTUP_SOURCES"):
                create_app({"sources": {"kev": True}})
            store.assert_not_called()
