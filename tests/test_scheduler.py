import asyncio
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, call, patch

from signalwatch.config import load_config
from signalwatch.engine import Engine, EXTENSION_ADAPTERS, source_outcome
from signalwatch.staging import StagingQueue
from signalwatch.store import Store


class ClockDatetime(datetime):
    current = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)


class SchedulerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / "config.json")
        self.config["sources"] = {"news": True, "kev": True, "corporate": True, "web": True}
        self.store = Store(self.config["db"])
        self.engine = self.make_engine()
        ClockDatetime.current = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)
        self.clock_patch = patch("signalwatch.engine.datetime", ClockDatetime)
        self.clock_patch.start()
        self.addCleanup(self.clock_patch.stop)

    def make_engine(self):
        engine = Engine(self.config, self.store)
        engine.collector = SimpleNamespace(http=object())
        engine._collect_source = AsyncMock(return_value={"records": 1})
        return engine

    def advance(self, minutes):
        ClockDatetime.current += timedelta(minutes=minutes)

    def stamp(self, minutes=0):
        return (ClockDatetime.current + timedelta(minutes=minutes)).isoformat(timespec="seconds")

    async def test_independent_family_schedules_persist_across_restart(self):
        first = await self.engine.run(scheduled=True)
        self.assertEqual({row["source"] for row in first["sources"]}, set(self.config["sources"]))
        self.assertEqual(self.store.source_state("news")["next_run"], self.stamp(15))
        self.assertEqual(self.store.source_state("kev")["next_run"], self.stamp(360))
        self.assertEqual(self.store.source_state("corporate")["next_run"], self.stamp(10080))
        self.assertEqual(self.store.source_state("web")["next_run"], self.stamp(30))
        previous_kev = self.store.source_state("kev")
        self.advance(14)
        restarted = self.make_engine()
        self.assertTrue((await restarted.run(scheduled=True))["skipped"])
        restarted._collect_source.assert_not_awaited()
        self.advance(1)
        due = await restarted.run(scheduled=True)
        self.assertEqual([row["source"] for row in due["sources"]], ["news"])
        self.advance(15)
        due = await restarted.run(scheduled=True)
        self.assertEqual({row["source"] for row in due["sources"]}, {"news", "web"})
        self.assertEqual(self.store.source_state("kev"), previous_kev)

    async def test_dynamic_intervals_recompute_next_run_without_forcing_manual_schedule(self):
        self.config["sources"] = {"news": True}
        await self.engine.run(scheduled=True)
        self.advance(15)
        self.config["source_intervals"] = {"news": 60}
        result = await self.engine.run(scheduled=True)
        self.assertTrue(result["skipped"])
        self.assertEqual(self.store.source_state("news")["next_run"], self.stamp(45))
        self.config["source_intervals"]["news"] = 5
        self.assertFalse((await self.engine.run(scheduled=True)).get("skipped", False))
        self.assertEqual(self.store.source_state("news")["next_run"], self.stamp(5))
        # Manual collection still runs immediately, even when disabled in the schedule.
        self.config["sources"]["news"] = False
        before = self.engine._collect_source.await_count
        await self.engine.run(["news"])
        self.assertEqual(self.engine._collect_source.await_count, before + 1)

    async def test_retry_at_is_stronger_than_interval_and_manual_run_cannot_override_it(self):
        self.config["sources"] = {"news": True}
        retry_at = self.stamp(120)

        async def limited(name):
            self.store.update_source(name, retry_at=retry_at)
            raise RuntimeError("HTTP 429: rate limited")

        self.engine._collect_source.side_effect = limited
        with self.assertLogs("signalwatch", level="ERROR"):
            await self.engine.run(scheduled=True)
        state = self.store.source_state("news")
        self.assertEqual(state["status"], "error")
        self.assertEqual(state["next_run"], retry_at)
        self.assertEqual(state["last_run"], self.stamp())
        self.advance(15)
        self.assertTrue((await self.engine.run(scheduled=True))["skipped"])
        manual = await self.engine.run(["news"])
        self.assertTrue(manual["sources"][0]["skipped"])
        self.assertEqual(self.engine._collect_source.await_count, 1)
        self.assertEqual(self.store.source_state("news"), state)

    async def test_failure_does_not_hotloop_and_does_not_stop_another_due_family(self):
        self.config["sources"] = {"news": True, "web": True}

        async def collect(name):
            if name == "news":
                raise RuntimeError("Source unavailable")
            return {"records": 1}

        self.engine._collect_source.side_effect = collect
        with self.assertLogs("signalwatch", level="ERROR"):
            await self.engine.run(scheduled=True)
        self.assertEqual(self.store.source_state("news")["next_run"], self.stamp(15))
        self.assertEqual(self.store.source_state("web")["status"], "ok")
        self.advance(1)
        result = await self.make_engine().run(scheduled=True)
        self.assertTrue(result["skipped"])

    async def test_legacy_last_finish_seeds_schedule_and_disabled_families_do_not_run(self):
        self.config["sources"] = {"news": True, "web": False}
        self.store.update_source("news", status="ok", finished_at=self.stamp(-10), last_success=self.stamp(-10))
        result = await self.engine.run(scheduled=True)
        self.assertTrue(result["skipped"])
        self.assertEqual(self.store.source_state("news")["next_run"], self.stamp(5))
        self.assertEqual(self.store.source_state("web"), {})

    async def test_all_unconfigured_providers_do_not_create_a_success_timestamp(self):
        self.config["sources"] = {"corporate": True}
        self.store.update_source("corporate", last_success=self.stamp(-20))
        self.engine._collect_source.return_value = {"records": 0, "provider_health": {
            "registry": {"status": "unconfigured"}, "optional": {"status": "disabled"},
        }}
        result = await self.engine.run(["corporate"])
        state = self.store.source_state("corporate")
        self.assertEqual(state["status"], "unconfigured")
        self.assertIsNone(state["last_success"])
        self.assertEqual(state["next_run"], self.stamp(10080))
        self.assertTrue(result["sources"][0]["skipped"])
        self.assertFalse(result["sources"][0]["ok"])

    async def test_provider_failures_are_error_or_partial_and_keep_details(self):
        self.config["sources"] = {"corporate": True}
        self.engine._collect_source.return_value = {"provider_health": {
            "registry": {"status": "error", "error": "Unavailable"}, "optional": {"status": "unconfigured"},
        }}
        await self.engine.run(["corporate"])
        state = self.store.source_state("corporate")
        self.assertEqual(state["status"], "error")
        self.assertIsNone(state.get("last_success"))
        self.assertIn("registry: Unavailable", state["error"])
        self.engine._collect_source.return_value["provider_health"]["registry2"] = {"status": "ok"}
        await self.engine.run(["corporate"])
        state = self.store.source_state("corporate")
        self.assertEqual(state["status"], "partial")
        self.assertEqual(state["last_success"], self.stamp())

    async def test_deferred_providers_do_not_invent_errors_or_fresh_success(self):
        self.config["sources"] = {"corporate": True}
        self.engine._collect_source.return_value = {"records": 0, "provider_health": {
            "registry": {"status": "deferred"}, "optional": {"status": "unconfigured"},
        }}
        for previous in (None, self.stamp(-20)):
            with self.subTest(previous=previous):
                self.store.update_source("corporate", last_success=previous)
                result = await self.engine.run(["corporate"])
                state = self.store.source_state("corporate")
                self.assertEqual(state["status"], "partial")
                self.assertEqual(state.get("last_success"), previous)
                self.assertIsNone(state["error"])
                self.assertEqual(state["next_run"], self.stamp(10080))
                self.assertTrue(result["sources"][0]["skipped"])
                self.assertFalse(result["sources"][0]["ok"])

    async def test_success_with_deferred_is_partial_and_real_failure_remains_an_error(self):
        self.config["sources"] = {"corporate": True}
        self.engine._collect_source.return_value = {"provider_health": {
            "registry": {"status": "ok"}, "pending": {"status": "deferred"},
        }}
        result = await self.engine.run(["corporate"])
        state = self.store.source_state("corporate")
        self.assertEqual(state["status"], "partial")
        self.assertEqual(state["last_success"], self.stamp())
        self.assertIsNone(state["error"])
        self.assertTrue(result["sources"][0]["ok"])
        self.assertNotIn("skipped", result["sources"][0])
        self.advance(1)
        self.engine._collect_source.return_value["provider_health"]["registry"] = {"status": "error", "error": "Unavailable"}
        await self.engine.run(["corporate"])
        state = self.store.source_state("corporate")
        self.assertEqual(state["status"], "error")
        self.assertEqual(state["last_success"], self.stamp(-1))
        self.assertEqual(state["error"], "registry: Unavailable")

    async def test_partial_with_explicit_deferred_marker_is_neutral_pending(self):
        self.config["sources"] = {"threat": True}
        for successful in (False, True):
            with self.subTest(successful=successful):
                previous = self.stamp(-20)
                self.store.update_source("threat", last_success=previous)
                health = {"pending": {"status": "partial", "deferred": True, "staged": 0, "records": 0}}
                if successful:
                    health["feed"] = {"status": "ok", "records": 1}
                self.engine._collect_source.return_value = {"provider_health": health}
                result = (await self.engine.run(["threat"]))["sources"][0]
                state = self.store.source_state("threat")
                self.assertEqual(state["status"], "partial")
                self.assertIsNone(state["error"])
                self.assertEqual(state["last_success"], self.stamp() if successful else previous)
                self.assertEqual(state["next_run"], self.stamp(15))
                self.assertEqual(result["ok"], successful)
                self.assertEqual(result.get("skipped", False), not successful)

    async def test_manual_process_guard_and_persisted_recheck_prevent_duplicate_scheduled_run(self):
        self.config["sources"] = {"news": True}
        started, release = asyncio.Event(), asyncio.Event()

        async def collect(name):
            started.set()
            await release.wait()
            return {"records": 1}

        self.engine._collect_source.side_effect = collect
        manual = asyncio.create_task(self.engine.run(["news"]))
        await started.wait()
        restarted = self.make_engine()
        self.assertTrue((await restarted.run(scheduled=True))["busy"])
        release.set()
        await manual
        self.assertTrue((await restarted.run(scheduled=True))["skipped"])
        restarted._collect_source.assert_not_awaited()

    async def test_adaptive_wait_is_short_and_can_be_cancelled(self):
        self.config["sources"] = {"news": True}
        self.store.update_source("news", last_run=self.stamp(-14.75))
        with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)) as sleep:
            with self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule()
            sleep.assert_awaited_once_with(15.0)
        self.store.update_source("news", last_run=self.stamp())
        with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)) as sleep:
            with self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule()
            sleep.assert_awaited_once_with(60.0)

    async def test_failed_schedule_state_read_does_not_kill_the_scheduler(self):
        self.engine.run = AsyncMock(return_value={"skipped": True})
        self.engine._due = AsyncMock(side_effect=RuntimeError("Temporary database read failure"))
        with patch("signalwatch.engine.asyncio.sleep", new=AsyncMock(side_effect=asyncio.CancelledError)) as sleep:
            with self.assertLogs("signalwatch", level="ERROR"), self.assertRaises(asyncio.CancelledError):
                await self.engine.schedule()
            sleep.assert_awaited_once_with(60.0)

    async def test_extension_adapters_are_imported_lazily_with_shared_http(self):
        engine = Engine(self.config, self.store)
        engine.collector = SimpleNamespace(http=object())
        for family, (module, function) in EXTENSION_ADAPTERS.items():
            adapter = AsyncMock(return_value={"records": 1})
            imported = SimpleNamespace(**{function: adapter})
            with self.subTest(family=family), patch("signalwatch.engine.importlib.import_module", return_value=imported) as load:
                self.assertEqual(await engine._collect_source(family), {"records": 1})
                load.assert_called_once_with("." + module, "signalwatch")
                adapter.assert_awaited_once_with(self.config, self.store, engine.collector.http)

    async def test_staged_outputs_are_drained_before_exactly_one_engine_reconciliation(self):
        queue = StagingQueue(self.store)
        queued = queue.enqueue(json.dumps({"entities": [{"id": "domain:staged.example", "kind": "domain", "name": "Staged domain"}]}).encode(),
                               source="provider", adapter="normalized_batch")
        with patch.object(self.store, "reconcile", wraps=self.store.reconcile) as reconcile:
            result = await self.engine.run([])
        self.assertEqual(result["staging"]["processed"], 1)
        self.assertEqual(queue.get(queued["id"])["status"], "processed")
        self.assertIsNotNone(self.store.detail("domain:staged.example"))
        reconcile.assert_called_once_with()

    async def test_staging_drain_batches_are_bounded_and_stop_when_available_work_is_exhausted(self):
        self.config["staging_max_records"] = 600
        drain = Mock(side_effect=[{"claimed": 500, "processed": 500}, {"claimed": 40, "processed": 40}])
        with patch("signalwatch.ingestion.StagingWorker", return_value=SimpleNamespace(drain=drain)):
            counts = await self.engine._drain_staging()
        self.assertEqual(counts["processed"], 540)
        self.assertEqual(drain.call_args_list, [call(500, reconcile=False), call(100, reconcile=False)])

    def test_default_interval_catalog_and_invalid_provider_success(self):
        for name in ("news", "threat"):
            self.assertEqual(self.engine.interval(name), 15)
        for name in ("nvd", "kev", "epss", "github", "osv", "cve_program", "csaf"):
            self.assertEqual(self.engine.interval(name), 360)
        for name in ("corporate", "exposure", "developer"):
            self.assertEqual(self.engine.interval(name), 10080)
        self.assertEqual(self.engine.interval("hardware"), 43200)
        self.config["interval_minutes"] = 42
        self.assertEqual(self.engine.interval("wikidata"), 42)
        self.assertEqual(source_outcome({"provider_health": {}})[0], "unconfigured")
        self.assertEqual(source_outcome({"provider_health": {"provider": {"status": "healthy"}}})[0], "ok")
        self.assertEqual(source_outcome({"provider_health": {}, "errors": ["Real error"]})[0], "error")
        self.assertEqual(source_outcome({"provider_health": {"provider": {"status": "unknown"}}})[0], "error")
        self.assertEqual(source_outcome({"provider_health": {"provider": {"status": "partial", "fetched": 0, "staged": 0, "errors": ["Unavailable"]}}})[0], "error")


if __name__ == "__main__":
    unittest.main()
