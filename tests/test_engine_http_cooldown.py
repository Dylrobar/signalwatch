import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch

from signalwatch.config import load_config
from signalwatch.engine import Engine
from signalwatch.http import HTTPError, PublicRequestError
from signalwatch.store import Store


class Clock(datetime):
    current = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)

    @classmethod
    def now(cls, tz=None):
        return cls.current.astimezone(tz) if tz else cls.current.replace(tzinfo=None)


class HTTPSourceCooldownTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / "config.json")
        self.config["sources"] = {"news": True, "kev": True}
        self.store = Store(self.config["db"])
        Clock.current = datetime(2026, 10, 19, 10, 0, tzinfo=timezone.utc)
        self.clock = patch("signalwatch.engine.datetime", Clock)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def engine(self, result=None):
        engine = Engine(self.config, self.store)
        engine._collect_source = AsyncMock(return_value=result or {"records": 1})
        return engine

    async def test_http_deadline_persists_across_restart_and_manual_run(self):
        engine = self.engine()
        engine._collect_source.side_effect = HTTPError(429, "https://example.test/feed", retry_after=7200)
        with self.assertLogs("signalwatch", level="ERROR"):
            result = await engine.run(["news"])
        deadline = Clock.current + timedelta(hours=2)
        state = self.store.source_state("news")
        self.assertEqual(datetime.fromisoformat(state["retry_at"]), deadline)
        self.assertEqual(datetime.fromisoformat(state["next_run"]), deadline)
        self.assertEqual(state["retry_status"], 429)
        self.assertEqual(result["sources"][0]["retry_at"], state["retry_at"])

        Clock.current += timedelta(minutes=15)
        restarted = self.engine()
        manual = await restarted.run(["news", "kev"])
        restarted._collect_source.assert_awaited_once_with("kev")
        self.assertTrue(manual["sources"][0]["skipped"])
        self.assertEqual(self.store.source_state("news"), state)
        self.assertTrue((await restarted.run(scheduled=True))["skipped"])

        Clock.current = deadline
        await restarted.run(["news"])
        cleared = self.store.source_state("news")
        self.assertEqual(cleared["status"], "ok")
        self.assertIsNone(cleared["retry_at"])
        self.assertIsNone(cleared["retry_status"])

    async def test_proxy_unavailability_with_deadline_is_persisted(self):
        engine = self.engine()
        error = PublicRequestError("Proxy pool temporarily unavailable", "https://example.test/feed")
        error.retry_after = 120
        engine._collect_source.side_effect = error
        with self.assertLogs("signalwatch", level="ERROR"):
            await engine._source("news")
        self.assertEqual(datetime.fromisoformat(self.store.source_state("news")["retry_at"]),
                         Clock.current + timedelta(seconds=120))
        self.assertTrue((await engine._source("news"))["skipped"])
        engine._collect_source.assert_awaited_once()

    async def test_fractional_deadline_is_not_shortened(self):
        engine = self.engine()
        Clock.current += timedelta(microseconds=800000)
        engine._collect_source.side_effect = HTTPError(503, "https://example.test/feed", retry_after=1.5)
        with self.assertLogs("signalwatch", level="ERROR"):
            await engine._source("news")
        deadline = datetime.fromisoformat(self.store.source_state("news")["retry_at"])
        self.assertEqual(deadline, Clock.current + timedelta(seconds=1.5))
        Clock.current = deadline - timedelta(microseconds=1)
        self.assertTrue((await engine._source("news"))["skipped"])
        engine._collect_source.assert_awaited_once()

    async def test_longer_adapter_deadline_is_preserved(self):
        engine = self.engine()
        deadline = Clock.current + timedelta(days=1)

        async def collect(name):
            self.store.update_source(name, retry_at=deadline.isoformat())
            raise HTTPError(429, "https://example.test/feed", retry_after=120)

        engine._collect_source.side_effect = collect
        with self.assertLogs("signalwatch", level="ERROR"):
            await engine._source("news")
        state = self.store.source_state("news")
        self.assertEqual(datetime.fromisoformat(state["retry_at"]), deadline)
        self.assertEqual(datetime.fromisoformat(state["next_run"]), deadline)

    async def test_success_preserves_new_future_adapter_deadline(self):
        engine = self.engine()
        deadline = Clock.current + timedelta(hours=1)

        async def collect(name):
            self.store.update_source(name, retry_at=deadline.isoformat())
            return {"records": 1}

        engine._collect_source.side_effect = collect
        await engine._source("news")
        self.assertEqual(datetime.fromisoformat(self.store.source_state("news")["retry_at"]), deadline)

    async def test_auth_not_found_and_transport_errors_do_not_gain_retry_deadlines(self):
        for error in (HTTPError(401, "https://example.test/feed"), HTTPError(404, "https://example.test/feed"),
                      PublicRequestError("Connection failed", "https://example.test/feed")):
            with self.subTest(error=error):
                engine = self.engine()
                engine._collect_source.side_effect = error
                with self.assertLogs("signalwatch", level="ERROR"):
                    await engine._source("news")
                self.assertIsNone(self.store.source_state("news").get("retry_at"))


if __name__ == "__main__":
    unittest.main()
