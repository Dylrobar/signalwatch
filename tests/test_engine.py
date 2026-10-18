import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from signalwatch.config import load_config
from signalwatch.engine import Engine
from signalwatch.store import Store


class EngineFailureTests(unittest.IsolatedAsyncioTestCase):
    async def test_failed_matching_is_reported_and_lock_recovers(self):
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(Path(directory) / "config.json")
            store = Store(config["db"])
            engine = Engine(config, store)
            with patch.object(store, "reconcile", side_effect=RuntimeError("Matching failed")):
                with self.assertRaisesRegex(RuntimeError, "Matching failed"):
                    await engine.run([])
            self.assertEqual(engine.last_error, "Matching failed")
            self.assertEqual(engine.last_result["error"], "Matching failed")
            self.assertFalse(engine.busy())
            result = await engine.run([])
            self.assertIn("matching", result)
            self.assertIsNone(engine.last_error)
            self.assertFalse(engine.running)

    async def test_cooldown_preserves_source_failure_and_other_collectors_continue(self):
        with tempfile.TemporaryDirectory() as directory:
            config = load_config(Path(directory) / "config.json")
            store = Store(config["db"])
            retry_at = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
            previous = store.update_source("wikidata", status="error", error="HTTP 429: rate limited",
                                           retry_at=retry_at, cursor="Q123", counts={"companies": 46},
                                           last_success="2026-01-01T00:00:00+00:00")
            engine = Engine(config, store)
            run_source = AsyncMock(return_value={"records": 1})
            engine.collector = SimpleNamespace(run_source=run_source)
            result = await engine.run(["wikidata", "kev"])
            run_source.assert_awaited_once_with("kev")
            self.assertEqual(store.source_state("wikidata"), previous)
            self.assertEqual(store.source_state("kev")["status"], "ok")
            deferred = next(row for row in result["sources"] if row["source"] == "wikidata")
            self.assertFalse(deferred["ok"])
            self.assertTrue(deferred["skipped"])
            self.assertEqual(deferred["retry_at"], retry_at)
            self.assertFalse(engine.current_sources)

    async def test_expired_or_invalid_cooldowns_allow_collection(self):
        for retry_at in ((datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat(), "invalid"):
            with self.subTest(retry_at=retry_at), tempfile.TemporaryDirectory() as directory:
                config = load_config(Path(directory) / "config.json")
                store = Store(config["db"])
                store.update_source("wikidata", status="error", error="old error", retry_at=retry_at)
                engine = Engine(config, store)
                run_source = AsyncMock(return_value={"companies": 1})
                engine.collector = SimpleNamespace(run_source=run_source)
                result = await engine.run(["wikidata"])
                run_source.assert_awaited_once_with("wikidata")
                self.assertTrue(result["sources"][0]["ok"])
                self.assertEqual(store.source_state("wikidata")["status"], "ok")
                self.assertIsNone(store.source_state("wikidata")["error"])
