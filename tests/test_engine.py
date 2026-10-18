import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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
