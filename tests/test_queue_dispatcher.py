import asyncio
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from signalwatch.config import load_config
from signalwatch.jobs import Jobs
from signalwatch.queue import QueueDispatcher, publish_job
from signalwatch.store import Store


class QueueDispatcherTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / "config.json")
        self.store = Store(self.config["db"])
        self.dispatcher = QueueDispatcher(self.config, self.store)
        self.jobs = self.dispatcher.jobs

    async def test_failed_publication_retains_job_and_defers_without_broker_secrets(self):
        job = self.jobs.enqueue("collect", {"sources": ["kev"]})
        with patch("signalwatch.queue.publish_job", side_effect=OSError("redis://user:SECRET@broker")):
            await self.dispatcher.dispatch_once()
        saved = self.jobs.get(job["id"])
        self.assertEqual((saved["status"], saved["attempts"]), ("retrying", 0))
        self.assertIsNone(saved["last_dispatched_at"])
        self.assertNotIn("SECRET", saved["error"])
        self.assertNotIn("SECRET", self.dispatcher.last_error)
        self.assertFalse(self.jobs.pending_dispatch())

    async def test_accepted_publication_marks_outbox_without_marking_execution_success(self):
        job = self.jobs.enqueue("collect", {"sources": ["kev"]})
        with patch("signalwatch.queue.publish_job") as publish:
            await self.dispatcher.dispatch_once()
        publish.assert_called_once_with(job["id"])
        saved = self.jobs.get(job["id"])
        self.assertEqual((saved["status"], saved["attempts"]), ("queued", 0))
        self.assertIsNotNone(saved["last_dispatched_at"])
        self.assertFalse(self.jobs.pending_dispatch())

    async def test_shutdown_joins_started_publisher_and_leaves_later_jobs_in_outbox(self):
        jobs = [self.jobs.enqueue("collect", {"sources": [name]}) for name in ("kev", "nvd")]
        loop = asyncio.get_running_loop()
        started = asyncio.Event()
        release = threading.Event()

        def blocked(job_id):
            loop.call_soon_threadsafe(started.set)
            if not release.wait(5):
                raise RuntimeError("Test did not release publisher")

        with patch("signalwatch.queue.publish_job", side_effect=blocked) as publish:
            running = asyncio.create_task(self.dispatcher.run())
            stopping = None
            try:
                await asyncio.wait_for(started.wait(), 2)
                stopping = asyncio.create_task(self.dispatcher.stop())
                await asyncio.sleep(0.02)
                self.assertFalse(stopping.done())
                self.assertFalse(running.done())
            finally:
                release.set()
                await asyncio.wait_for(stopping or self.dispatcher.stop(), 3)
                await running
        self.assertEqual(publish.call_count, 1)
        self.assertEqual(len(self.jobs.pending_dispatch()), 1)
        self.assertFalse(self.dispatcher.running)

    def test_broker_message_contains_only_job_id_and_disables_publish_retries(self):
        fake = MagicMock()
        connection = fake.connection_for_write.return_value.__enter__.return_value
        with patch("signalwatch.queue.app", fake):
            publish_job("opaque-job-id")
        connection.ensure_connection.assert_called_once_with(max_retries=0, timeout=5)
        call = fake.send_task.call_args
        self.assertEqual(call.args, ("signalwatch.execute_job",))
        self.assertEqual(call.kwargs["args"], ["opaque-job-id"])
        self.assertFalse(call.kwargs["retry"])
        self.assertTrue(call.kwargs["ignore_result"])
        self.assertEqual(call.kwargs["expires"], 300)
        self.assertNotIn("kwargs", call.kwargs)


if __name__ == "__main__":
    unittest.main()
