"""Database outbox dispatcher: publishing failure never discards an accepted job."""

import asyncio
import logging

from .async_utils import to_thread
from .celery_app import BROKER_TIMEOUT, EXECUTE_TASK, QUEUE_NAME, app
from .jobs import Jobs, REPUBLISH_SECONDS

log = logging.getLogger("signalwatch")


def publish_job(job_id):
    """Publish only an opaque ID with bounded broker connect/socket waits."""
    with app.connection_for_write(connect_timeout=BROKER_TIMEOUT) as connection:
        connection.ensure_connection(max_retries=0, timeout=BROKER_TIMEOUT)
        app.send_task(EXECUTE_TASK, args=[job_id], task_id=job_id,
                      queue=QUEUE_NAME, connection=connection,
                      retry=False, ignore_result=True, expires=REPUBLISH_SECONDS)


class QueueDispatcher:
    def __init__(self, config, store):
        self.config = config
        self.store = store
        self.jobs = Jobs(store)
        self.last_error = ""
        self.running = False
        self._stop = asyncio.Event()
        self._task = None

    async def dispatch_once(self):
        await to_thread(self.jobs.recover)
        pending = await to_thread(self.jobs.pending_dispatch, limit=20)
        for job in pending:
            if self._stop.is_set():
                break
            try:
                await to_thread(publish_job, job["id"])
            except Exception:
                self.last_error = "Queue broker unavailable; accepted jobs will retry dispatch"
                await to_thread(self.jobs.defer, job["id"], error=self.last_error,
                                delay=30, attempted=False)
                log.warning("Queue broker unavailable; job dispatch deferred")
            else:
                await to_thread(self.jobs.dispatched, job["id"])
                self.last_error = ""

    async def run(self):
        if self.running:
            raise RuntimeError("Queue dispatcher is already running")
        self.running = True
        self._task = asyncio.current_task()
        try:
            while not self._stop.is_set():
                try:
                    await self.dispatch_once()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self.last_error = "Queue dispatch could not update the job ledger; it will retry"
                    log.warning("Queue dispatch could not update the job ledger")
                try:
                    await asyncio.wait_for(self._stop.wait(), timeout=2)
                except asyncio.TimeoutError:
                    pass
        finally:
            self.running = False

    async def stop(self):
        self._stop.set()
        task = self._task
        if task is not None and task is not asyncio.current_task() and not task.done():
            # A started synchronous publisher must settle before shutdown returns.
            await asyncio.shield(task)
