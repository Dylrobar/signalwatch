import asyncio
import logging

from .normalization import NormalizationError, normalize
from .staging import LeaseLost, StagingQueue


log = logging.getLogger("signalwatch")


def staging_queue(store, config):
    return StagingQueue(
        store,
        max_payload_bytes=int(float(config.get("staging_max_payload_mb", 8)) * 1024 * 1024),
        max_bytes=int(float(config.get("staging_max_mb", 512)) * 1024 * 1024),
        max_records=int(config.get("staging_max_records", 10000)),
    )


class StagingWorker:
    def __init__(self, store, config, queue=None):
        self.store = store
        self.config = config
        self.queue = queue or staging_queue(store, config)
        self.last_result = None
        self.last_error = None
        self.needs_matching = True

    def drain(self, limit=None, *, reconcile=True):
        limit = int(limit if limit is not None else self.config.get("staging_batch", 25))
        if not 1 <= limit <= 500:
            raise ValueError("Staging processing limit must be between 1 and 500")
        result = {"claimed": 0, "processed": 0, "retried": 0, "dead": 0, "lease_lost": 0}
        for _ in range(limit):
            item = self.queue.claim()
            if item is None:
                break
            result["claimed"] += 1
            try:
                batch = normalize(item)
                self.queue.complete(item["id"], item["lease_token"], batch)
                result["processed"] += 1
                if set(batch) != {"wireless_batch"}:
                    self.needs_matching = True
            except LeaseLost:
                result["lease_lost"] += 1
            except Exception as error:
                try:
                    state = self.queue.fail(item["id"], item["lease_token"],
                                            str(error) or type(error).__name__,
                                            retryable=not isinstance(error, NormalizationError))
                    result["dead" if state["status"] == "dead" else "retried"] += 1
                except LeaseLost:
                    result["lease_lost"] += 1
        if self.needs_matching and reconcile:
            try:
                result["matching"] = self.store.reconcile()
                result["events_pruned"] = self.store.prune_events(
                    int(self.config.get("events_max_rows", 50000)),
                    float(self.config.get("events_retention_days", 90)),
                )
                self.needs_matching = False
                self.last_error = None
            except Exception as error:
                self.last_error = str(error) or type(error).__name__
                result["matching_error"] = self.last_error[:1000]
        self.queue.prune(retention_days=float(self.config.get("staging_retention_days", 7)),
                         max_completed=int(self.config.get("staging_max_completed", 10000)))
        self.last_result = result
        return result

    async def run(self):
        while True:
            try:
                result = await asyncio.to_thread(self.drain)
            except asyncio.CancelledError:
                raise
            except Exception as error:
                self.last_error = str(error) or type(error).__name__
                log.exception("Staging queue processing failed")
                result = {"claimed": 0}
            if not result["claimed"]:
                await asyncio.sleep(float(self.config.get("staging_poll_seconds", 2)))
