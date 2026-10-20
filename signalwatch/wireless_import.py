import asyncio
from pathlib import Path

from .async_utils import gather, to_thread
from .config import data_directory
from .ingestion import staging_queue
from .staging import QueueFull


class WirelessImports:
    def __init__(self, store, config):
        self.store = store
        self.config = config
        self.directory = data_directory(config) / "wireless-imports"
        self.directory.mkdir(parents=True, exist_ok=True)
        self.tasks = {}
        self.lock = asyncio.Lock()

    def state(self, dataset_id):
        return self.store.source_state("wireless-import:" + dataset_id)

    def archive(self, dataset_id):
        state = self.state(dataset_id)
        value = state.get("archive_path")
        path = Path(value).resolve() if value else None
        if not path or not path.is_relative_to(self.directory.resolve()) or not path.is_file():
            raise LookupError("Original wireless export is unavailable")
        return path

    async def start(self, path, name, digest, source_url=""):
        async with self.lock:
            return await self._start(path, name, digest, source_url)

    async def _start(self, path, name, digest, source_url=""):
        from .wireless import register_dataset
        dataset_id = "wireless:" + digest
        state = await to_thread(self.state, dataset_id)
        existing = self.tasks.get(dataset_id)
        if state.get("status") == "complete" or existing and not existing.done():
            return {"dataset_id": dataset_id, "job_id": dataset_id, "status": state.get("status", "importing"), "duplicate": True}
        name = state.get("dataset_name") or name
        await to_thread(register_dataset, self.store, {"dataset_id": dataset_id, "source_hash": digest,
                                "dataset_name": name, "source_url": source_url or state.get("source_url", "")}, status="queued")
        await to_thread(self.store.update_source, "wireless-import:" + dataset_id,
                                status="queued", archive_path=str(path), dataset_name=name,
                                source_hash=digest, source_url=source_url or state.get("source_url", ""), error=None)
        task = asyncio.create_task(self._run(dataset_id), name="wireless-import:" + digest[:12])
        self.tasks[dataset_id] = task
        return {"dataset_id": dataset_id, "job_id": dataset_id, "status": "queued", "duplicate": False}

    async def resume(self):
        from .wireless import update_dataset_status
        states = await to_thread(self.store.sources)
        for state in states:
            if str(state["name"]).startswith("wireless-import:") and state.get("status") in {"queued", "importing", "processing"}:
                dataset_id = state["name"].removeprefix("wireless-import:")
                try:
                    path = self.archive(dataset_id)
                except LookupError:
                    await to_thread(self.store.update_source, state["name"], status="failed", error="Original archive is unavailable for import recovery")
                    await to_thread(update_dataset_status, self.store, dataset_id, "failed", error="Original archive is unavailable for import recovery")
                    continue
                await self.start(path, state.get("dataset_name", path.name), state["source_hash"], state.get("source_url", ""))

    async def stop(self):
        tasks = [task for task in self.tasks.values() if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await gather(*tasks, return_exceptions=True)

    async def _run(self, dataset_id):
        from .wireless import get_dataset, iter_wigle_chunks, update_dataset_status
        state = await to_thread(self.state, dataset_id)
        source = "wireless-import:" + dataset_id
        queue = staging_queue(self.store, self.config)
        queued, chunks = 0, 0
        iterator = None
        try:
            await to_thread(update_dataset_status, self.store, dataset_id, "importing")
            await to_thread(self.store.update_source, source, status="importing", error=None)
            iterator = iter_wigle_chunks(self.archive(dataset_id), rows_per_chunk=int(self.config.get("wireless_chunk_rows", 5000)))
            while True:
                item = await to_thread(next, iterator, None)
                if item is None:
                    break
                metadata = {**item["metadata"], "dataset_name": state["dataset_name"]}
                while True:
                    try:
                        await to_thread(queue.enqueue, item["payload"], source=source, adapter="wigle_csv",
                                                content_type="text/csv", source_url=state.get("source_url", ""),
                                                stream_key=dataset_id, metadata=metadata,
                                                idempotency_key=str(metadata["row_start"]))
                        break
                    except QueueFull:
                        await asyncio.sleep(1)
                queued += metadata["row_count"]
                chunks += 1
                await to_thread(self.store.update_source, source, queued_rows=queued, chunks=chunks)
                await to_thread(update_dataset_status, self.store, dataset_id, "importing", queued_rows=queued)
                await asyncio.sleep(0)
            if not queued:
                raise ValueError("WiGLE export contains no observation rows")
            await to_thread(self.store.update_source, source, status="processing", expected_rows=queued)
            while True:
                def pending():
                    with self.store.connection() as conn:
                        return dict(conn.execute("SELECT status,count(*) FROM raw_ingress WHERE source=? GROUP BY status", (source,)).fetchall())
                counts = await to_thread(pending)
                if not counts.get("pending", 0) and not counts.get("processing", 0):
                    break
                await asyncio.sleep(1)
            if counts.get("dead", 0):
                raise ValueError(f"{counts['dead']} wireless chunks need inspection in staging")
            saved = await to_thread(get_dataset, self.store, dataset_id)
            if not saved or saved["observation_count"] != queued:
                raise ValueError("Imported observation count does not match the source export")
            await to_thread(update_dataset_status, self.store, dataset_id, "complete", expected_rows=queued, queued_rows=queued, chunks=chunks)
            await to_thread(self.store.update_source, source, status="complete", error=None, expected_rows=queued)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            message = (str(error) or type(error).__name__)[:1000]
            await to_thread(self.store.update_source, source, status="failed", error=message, queued_rows=queued)
            await to_thread(update_dataset_status, self.store, dataset_id, "failed", error=message, queued_rows=queued)
        finally:
            if iterator is not None:
                iterator.close()
