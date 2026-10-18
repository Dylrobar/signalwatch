import asyncio
import fcntl
import logging
import time
from datetime import datetime, timezone
from pathlib import Path

from .collectors import Collector
from .cve_program import collect_cve_program
from .csaf import collect_csaf
from .network import collect_network
from .osv import collect_osv


log = logging.getLogger("signalwatch")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Engine:
    def __init__(self, config, store):
        self.config = config
        self.store = store
        self.collector = None
        self.running = False
        self.current_sources = set()
        self.last_result = None
        self.last_error = None
        self._guard = asyncio.Lock()

    async def __aenter__(self):
        self.collector = await Collector(self.config, self.store).__aenter__()
        for url in self.config["seed_urls"]:
            await asyncio.to_thread(self.store.enqueue_url, url, "configured-seed")
        return self

    async def __aexit__(self, *args):
        await self.collector.__aexit__(*args)

    def enabled(self):
        return [name for name, enabled in self.config["sources"].items() if enabled]

    def busy(self):
        if self.running:
            return True
        path = Path(self.config["db"] + ".collector.lock")
        if not path.exists():
            return False
        with path.open("a") as lock_file:
            try:
                fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(lock_file, fcntl.LOCK_UN)
        return False

    async def _source(self, name):
        state = await asyncio.to_thread(self.store.source_state, name)
        retry_at = state.get("retry_at")
        try:
            retry_time = datetime.fromisoformat(str(retry_at).replace("Z", "+00:00")) if retry_at else None
            if retry_time and retry_time.tzinfo is None:
                retry_time = retry_time.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            retry_time = None
        if retry_time and retry_time > datetime.now(timezone.utc):
            return {"source": name, "ok": False, "skipped": True, "retry_at": retry_at,
                    "error": state.get("error") or "Source is waiting for its retry time"}
        start = time.monotonic()
        self.current_sources.add(name)
        await asyncio.to_thread(self.store.update_source, name, status="running", started_at=now(), error=None)
        try:
            adapters = {"osv": collect_osv, "cve_program": collect_cve_program,
                        "csaf": collect_csaf, "network": collect_network}
            if name in adapters:
                result = await adapters[name](self.config, self.store, self.collector.http)
            else:
                result = await self.collector.run_source(name)
            errors = result.get("errors") or []
            await asyncio.to_thread(
                self.store.update_source, name, status="partial" if errors else "ok", last_success=now(),
                finished_at=now(), duration=round(time.monotonic() - start, 2), counts=result,
                error="; ".join(map(str, errors))[:2000] if errors else None
            )
            log.info("%s: %s", name, result)
            return {"source": name, "ok": True, "counts": result}
        except asyncio.CancelledError:
            await asyncio.to_thread(self.store.update_source, name, status="interrupted", finished_at=now())
            raise
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            log.exception("%s collection failed", name)
            await asyncio.to_thread(self.store.update_source, name, status="error", error=message[:1000], finished_at=now())
            return {"source": name, "ok": False, "error": message}
        finally:
            self.current_sources.discard(name)

    async def run(self, sources=None, years=None):
        if self._guard.locked():
            return {"busy": True}
        async with self._guard:
            lock_path = Path(self.config["db"] + ".collector.lock")
            lock_path.parent.mkdir(parents=True, exist_ok=True)
            with lock_path.open("a") as lock_file:
                try:
                    fcntl.flock(lock_file, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return {"busy": True, "error": "Another process is collecting this database"}
                self.running = True
                self.last_error = None
                started = now()
                try:
                    if years:
                        results = []
                        for year in years:
                            name = f"nvd-{year}"
                            self.current_sources.add(name)
                            await asyncio.to_thread(self.store.update_source, name, status="running", started_at=now())
                            try:
                                result = await self.collector.bootstrap_year(year)
                                results.append({"source": name, "ok": True, "counts": result})
                                await asyncio.to_thread(self.store.update_source, name, status="ok", last_success=now(), counts=result, error=None)
                            except Exception as exc:
                                await asyncio.to_thread(self.store.update_source, name, status="error", error=str(exc), finished_at=now())
                                raise
                            finally:
                                self.current_sources.discard(name)
                    else:
                        names = list(dict.fromkeys(sources if sources is not None else self.enabled()))
                        unknown = set(names) - set(self.config["sources"])
                        if unknown:
                            raise ValueError(f"Unknown sources: {', '.join(sorted(unknown))}")
                        results = await asyncio.gather(*(self._source(name) for name in names))
                    matched = await asyncio.to_thread(self.store.reconcile)
                    await asyncio.to_thread(self.store.prune_events, int(self.config.get("events_max_rows", 50000)), float(self.config.get("events_retention_days", 90)))
                    self.last_result = {"started_at": started, "finished_at": now(), "sources": results, "matching": matched}
                    return self.last_result
                except Exception as exc:
                    self.last_error = str(exc) or type(exc).__name__
                    self.last_result = {"started_at": started, "finished_at": now(), "error": self.last_error}
                    raise
                finally:
                    self.running = False
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

    async def schedule(self):
        while True:
            try:
                await self.run()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Collection cycle failed")
            await asyncio.sleep(self.config["interval_minutes"] * 60)
