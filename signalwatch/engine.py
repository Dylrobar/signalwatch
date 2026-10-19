import asyncio
import fcntl
import importlib
import logging
import math
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .collectors import Collector
from .cve_program import collect_cve_program
from .csaf import collect_csaf
from .network import collect_network
from .nmap import collect_nmap
from .osv import collect_osv


log = logging.getLogger("signalwatch")

SOURCE_INTERVALS = {
    "news": 15, "threat": 15, "prerelease": 60, "nmap": 1440,
    **{name: 360 for name in ("nvd", "kev", "epss", "github", "osv", "cve_program", "csaf")},
    "web": 5, "wikidata": 15, "network": 15,
    "exposure": 30, "developer": 360, "corporate": 15, "hardware": 43200,
}
EXTENSION_ADAPTERS = {
    "exposure": ("extension_network", "collect_network_sources"),
    "corporate": ("extension_corporate", "collect_corporate_sources"),
    "developer": ("extension_developer", "collect_developer_sources"),
    "threat": ("extension_threat", "collect_threat_sources"),
    "hardware": ("extension_hardware", "collect_hardware_sources"),
    "prerelease": ("extension_prerelease", "collect_prerelease_sources"),
}


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def parsed_time(value):
    try:
        result = datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
        return result.replace(tzinfo=timezone.utc) if result and result.tzinfo is None else result
    except (TypeError, ValueError):
        return None


def source_outcome(result):
    errors = result.get("errors") or []
    if not isinstance(errors, (list, tuple)):
        errors = [errors]
    errors = [str(error) for error in errors if error]
    health = result.get("provider_health")
    if not isinstance(health, dict):
        return "partial" if errors else "ok", errors, True
    inactive = {"disabled", "unconfigured", "skipped"}
    active = [(name, row if isinstance(row, dict) else {"status": row}) for name, row in health.items()
              if (row.get("status") if isinstance(row, dict) else row) not in inactive]
    if not active:
        return "error" if errors else "unconfigured", errors, False
    successful = {"ok", "healthy", "unchanged", "success", "staged", "processed"}
    failed = {"error", "failed", "rate_limited", "blocked", "timeout"}
    successes, deferred = 0, False
    for name, row in active:
        status = row.get("status")
        if status == "deferred" or row.get("deferred") is True:
            deferred = True
        elif status in successful:
            successes += 1
        elif status == "partial":
            progress = [row[key] for key in ("staged", "records", "fetched", "successful", "pages", "processed", "unchanged")
                        if isinstance(row.get(key), (int, float))]
            if not progress or any(value > 0 for value in progress):
                successes += 1
            errors.append(f"{name}: {row.get('error') or 'Provider returned incomplete coverage'}")
        elif status in failed or row.get("error"):
            errors.append(f"{name}: {row.get('error') or 'Provider collection failed'}")
        else:
            errors.append(f"{name}: Provider success was not established")
    status = ("partial" if errors or deferred else "ok") if successes else "error" if errors else "partial"
    return status, list(dict.fromkeys(errors)), bool(successes)


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

    def interval(self, name):
        supplied = self.config.get("source_intervals", {})
        value = supplied.get(name, SOURCE_INTERVALS.get(name, self.config.get("interval_minutes", 30))) if isinstance(supplied, dict) else SOURCE_INTERVALS.get(name, self.config.get("interval_minutes", 30))
        try:
            minutes = float(value)
            if math.isfinite(minutes) and minutes > 0:
                return minutes
        except (TypeError, ValueError):
            pass
        return float(SOURCE_INTERVALS.get(name, 30))

    def next_run(self, name, state, clock=None):
        clock = clock or datetime.now(timezone.utc)
        previous = parsed_time(state.get("last_run")) or parsed_time(state.get("finished_at")) or parsed_time(state.get("last_success"))
        if previous:
            try:
                due = previous + timedelta(minutes=self.interval(name))
            except OverflowError:
                due = datetime.max.replace(tzinfo=timezone.utc)
        else:
            due = parsed_time(state.get("next_run")) or clock
        retry = parsed_time(state.get("retry_at"))
        return max(due, retry) if retry else due

    async def _due(self, names, *, persist=False):
        states = {row["name"]: row for row in await asyncio.to_thread(self.store.sources)}
        clock = datetime.now(timezone.utc)
        due, next_times = [], []
        for name in names:
            state = states.get(name, {})
            next_time = self.next_run(name, state, clock)
            stamp = next_time.isoformat(timespec="seconds")
            if persist and stamp != state.get("next_run"):
                await asyncio.to_thread(self.store.update_source, name, next_run=stamp)
            next_times.append(next_time)
            if next_time <= clock:
                due.append(name)
        delay = max(1.0, min(60.0, (min(next_times) - clock).total_seconds())) if next_times else 60.0
        return due, delay

    async def _schedule_fields(self, name, **fields):
        stamp = now()
        state = await asyncio.to_thread(self.store.source_state, name)
        next_time = self.next_run(name, {**state, "last_run": stamp})
        await asyncio.to_thread(self.store.update_source, name, last_run=stamp,
                                next_run=next_time.isoformat(timespec="seconds"), **fields)

    async def _collect_source(self, name):
        adapters = {"osv": collect_osv, "cve_program": collect_cve_program,
                    "csaf": collect_csaf, "network": collect_network, "nmap": collect_nmap}
        if name in EXTENSION_ADAPTERS:
            module, function = EXTENSION_ADAPTERS[name]
            adapter = getattr(importlib.import_module("." + module, __package__), function)
            config = self.config
            discovered = []
            if name in {"exposure", "corporate", "developer"}:
                discovered = await asyncio.to_thread(self.store.company_enrichment_targets, self.config.get("max_discovered_domains", 10000))
                if discovered:
                    targets = list(self.config.get("source_targets", []))
                    domains = {str(target.get("domain", "")).lower().rstrip(".") for target in targets}
                    targets.extend(target for target in discovered if target["domain"] not in domains)
                    config = {**self.config, "source_targets": targets}
            result = await adapter(config, self.store, self.collector.http)
            if discovered:
                result.update(company_targets=len(config["source_targets"]), discovered_company_targets=len(discovered))
            return result
        if name in adapters:
            return await adapters[name](self.config, self.store, self.collector.http)
        return await self.collector.run_source(name)

    async def _drain_staging(self):
        from .ingestion import StagingWorker
        worker = StagingWorker(self.store, self.config)
        remaining = max(1, int(self.config.get("staging_max_records", 10000)))
        counts = {"claimed": 0, "processed": 0, "retried": 0, "dead": 0, "lease_lost": 0}
        while remaining:
            limit = min(500, remaining)
            result = await asyncio.to_thread(worker.drain, limit, reconcile=False)
            for key in counts:
                counts[key] += int(result.get(key, 0))
            claimed = int(result.get("claimed", 0))
            remaining -= claimed
            if claimed < limit:
                break
        return counts

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
        retry_time = parsed_time(retry_at)
        if retry_time and retry_time > datetime.now(timezone.utc):
            return {"source": name, "ok": False, "skipped": True, "retry_at": retry_at,
                    "error": state.get("error") or "Source is waiting for its retry time"}
        start = time.monotonic()
        self.current_sources.add(name)
        await self._schedule_fields(name, status="running", started_at=now(), error=None)
        try:
            result = await self._collect_source(name)
            status, errors, succeeded = source_outcome(result)
            fields = {"last_success": None} if status == "unconfigured" else {"last_success": now()} if succeeded else {}
            await self._schedule_fields(
                name, status=status,
                finished_at=now(), duration=round(time.monotonic() - start, 2), counts=result,
                error="; ".join(errors)[:2000] if errors else None, **fields
            )
            log.info("%s: %s", name, result)
            return {"source": name, "ok": succeeded, "counts": result,
                    **({"skipped": True} if status == "unconfigured" or status == "partial" and not succeeded else {})}
        except asyncio.CancelledError:
            await self._schedule_fields(name, status="interrupted", finished_at=now())
            raise
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            log.exception("%s collection failed", name)
            await self._schedule_fields(name, status="error", error=message[:1000], finished_at=now())
            return {"source": name, "ok": False, "error": message}
        finally:
            self.current_sources.discard(name)

    async def run(self, sources=None, years=None, *, scheduled=False):
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
                started = now()
                try:
                    names = list(dict.fromkeys(sources if sources is not None else self.enabled()))
                    if not years:
                        unknown = set(names) - set(self.config["sources"])
                        if unknown:
                            raise ValueError(f"Unknown sources: {', '.join(sorted(unknown))}")
                        if scheduled:
                            names, _ = await self._due(names, persist=True)
                            if not names:
                                return {"scheduled": True, "sources": [], "skipped": True}
                    self.last_error = None
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
                        results = await asyncio.gather(*(self._source(name) for name in names))
                    staging = await self._drain_staging()
                    matched = await asyncio.to_thread(self.store.reconcile)
                    await asyncio.to_thread(self.store.prune_events, int(self.config.get("events_max_rows", 50000)), float(self.config.get("events_retention_days", 90)))
                    self.last_result = {"started_at": started, "finished_at": now(), "sources": results, "matching": matched, "staging": staging}
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
            delay = 60.0
            try:
                await self.run(scheduled=True)
                _, delay = await self._due(self.enabled())
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Collection cycle failed")
            await asyncio.sleep(delay)
