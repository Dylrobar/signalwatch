import asyncio
import copy
import fcntl
import hashlib
import importlib
import logging
import math
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .async_utils import gather, to_thread
from .collectors import Collector
from .companies import asset_identity, company, company_assets
from .cve_program import collect_cve_program
from .csaf import collect_csaf
from .http import HTTPError, PublicRequestError
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


def parse_startup_sources(value, known_sources):
    """Validate the server operator's optional one-run source selection."""
    if value is None or value == "":
        return []
    if not isinstance(value, str) or len(value) > 4096:
        raise ValueError("SIGNALWATCH_STARTUP_SOURCES must contain comma-separated known source names")
    names = [name.strip() for name in value.split(",")]
    if any(not name or name not in known_sources for name in names):
        raise ValueError("SIGNALWATCH_STARTUP_SOURCES must contain comma-separated known source names")
    return list(dict.fromkeys(names))


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


def company_scope(store, company_id, primary_domain=None, *, include_candidates=True, limit=50):
    """Resolve an explicit bounded scope without granting certificate names ownership."""
    if not isinstance(company_id, str) or not company_id.strip() or len(company_id) > 300:
        raise ValueError("A valid company_id is required")
    limit = max(1, min(100, int(limit)))
    with store.connection() as conn:
        profile = company(conn, company_id)
        assets, incomplete = company_assets(conn, company_id)
        approved = sorted({asset["id"].removeprefix("domain:") for asset in assets if asset["included"]})
        selected_domain = None
        if primary_domain is not None:
            if not isinstance(primary_domain, str) or not primary_domain.strip():
                raise ValueError("primary_domain must be an approved company domain")
            supplied = primary_domain.strip()
            parsed = urlsplit(supplied if "://" in supplied else "https://" + supplied)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.port is not None:
                raise ValueError("primary_domain must be a domain without a path, query, or port")
            _, selected_domain = asset_identity(parsed.geturl())
            if selected_domain not in approved:
                raise ValueError("primary_domain is not an included company asset")
            approved = [selected_domain]
        if not approved:
            raise ValueError("Company has no included domains; confirm an owned asset or an official website first")
        domains = approved[:limit]
        targets = [{"domain": domain, "source_url": "", "included": True} for domain in domains]
        truncated = incomplete or len(approved) > limit
        if include_candidates and len(targets) < limit:
            slots = ",".join("?" for _ in approved)
            rows = conn.execute(f"""SELECT DISTINCT d.value AS domain,min(s.source_url) AS source_url
             FROM entities s JOIN edges report ON report.from_id=s.id AND report.relation='reports_on'
             JOIN entities d ON d.id=report.to_id AND d.kind='domain'
             WHERE s.kind='source_record' AND json_extract(s.metadata,'$.provider') IN ('ctlogs','crtsh','certspotter')
              AND json_extract(s.metadata,'$.target_domain') IN ({slots})
              AND substr(d.value,-length(json_extract(s.metadata,'$.target_domain'))-1)='.'||json_extract(s.metadata,'$.target_domain')
              AND NOT EXISTS (SELECT 1 FROM company_asset_decisions decision WHERE decision.company_id=?
               AND decision.asset_id=d.id AND (decision.status!='confirmed' OR decision.role!='owned'))
             GROUP BY d.value ORDER BY d.value LIMIT ?""", (*approved, company_id, limit + 1)).fetchall()
            known = set(domains)
            for row in rows:
                if row["domain"] in known:
                    continue
                if len(targets) == limit:
                    truncated = True
                    break
                _, domain = asset_identity("https://" + row["domain"] + "/")
                targets.append({"domain": domain, "source_url": row["source_url"], "included": False})
                known.add(domain)
    for target in targets:
        domain = target["domain"]
        target["url"] = "https://" + ("[" + domain + "]" if ":" in domain else domain) + "/"
    return {"company_id": company_id, "company_name": profile["name"], "primary_domain": selected_domain,
            "domains": domains, "targets": targets, "truncated": truncated,
            "asset_ids": [company_id, *("domain:" + target["domain"] for target in targets)]}


class _CompanyProviderStore:
    """Keep target rotation local while sharing real provider quotas and checkpoints."""
    def __init__(self, store, company_id):
        self.store = store
        self.cursor_key = "company_exposure_cursors:" + hashlib.sha256(company_id.encode()).hexdigest()

    def __getattr__(self, name):
        return getattr(self.store, name)

    def source_state(self, name):
        return self.store.source_state(self.cursor_key if name == "exposure_cursors" else name)

    def update_source(self, name, **fields):
        return self.store.update_source(self.cursor_key if name == "exposure_cursors" else name, **fields)


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
            await to_thread(self.store.enqueue_url, url, "configured-seed")
        return self

    async def __aexit__(self, *args):
        await self.collector.__aexit__(*args)

    def enabled(self):
        return [name for name, enabled in self.config["sources"].items() if enabled]

    def company_scope(self, company_id, primary_domain=None):
        return company_scope(self.store, company_id, primary_domain,
                             limit=self.config.get("crawl_batch", 50))

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
        states = {row["name"]: row for row in await to_thread(self.store.sources)}
        clock = datetime.now(timezone.utc)
        due, next_times = [], []
        for name in names:
            state = states.get(name, {})
            next_time = self.next_run(name, state, clock)
            stamp = next_time.isoformat(timespec="seconds")
            if persist and stamp != state.get("next_run"):
                await to_thread(self.store.update_source, name, next_run=stamp)
            next_times.append(next_time)
            if next_time <= clock:
                due.append(name)
        delay = max(1.0, min(60.0, (min(next_times) - clock).total_seconds())) if next_times else 60.0
        return due, delay

    async def _schedule_fields(self, name, **fields):
        stamp = now()
        state = await to_thread(self.store.source_state, name)
        next_time = self.next_run(name, {**state, **fields, "last_run": stamp})
        await to_thread(self.store.update_source, name, last_run=stamp,
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
                discovered = await to_thread(self.store.company_enrichment_targets, self.config.get("max_discovered_domains", 10000))
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
            result = await to_thread(worker.drain, limit, reconcile=False)
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
        state = await to_thread(self.store.source_state, name)
        retry_at = state.get("retry_at")
        retry_time = parsed_time(retry_at)
        if retry_time and retry_time > datetime.now(timezone.utc):
            return {"source": name, "ok": False, "skipped": True, "retry_at": retry_at,
                    "error": state.get("error") or "Source is waiting for its retry time"}
        start = time.monotonic()
        self.current_sources.add(name)
        try:
            await self._schedule_fields(name, status="running", started_at=now(), error=None)
            result = await self._collect_source(name)
            status, errors, succeeded = source_outcome(result)
            fields = {"last_success": None} if status == "unconfigured" else {"last_success": now()} if succeeded else {}
            if succeeded:
                current = await to_thread(self.store.source_state, name)
                retry_time = parsed_time(current.get("retry_at"))
                if current.get("retry_at") and (retry_time is None or retry_time <= datetime.now(timezone.utc)):
                    fields.update(retry_at=None, retry_status=None)
            await self._schedule_fields(
                name, status=status,
                finished_at=now(), duration=round(time.monotonic() - start, 2), counts=result,
                error="; ".join(errors)[:2000] if errors else None, **fields
            )
            log.info("%s: %s", name, result)
            return {"source": name, "ok": succeeded, "counts": result,
                    **({"skipped": True} if status == "unconfigured" or status == "partial" and not succeeded else {})}
        except asyncio.CancelledError:
            try:
                await self._schedule_fields(name, status="interrupted", finished_at=now())
            except Exception:
                log.exception("%s interrupted status could not be saved", name)
            raise
        except Exception as exc:
            message = str(exc) or type(exc).__name__
            log.exception("%s collection failed", name)
            retry = {}
            delay = getattr(exc, "retry_after", None)
            if isinstance(exc, (HTTPError, PublicRequestError)) and delay is not None and math.isfinite(delay) and delay > 0:
                try:
                    deadline = datetime.now(timezone.utc) + timedelta(seconds=delay)
                except OverflowError:
                    deadline = datetime.max.replace(tzinfo=timezone.utc)
                current = await to_thread(self.store.source_state, name)
                existing = parsed_time(current.get("retry_at"))
                if existing is not None:
                    deadline = max(deadline, existing)
                retry = {"retry_at": deadline.isoformat(), "retry_status": getattr(exc, "status", None)}
            await self._schedule_fields(name, status="error", error=message[:1000], finished_at=now(), **retry)
            return {"source": name, "ok": False, "error": message, **retry}
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
                            try:
                                await to_thread(self.store.update_source, name, status="running", started_at=now())
                                result = await self.collector.bootstrap_year(year)
                                results.append({"source": name, "ok": True, "counts": result})
                                await to_thread(self.store.update_source, name, status="ok", last_success=now(), counts=result, error=None)
                            except Exception as exc:
                                await to_thread(self.store.update_source, name, status="error", error=str(exc), finished_at=now())
                                raise
                            finally:
                                self.current_sources.discard(name)
                    else:
                        # A failed status write must not release the process/file
                        # guards while sibling collectors still use the database.
                        results = await gather(*(self._source(name) for name in names), return_exceptions=True)
                        for result in results:
                            if isinstance(result, BaseException):
                                raise result
                    staging = await self._drain_staging()
                    matched = await to_thread(self.store.reconcile)
                    await to_thread(self.store.prune_events, int(self.config.get("events_max_rows", 50000)), float(self.config.get("events_retention_days", 90)))
                    self.last_result = {"started_at": started, "finished_at": now(), "sources": results, "matching": matched, "staging": staging}
                    return self.last_result
                except Exception as exc:
                    self.last_error = str(exc) or type(exc).__name__
                    self.last_result = {"started_at": started, "finished_at": now(), "error": self.last_error}
                    raise
                finally:
                    self.running = False
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

    async def run_company(self, kind, company_id, primary_domain=None):
        """Run a company job under the same process guard as global collection."""
        if kind not in {"passive_scan", "web_probe"}:
            raise ValueError("Unknown company job kind")
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
                source = "exposure" if kind == "passive_scan" else "web"
                marker = kind + ":" + str(company_id)
                self.current_sources.add(marker)
                try:
                    scope = await to_thread(company_scope, self.store, company_id, primary_domain,
                                            include_candidates=kind == "web_probe",
                                            limit=self.config.get("crawl_batch", 50))
                    self.last_error = None
                    state = await to_thread(self.store.source_state, source)
                    retry_time = parsed_time(state.get("retry_at"))
                    if retry_time and retry_time > datetime.now(timezone.utc):
                        return {"company_id": company_id, "kind": kind, "sources": [
                            {"source": kind, "ok": False, "skipped": True, "retry_at": state["retry_at"],
                             "error": state.get("error") or "Source is waiting for its retry time"}]}
                    if kind == "web_probe":
                        counts = await self.collector.collect_web(targets=scope["targets"])
                        staging = None
                    else:
                        from .extension_network import SOURCE_DEFINITIONS, collect_network_sources
                        # Arbitrary saved provider searches and export URLs are
                        # not a domain-scoped passive scan. Reuse only the public
                        # CT/DNS adapters with explicit approved domain inputs.
                        allowed = {"ctlogs", "crtsh", "certspotter", "passive_dns", "dns_txt"}
                        scoped_config = copy.deepcopy(self.config)
                        scoped_config["source_targets"] = [{"domain": domain, "company_id": company_id,
                                                             "name": scope["company_name"]} for domain in scope["domains"]]
                        settings = scoped_config.setdefault("provider_settings", {})
                        for definition in SOURCE_DEFINITIONS:
                            if definition["id"] not in allowed:
                                settings.setdefault(definition["id"], {})["enabled"] = False
                        scoped_store = _CompanyProviderStore(self.store, company_id)
                        counts = await collect_network_sources(scoped_config, scoped_store, self.collector.http)
                        staging = await self._drain_staging()
                    _, errors, succeeded = source_outcome(counts)
                    assets = sorted(set(scope["asset_ids"]) | set(counts.get("asset_ids", [])))
                    matched = await to_thread(self.store.reconcile, asset_ids=assets)
                    self.last_result = {"started_at": started, "finished_at": now(), "kind": kind,
                                        "company_id": company_id, "scope": scope,
                                        "sources": [{"source": kind, "ok": succeeded, "counts": counts,
                                                     **({"error": "; ".join(errors)[:2000]} if errors else {})}],
                                        "matching": matched, **({"staging": staging} if staging is not None else {})}
                    return self.last_result
                except Exception as exc:
                    self.last_error = str(exc) or type(exc).__name__
                    self.last_result = {"started_at": started, "finished_at": now(), "kind": kind,
                                        "company_id": company_id, "error": self.last_error}
                    raise
                finally:
                    self.current_sources.discard(marker)
                    self.running = False
                    fcntl.flock(lock_file, fcntl.LOCK_UN)

    async def schedule(self, startup_sources=None):
        if startup_sources:
            names = list(dict.fromkeys(startup_sources))
            log.info("Startup collection requested for: %s", ", ".join(names))
            try:
                # Another process may still be finishing its previous run during
                # a deployment. Keep the normal process guard and bound the wait.
                for attempt in range(60):
                    result = await self.run(sources=names)
                    if not result.get("busy"):
                        outcomes = ", ".join(
                            f"{row['source']}={'ok' if row.get('ok') else 'skipped' if row.get('skipped') else 'failed'}"
                            for row in result.get("sources", []))
                        log.info("Startup collection completed for %s: %s", ", ".join(names), outcomes)
                        break
                    if attempt < 59:
                        await asyncio.sleep(5)
                else:
                    log.warning("Startup collection deferred; collection lock remained busy for: %s", ", ".join(names))
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Startup collection failed for: %s", ", ".join(names))
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
