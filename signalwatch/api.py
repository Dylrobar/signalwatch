import asyncio
import base64
import binascii
import json
import logging
import math
import os
import re
import secrets
import threading
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .config import VERSION
from .engine import Engine, now, parse_startup_sources
from .ingestion import StagingWorker, staging_queue
from .staging import QueueFull
from .store import Store


EventKind = Literal["", "advisory_added", "advisory_changed", "kev_added", "kev_removed", "warning_opened", "warning_resolved"]


def public_url(value):
    value = value.strip()
    if "://" not in value:
        value = "https://" + value
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A public HTTP(S) URL without credentials is required")
    parsed.port
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", parsed.query, ""))


class CollectRequest(BaseModel):
    sources: list[str] | None = Field(default=None, max_length=100)
    idempotency_key: str = Field(default="", max_length=200)


class SeedRequest(BaseModel):
    urls: list[str] = Field(min_length=1, max_length=10000)


class FeedRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    url: str


class ObservationRequest(BaseModel):
    asset_url: str
    vendor: str = Field(min_length=1, max_length=200)
    product: str = Field(min_length=1, max_length=300)
    version: str = Field(default="", max_length=200)
    evidence: str = Field(min_length=1, max_length=10000)


class SBOMRequest(BaseModel):
    asset_url: str
    source_key: str = Field(default="default", min_length=1, max_length=200)
    document: dict


class VerifiedASNRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    asn: int = Field(strict=True, ge=1, le=4294967295)
    evidence: str = Field(min_length=1, max_length=10000)
    source_url: str = Field(min_length=1, max_length=2000)


class CompanyProfileRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    company_id: str = Field(default="", max_length=300)
    name: str = Field(min_length=1, max_length=200)
    legal_name: str = Field(default="", max_length=300)
    aliases: list[str] = Field(default_factory=list, max_length=50)
    brands: list[str] = Field(default_factory=list, max_length=50)
    parent_company_id: str = Field(default="", max_length=300)
    notes: str = Field(default="", max_length=10000)
    source_url: str = Field(default="", max_length=2000)
    primary_domain: str | None = Field(default=None, max_length=253)
    primary_domain_evidence: str | None = Field(default=None, max_length=10000)
    primary_domain_source_url: str | None = Field(default=None, max_length=2000)
    verified_asns: list[VerifiedASNRequest] | None = Field(default=None, max_length=100)

    @field_validator("aliases", "brands")
    @classmethod
    def labels(cls, values):
        if any(len(value) > 200 for value in values):
            raise ValueError("Each alias or brand must be at most 200 characters")
        return list(dict.fromkeys(value.strip() for value in values if value.strip()))


class CompanyResolveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    company_id: str = Field(default="", max_length=300)
    domain: str = Field(default="", max_length=253)
    name: str = Field(default="", max_length=300)
    asn: int | None = Field(default=None, strict=True, ge=1, le=4294967295)
    source_url: str = Field(default="", max_length=2000)
    text: str = Field(default="", max_length=16000)


class CompanyAssetRequest(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    company_id: str = Field(min_length=1, max_length=300)
    asset_url: str = Field(min_length=1, max_length=2000)
    status: Literal["confirmed", "candidate", "rejected", "automatic"] = "confirmed"
    role: Literal["owned", "service"] = "owned"
    evidence: str = Field(default="", max_length=10000)
    source_url: str = Field(default="", max_length=2000)


class StagingRequest(BaseModel):
    source: str = Field(min_length=1, max_length=200)
    adapter: str = Field(default="auto", min_length=1, max_length=80)
    content_type: str = Field(default="application/octet-stream", min_length=1, max_length=200)
    source_url: str = Field(default="", max_length=2000)
    stream_key: str = Field(default="", max_length=200)
    idempotency_key: str = Field(default="", max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)
    observed_at: str | None = None
    payload_encoding: Literal["utf-8", "json", "base64"] = "utf-8"
    payload: Any

    @field_validator("source", "adapter", "content_type")
    @classmethod
    def nonblank(cls, value):
        value = value.strip()
        if not value:
            raise ValueError("Source, adapter, and content type cannot be blank")
        return value

    @field_validator("observed_at")
    @classmethod
    def timestamp(cls, value):
        if value is None:
            return None
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("observed_at requires an ISO timestamp with timezone")
        return parsed.astimezone(timezone.utc).isoformat()


class StagingRetryRequest(BaseModel):
    adapter: str | None = Field(default=None, min_length=1, max_length=80)


class SourceSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_targets: list[dict[str, Any]] | None = Field(default=None, max_length=100)
    expected_source_targets: list[dict[str, Any]] | None = Field(default=None, max_length=100)
    source_intervals: dict[str, float] | None = None
    sources: dict[str, bool] | None = None
    provider_settings: dict[str, dict[str, Any]] | None = None
    watch_products: list[str] | None = Field(default=None, max_length=1000)
    exploit_keywords: list[str] | None = Field(default=None, max_length=200)


def compact_records(result):
    items = []
    for row in result["items"]:
        item = {key: value for key, value in row.items() if key not in ("configurations", "references")}
        if item.get("summary"):
            item["summary"] = item["summary"][:800]
        if "affected" in item:
            item["affected"] = item["affected"][:4]
        items.append(item)
    return {"items": items, "total": result["total"]}


def create_app(config, auto_collect=True):
    startup_sources = parse_startup_sources(os.environ.get("SIGNALWATCH_STARTUP_SOURCES"), config["sources"]) if auto_collect else []
    store = Store(config["db"])
    engine = Engine(config, store)
    from .jobs import Jobs
    jobs = Jobs(store)
    queue_enabled = bool(os.environ.get("CELERY_BROKER_URL", "").strip())
    dispatcher = None
    if queue_enabled:
        from .queue import QueueDispatcher
        dispatcher = QueueDispatcher(config, store)
    ingress = staging_queue(store, config)
    ingress_worker = StagingWorker(store, config, ingress)
    from .wireless_import import WirelessImports
    wireless_imports = WirelessImports(store, config)
    tasks = set()
    config_lock = threading.Lock()

    def collection_done(task):
        tasks.discard(task)
        if not task.cancelled() and task.exception():
            error = task.exception()
            logging.getLogger("signalwatch").error("Collection job failed: %s", error, exc_info=(type(error), error, error.__traceback__))

    @asynccontextmanager
    async def lifespan(app):
        async with engine:
            tasks.add(asyncio.create_task(ingress_worker.run(), name="staging-worker"))
            await wireless_imports.resume()
            if dispatcher is not None:
                tasks.add(asyncio.create_task(dispatcher.run(), name="collection-outbox"))
                if startup_sources:
                    await asyncio.to_thread(jobs.enqueue, "collect", {"sources": startup_sources})
            elif auto_collect:
                task = asyncio.create_task(engine.schedule(startup_sources=startup_sources))
                tasks.add(task)
            yield
            if dispatcher is not None:
                await dispatcher.stop()
            await wireless_imports.stop()
            enrichment = getattr(app.state, "wireless_enrichment", {}).get("task")
            if enrichment is not None and not enrichment.done():
                enrichment.cancel()
                with suppress(asyncio.CancelledError):
                    await enrichment
            for task in list(tasks):
                task.cancel()
            for task in list(tasks):
                with suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="SignalWatch", version=VERSION, lifespan=lifespan)
    app.state.store = store
    app.state.engine = engine
    app.state.jobs = jobs
    app.state.queue_enabled = queue_enabled
    app.state.staging = ingress
    api_token = config.get("api_token", "").encode("utf-8")
    @app.middleware("http")
    async def authorize(request, call_next):
        path = request.scope["path"]
        root_path = request.scope.get("root_path", "")
        if root_path and path.startswith(root_path + "/"):
            path = path[len(root_path):]
        if api_token and (path == "/api" or path.startswith("/api/")):
            scheme, _, credential = request.headers.get("authorization", "").partition(" ")
            if scheme.lower() != "bearer" or not secrets.compare_digest(credential.encode("utf-8"), api_token):
                return JSONResponse({"detail": "Bearer authentication required"}, status_code=401, headers={"WWW-Authenticate": "Bearer"})
        try:
            return await call_next(request)
        except Exception:
            logging.getLogger("signalwatch").exception("HTTP request failed")
            return JSONResponse({"detail": "Internal Server Error"}, status_code=500)
    app.add_middleware(CORSMiddleware, allow_origins=config.get("cors_origins", []), allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Authorization", "Content-Type", "X-Filename", "X-Source-Url"], allow_credentials=False)
    from .wireless_api import register_wireless_routes
    register_wireless_routes(app, config, store, wireless_imports)
    from .knowledge_graph import register_graph_routes
    register_graph_routes(app, store)
    from .extension_prerelease import register_prerelease_routes
    register_prerelease_routes(app, store)
    from .queue_api import register_job_routes
    register_job_routes(app, config, engine, jobs, queue_enabled)
    static = Path(__file__).parent / "static"
    app.mount("/static", StaticFiles(directory=static), name="static")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(static / "index.html")

    @app.get("/health")
    def health():
        return {"service": "SignalWatch", "version": VERSION, "auth_required": bool(api_token)}

    @app.get("/api/status")
    def status():
        fields = ("name", "status", "started_at", "finished_at", "last_success", "duration", "counts", "error", "retry_at",
                  "coverage", "coverage_scope", "coverage_floor", "coverage_through", "pending", "feed_health", "checked_at", "gap", "last_run", "next_run", "interval_minutes")
        sources = [{key: row[key] for key in fields if key in row} for row in store.sources()
                   if row["name"] in config["sources"] or row["name"].startswith("nvd-")]
        running = engine.busy()
        if not running:
            for row in sources:
                if row.get("status") == "running":
                    row["status"] = "interrupted"
        recent_jobs = jobs.list(limit=30) if queue_enabled else []
        completed_job = next((job for job in recent_jobs if job["status"] in {"succeeded", "failed"}), None)
        return {
            "stats": store.stats(), "running": running, "staging": ingress.stats(),
            "current_sources": (sorted(engine.current_sources) or [row["name"] for row in sources if row.get("status") == "running"]) if running else [], "sources": sources,
            "last_result": completed_job.get("result") if completed_job else engine.last_result,
            "error": completed_job.get("error", "") if completed_job else engine.last_error,
            "queue_enabled": queue_enabled,
            "config": {key: config[key] for key in ("concurrency", "per_host", "interval_minutes", "crawl_pages", "crawl_batch", "sources", "sbom_max_mb", "events_max_rows", "events_retention_days", "source_intervals", "public_source_batch", "public_source_records")}
        }

    @app.get("/api/sources/catalog")
    def catalog():
        from .sourcehub import source_catalog
        return source_catalog(config, store)

    @app.get("/api/sources/settings")
    def source_settings():
        from .sourcehub import public_settings
        return public_settings({key: config[key] for key in ("source_targets", "source_intervals", "sources", "provider_settings", "watch_products", "exploit_keywords")})

    @app.post("/api/sources/settings")
    async def save_source_settings(request: Request):
        from .sourcehub import definitions, public_settings
        body = bytearray()
        async for chunk in request.stream():
            # Reserve room for the original snapshot without reducing the
            # existing 64 KiB budget for the settings being saved.
            if len(body) + len(chunk) > 2 * 65536 + 1024:
                raise HTTPException(413, "Source settings request exceeds 129 KiB")
            body.extend(chunk)
        try:
            supplied = SourceSettingsRequest.model_validate_json(body).model_dump(exclude_none=True)
            expected_targets = supplied.pop("expected_source_targets", None)
            if len(json.dumps(supplied, ensure_ascii=False, separators=(",", ":")).encode()) > 65536:
                raise HTTPException(413, "Source settings exceed 64 KiB")
            if expected_targets is not None and "source_targets" not in supplied:
                raise ValueError("Expected source targets require a source targets update")
            providers = {row["id"] for row in definitions()}
            providers.add("technographics")
            if set(supplied.get("sources", {})) - set(config["sources"]) or set(supplied.get("source_intervals", {})) - set(config["sources"]):
                raise ValueError("Unknown source family")
            if set(supplied.get("provider_settings", {})) - providers:
                raise ValueError("Unknown provider")
            if any(not math.isfinite(value) or not 0 < value <= 525600 for value in supplied.get("source_intervals", {}).values()):
                raise ValueError("Source intervals must be positive minutes, at most one year")

            def validate_location(value):
                location = public_url(value)
                if any(re.search(r"(?:key|token|secret|password|signature|credential|authorization)", key, re.I)
                       for key, _ in parse_qsl(urlsplit(location).query, keep_blank_values=True)):
                    raise ValueError("Public source URLs must not include credentials")

            def validate(value):
                if isinstance(value, dict):
                    for key, child in value.items():
                        if re.search(r"(?:password|secret|token|api[_-]?key|authorization|credentials|headers)|^key$", key, re.I):
                            raise ValueError("Configure provider credentials through environment variables")
                        is_url = key == "url" or key.endswith("_url")
                        is_urls = key == "urls" or key.endswith("_urls") and key != "provider_urls"
                        if key == "enabled" and type(child) is not bool:
                            raise ValueError("Provider enabled must be a boolean")
                        if (is_url or key in {"query", "user_agent"}) and not isinstance(child, str):
                            raise ValueError(f"Provider {key} must be a string")
                        if is_urls and (not isinstance(child, list) or any(not isinstance(location, str) for location in child)):
                            raise ValueError(f"Provider {key} must be an array of strings")
                        if is_url and child:
                            validate_location(child)
                        if is_urls:
                            for location in child:
                                validate_location(location)
                        validate(child)
                elif isinstance(value, list):
                    for child in value:
                        validate(child)
                elif isinstance(value, str):
                    if len(value) > 4000:
                        raise ValueError("Source setting strings must be at most 4000 characters")
                    if re.match(r"https?://", value.strip(), re.I):
                        validate_location(value)
                elif isinstance(value, float) and not math.isfinite(value):
                    raise ValueError("Source settings must contain finite numbers")

            validate(supplied)
            if "nmap" in supplied.get("provider_settings", {}):
                from .nmap import scan_options
                scan_options({**config["provider_settings"].get("nmap", {}), **supplied["provider_settings"]["nmap"]})
            for target in supplied.get("source_targets", []):
                domain = target.get("domain", "")
                if not isinstance(domain, str) or not domain.strip() or any(char in domain for char in "/:@?#* "):
                    raise ValueError("Each source target requires a plain domain name")
                domain = domain.rstrip(".").encode("idna").decode().lower()
                if len(domain) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")):
                    raise ValueError("Invalid target domain name")
                target["domain"] = domain
                for key in ("document_urls", "javascript_urls", "sourcemap_urls", "feed_urls", "dkim_selectors", "bssids"):
                    if key in target and (not isinstance(target[key], list) or any(not isinstance(value, str) for value in target[key])):
                        raise ValueError(f"Target {key} must be an array of strings")
                for key in ("document_urls", "javascript_urls", "sourcemap_urls", "feed_urls"):
                    for location in target.get(key, []):
                        validate_location(location)
                if "provider_urls" in target:
                    if not isinstance(target["provider_urls"], dict) or any(not isinstance(locations, list) or any(not isinstance(location, str) for location in locations) for locations in target["provider_urls"].values()):
                        raise ValueError("Target provider_urls must map providers to URL arrays")
                    for locations in target["provider_urls"].values():
                        for location in locations:
                            validate_location(location)
        except (ValidationError, ValueError, UnicodeError, RecursionError) as error:
            raise HTTPException(422, str(error)[:300] if isinstance(error, ValueError) and not isinstance(error, ValidationError) else "Invalid source settings") from error
        with config_lock:
            # Compare the same public snapshot returned by GET, inside the write
            # lock so another save cannot pass between the check and replacement.
            if expected_targets is not None and expected_targets != public_settings(config["source_targets"]):
                raise HTTPException(409, "Source targets changed since you opened them. Reload before saving to preserve other changes.")
            changes = {}
            for key, value in supplied.items():
                if key in {"sources", "source_intervals"}:
                    changes[key] = {**config[key], **value}
                elif key == "provider_settings":
                    changes[key] = {**config[key], **{provider: {**config[key].get(provider, {}), **options} for provider, options in value.items()}}
                else:
                    changes[key] = value
            path = Path(config["config_path"])
            disk = json.loads(path.read_text()) if path.exists() else {}
            disk.update(changes)
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_text(json.dumps(disk, indent=2) + "\n")
            os.replace(temporary, path)
            config.update(changes)
        return {"saved": True, **source_settings()}

    @app.get("/api/search")
    def search(q: str = "", kind: str = "", limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
        return store.search(q, kind, limit, offset)

    @app.get("/api/advisories")
    def advisories(q: str = "", kev: bool = False, limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), sort: Literal["rank", "newest"] = "rank"):
        return compact_records(store.advisories(q, kev, limit, offset, sort=sort))

    @app.get("/api/alerts")
    def alerts(q: str = "", limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0), kev: bool = False,
               version_state: Literal["", "exact", "affected_range", "unknown", "version_unverified"] = "", sort: Literal["rank", "newest"] = "rank"):
        return store.alerts(q, limit, offset, kev=kev, version_state=version_state, sort=sort)

    @app.get("/api/articles")
    def articles(q: str = "", limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
        return compact_records(store.articles(q, limit, offset))

    @app.get("/api/events")
    def events(q: str = "", kind: EventKind = "", limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
        return store.events(q, kind, limit, offset)

    @app.get("/api/event")
    def event(id: str):
        result = store.event(id)
        if result is None:
            raise HTTPException(404, "Event not found")
        return result

    @app.get("/api/entity")
    def detail(id: str):
        result = store.detail(id)
        if result is None:
            raise HTTPException(404, "Record not found")
        if "technographics" in result:
            from .technographic_verifier import verifier_enabled
            result["technographics"]["verification"] = {"enabled": verifier_enabled(config)}
        return result

    @app.get("/api/staging/stats")
    def staging_stats():
        return {**ingress.stats(), "worker_result": ingress_worker.last_result, "worker_error": ingress_worker.last_error}

    @app.get("/api/staging")
    def staging_list(status: Literal["", "pending", "processing", "processed", "dead"] = "",
                     limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
        return ingress.list(status=status, limit=limit, offset=offset)

    @app.get("/api/staging/{item_id}/payload")
    def staging_payload(item_id: int):
        item = ingress.get(item_id, include_payload=True)
        if item is None:
            raise HTTPException(404, "Staged record not found")
        return Response(item["payload"], media_type="application/octet-stream",
                        headers={"Content-Disposition": f'attachment; filename="staging-{item_id}.bin"', "X-Content-Type-Options": "nosniff"})

    @app.get("/api/staging/{item_id}")
    def staging_detail(item_id: int):
        item = ingress.get(item_id)
        if item is None:
            raise HTTPException(404, "Staged record not found")
        return item

    @app.post("/api/staging", status_code=202)
    async def stage_record(request: Request):
        maximum = int(float(config.get("staging_max_payload_mb", 8)) * 1024 * 1024)
        body = bytearray()
        async for chunk in request.stream():
            if len(body) + len(chunk) > 2 * maximum + 65536:
                raise HTTPException(413, "Staging request exceeds the configured size limit")
            body.extend(chunk)
        try:
            supplied = StagingRequest.model_validate_json(body)
        except ValidationError as error:
            raise HTTPException(422, "Expected source, payload, encoding, and optional format/provenance fields") from error
        try:
            if len(json.dumps(supplied.metadata, allow_nan=False).encode()) > 16384:
                raise ValueError("Staging metadata exceeds 16 KiB")
            if supplied.payload_encoding == "json":
                payload = json.dumps(supplied.payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
            elif supplied.payload_encoding == "base64":
                if not isinstance(supplied.payload, str):
                    raise ValueError("Base64 payload must be a string")
                payload = base64.b64decode(supplied.payload, validate=True)
            else:
                if not isinstance(supplied.payload, str):
                    raise ValueError("UTF-8 payload must be a string")
                payload = supplied.payload.encode("utf-8")
            if len(payload) > maximum:
                raise HTTPException(413, "Payload exceeds the configured staging size limit")
            values = supplied.model_dump(exclude={"payload", "payload_encoding"})
            return await asyncio.to_thread(ingress.enqueue, payload, **values)
        except QueueFull as error:
            raise HTTPException(503, str(error), headers={"Retry-After": "30"}) from error
        except (ValueError, UnicodeError, binascii.Error) as error:
            raise HTTPException(400, str(error)) from error

    @app.post("/api/staging/{item_id}/retry")
    def staging_retry(item_id: int, request: StagingRetryRequest):
        try:
            return ingress.retry(item_id, adapter=request.adapter)
        except LookupError as error:
            raise HTTPException(404, str(error)) from error
        except ValueError as error:
            raise HTTPException(409, str(error)) from error

    @app.post("/api/collect")
    async def collect(request: CollectRequest):
        names = sorted(set(request.sources if request.sources is not None else engine.enabled()))
        if set(names) - set(config["sources"]):
            raise HTTPException(400, "Unknown collector name")
        if queue_enabled:
            from .queue_api import enqueue_job
            return await enqueue_job(jobs, "collect", {"sources": names}, request.idempotency_key)
        if engine.busy() or any(not task.done() and task.get_name() == "manual-collection" for task in tasks):
            return {"running": True, "queued": False}
        task = asyncio.create_task(engine.run(names), name="manual-collection")
        tasks.add(task)
        task.add_done_callback(collection_done)
        return {"queued": True, "sources": names}

    @app.post("/api/companies/profile")
    def save_company_profile(request: CompanyProfileRequest):
        from .entity_resolution import DomainConflict
        values = request.model_dump()
        try:
            if values["source_url"]:
                values["source_url"] = public_url(values["source_url"])
            return store.save_company_profile(**values)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except DomainConflict as exc:
            raise HTTPException(409, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/companies/resolve")
    def resolve_company(request: CompanyResolveRequest):
        from .entity_resolution import resolve
        context = request.model_dump(exclude={"source_url", "text"}, exclude_none=True)
        try:
            with store.connection() as conn:
                return resolve(conn, context, source_url=request.source_url, text=request.text)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/companies/assets")
    def set_company_asset(request: CompanyAssetRequest):
        values = request.model_dump()
        try:
            values["asset_url"] = public_url(values["asset_url"])
            if values["status"] != "automatic" and (not values["evidence"] or not values["source_url"]):
                raise ValueError("An evidence description and source URL are required for asset decisions")
            if values["source_url"]:
                values["source_url"] = public_url(values["source_url"])
            result = store.set_company_asset(**values)
        except LookupError as exc:
            raise HTTPException(404, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        if values["status"] == "confirmed" and values["role"] == "owned":
            store.enqueue_url(values["asset_url"], source_url=values["source_url"], company_id=request.company_id)
        return result

    @app.post("/api/seeds")
    def seeds(request: SeedRequest):
        try:
            urls = list(dict.fromkeys(public_url(url) for url in request.urls))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        for url in urls:
            store.enqueue_url(url, "user-seed")
        return {"count": len(urls)}

    @app.post("/api/sources/feed")
    def add_feed(request: FeedRequest):
        try:
            url = public_url(request.url)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        with config_lock:
            feeds = [item for item in config["feeds"] if item["url"] != url]
            feeds.append({"name": request.name, "url": url})
            path = Path(config["config_path"])
            disk = json.loads(path.read_text()) if path.exists() else {}
            disk["feeds"] = feeds
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_name(path.name + ".tmp")
            temporary.write_text(json.dumps(disk, indent=2) + "\n")
            os.replace(temporary, path)
            config["feeds"] = feeds
        return {"saved": True, "count": len(feeds)}

    @app.post("/api/observations")
    def add_observation(request: ObservationRequest):
        from .companies import asset_identity

        try:
            url = public_url(request.asset_url)
            asset, host = asset_identity(url)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        stamp = now()
        result = store.ingest({
            "entities": [{"id": asset, "kind": "domain", "name": host, "value": host, "metadata": {}, "observed_at": stamp, "source_url": url, "confidence": 1.0}],
            "observations": [{"asset_id": asset, "vendor": request.vendor, "product": request.product, "version": request.version,
                              "evidence": request.evidence, "source_url": url, "observed_at": stamp, "confidence": 1.0}]
        })
        store.reconcile()
        return {"saved": True, "counts": result, "id": asset}

    @app.post("/api/import/sbom")
    async def import_sbom(request: Request):
        from .sbom import parse_sbom

        body = bytearray()
        maximum = int(float(config.get("sbom_max_mb", 20)) * 1024 * 1024)
        async for chunk in request.stream():
            if len(body) + len(chunk) > maximum:
                raise HTTPException(413, "SBOM request exceeds the configured size limit")
            body.extend(chunk)
        try:
            supplied = SBOMRequest.model_validate_json(body)
        except ValidationError as exc:
            raise HTTPException(422, "Expected asset_url, source_key, and a JSON document object") from exc
        try:
            asset = public_url(supplied.asset_url)
            parsed = await asyncio.to_thread(parse_sbom, supplied.document, asset, supplied.source_key)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        counts = await asyncio.to_thread(store.ingest, parsed["batch"])
        matching = await asyncio.to_thread(store.reconcile)
        await asyncio.to_thread(store.prune_events, int(config.get("events_max_rows", 50000)), float(config.get("events_retention_days", 90)))
        return {"saved": True, "report": parsed["report"], "counts": counts, "matching": matching, "id": asset}

    @app.get("/api/export")
    def export(kind: str = "advisories", q: str = "", entity_kind: str = "", kev: bool = False,
               version_state: Literal["", "exact", "affected_range", "unknown", "version_unverified"] = "", sort: Literal["rank", "newest"] = "rank", event_kind: EventKind = ""):
        methods = {"entities": lambda offset: store.search(q, entity_kind, 500, offset),
                   "advisories": lambda offset: store.advisories(q, kev, 500, offset, sort=sort),
                   "alerts": lambda offset: store.alerts(q, 500, offset, kev=kev, version_state=version_state, sort=sort),
                   "articles": lambda offset: store.articles(q, 500, offset),
                   "events": lambda offset: store.events(q, event_kind, 500, offset)}
        if kind not in methods:
            raise HTTPException(400, "Unknown export kind")

        def rows():
            yield "["
            offset = 0
            first = True
            while True:
                result = methods[kind](offset)
                if not result["items"]:
                    break
                for item in result["items"]:
                    if not first:
                        yield ","
                    yield json.dumps(item, ensure_ascii=False)
                    first = False
                offset += len(result["items"])
                if offset >= result["total"]:
                    break
            yield "]"

        return StreamingResponse(rows(), media_type="application/json", headers={"Content-Disposition": f'attachment; filename="signalwatch-{kind}.json"'})

    return app
