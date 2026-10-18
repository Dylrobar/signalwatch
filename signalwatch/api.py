import asyncio
import json
import logging
import os
import secrets
import threading
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from .config import VERSION
from .engine import Engine, now
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
    sources: list[str] | None = None


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
    store = Store(config["db"])
    engine = Engine(config, store)
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
            if auto_collect:
                task = asyncio.create_task(engine.schedule())
                tasks.add(task)
            yield
            for task in list(tasks):
                task.cancel()
            for task in list(tasks):
                with suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(title="SignalWatch", version=VERSION, lifespan=lifespan)
    app.state.store = store
    app.state.engine = engine
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
    app.add_middleware(CORSMiddleware, allow_origins=config.get("cors_origins", []), allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["Authorization", "Content-Type"], allow_credentials=False)
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
                  "coverage", "coverage_scope", "coverage_floor", "coverage_through", "pending", "feed_health", "checked_at", "gap")
        sources = [{key: row[key] for key in fields if key in row} for row in store.sources()
                   if row["name"] in config["sources"] or row["name"].startswith("nvd-")]
        running = engine.busy()
        if not running:
            for row in sources:
                if row.get("status") == "running":
                    row["status"] = "interrupted"
        return {
            "stats": store.stats(), "running": running,
            "current_sources": (sorted(engine.current_sources) or [row["name"] for row in sources if row.get("status") == "running"]) if running else [], "sources": sources,
            "last_result": engine.last_result, "error": engine.last_error,
            "config": {key: config[key] for key in ("concurrency", "per_host", "interval_minutes", "crawl_pages", "crawl_batch", "sources", "sbom_max_mb", "events_max_rows", "events_retention_days")}
        }

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
        return result

    @app.post("/api/collect")
    async def collect(request: CollectRequest):
        names = request.sources if request.sources is not None else engine.enabled()
        if set(names) - set(config["sources"]):
            raise HTTPException(400, "Unknown collector name")
        if engine.busy() or any(not task.done() and task.get_name() == "manual-collection" for task in tasks):
            return {"running": True, "queued": False}
        task = asyncio.create_task(engine.run(names), name="manual-collection")
        tasks.add(task)
        task.add_done_callback(collection_done)
        return {"queued": True, "sources": names}

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
        try:
            url = public_url(request.asset_url)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        host = urlsplit(url).hostname
        stamp = now()
        asset = "domain:" + host
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
