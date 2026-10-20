import argparse
import asyncio
import json
import logging
import mimetypes
import sys
from datetime import datetime, timezone
from pathlib import Path

from .config import DEFAULTS, load_config


def parser():
    root = argparse.ArgumentParser(prog="signalwatch")
    root.add_argument("--config", default="config.json")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("init")
    serve = commands.add_parser("serve")
    serve.add_argument("--host")
    serve.add_argument("--port", type=int)
    serve.add_argument("--no-collect", action="store_true")
    runtime = commands.add_parser("runtime", help="Supervise API and optional Celery worker on one data disk")
    runtime.add_argument("--host")
    runtime.add_argument("--port", type=int)
    runtime.add_argument("--no-collect", action="store_true", help="Disable automatic collection and Celery Beat")
    collect = commands.add_parser("collect")
    collect.add_argument("--sources", nargs="+")
    bootstrap = commands.add_parser("bootstrap")
    bootstrap.add_argument("--years", nargs="+", default=[str(datetime.now(timezone.utc).year)])
    commands.add_parser("status")
    seeds = commands.add_parser("seed")
    seeds.add_argument("urls", nargs="+")
    importing = commands.add_parser("import-jsonl")
    importing.add_argument("path", type=Path)
    importing.add_argument("--kind", choices=["advisories", "articles", "entities", "edges", "observations", "kev", "epss"])
    sbom = commands.add_parser("import-sbom")
    sbom.add_argument("path", type=Path)
    sbom.add_argument("--asset", required=True)
    sbom.add_argument("--source", default="default")
    stage = commands.add_parser("stage")
    stage.add_argument("path", type=Path)
    stage.add_argument("--source", required=True)
    stage.add_argument("--adapter", default="auto")
    stage.add_argument("--content-type")
    stage.add_argument("--source-url", default="")
    stage.add_argument("--stream-key", default="")
    stage.add_argument("--idempotency-key", default="")
    stage.add_argument("--observed-at")
    stage.add_argument("--metadata", default="{}")
    queue = commands.add_parser("staging")
    operations = queue.add_subparsers(dest="operation", required=True)
    listing = operations.add_parser("list")
    listing.add_argument("--status", choices=["pending", "processing", "processed", "dead"], default="")
    listing.add_argument("--limit", type=int, default=50)
    listing.add_argument("--offset", type=int, default=0)
    show = operations.add_parser("show")
    show.add_argument("id", type=int)
    show.add_argument("--payload", action="store_true")
    work = operations.add_parser("work")
    work.add_argument("--limit", type=int)
    retry = operations.add_parser("retry")
    retry.add_argument("id", type=int)
    retry.add_argument("--adapter")
    operations.add_parser("stats")
    operations.add_parser("prune")
    export = commands.add_parser("export")
    export.add_argument("--kind", choices=["entities", "advisories", "alerts", "articles", "events"], default="advisories")
    export.add_argument("--query", default="")
    export.add_argument("--event-kind", default="")
    return root


def main():
    args = parser().parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    if args.command == "init":
        path = Path(args.config).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("x") as output:
            json.dump(DEFAULTS, output, indent=2)
            output.write("\n")
        print(str(path.resolve()))
        return
    if args.command == "runtime":
        from .runtime import run
        raise SystemExit(run(args.config, host=args.host, port=args.port, no_collect=args.no_collect))
    config = load_config(args.config)
    if args.command == "serve":
        import uvicorn
        from .api import create_app
        uvicorn.run(create_app(config, auto_collect=not args.no_collect), host=args.host or config["host"], port=args.port or config["port"])
        return
    from .store import Store
    store = Store(config["db"])
    if args.command in ("collect", "bootstrap"):
        from .engine import Engine
        years = None
        if args.command == "bootstrap":
            if args.years == ["all"]:
                years = list(range(2002, datetime.now(timezone.utc).year + 1))
            else:
                years = [int(value) for value in args.years]
                if any(year < 2002 or year > datetime.now(timezone.utc).year for year in years):
                    raise ValueError("NVD feed years must be between 2002 and the current year")

        async def run():
            async with Engine(config, store) as engine:
                return await engine.run(sources=getattr(args, "sources", None), years=years)

        result = asyncio.run(run())
        print(json.dumps(result, indent=2))
        if result.get("busy") or any(not item["ok"] for item in result.get("sources", [])):
            raise SystemExit(1)
    elif args.command == "status":
        from .ingestion import staging_queue
        print(json.dumps({"stats": store.stats(), "sources": store.sources(), "staging": staging_queue(store, config).stats()}, indent=2))
    elif args.command == "stage":
        from .ingestion import staging_queue
        maximum = int(float(config.get("staging_max_payload_mb", 8)) * 1024 * 1024)
        if str(args.path) == "-":
            payload = sys.stdin.buffer.read(maximum + 1)
        else:
            with args.path.open("rb") as source:
                payload = source.read(maximum + 1)
        metadata = json.loads(args.metadata)
        if not isinstance(metadata, dict):
            raise ValueError("Staging metadata must be a JSON object")
        result = staging_queue(store, config).enqueue(
            payload, source=args.source, adapter=args.adapter,
            content_type=args.content_type or mimetypes.guess_type(str(args.path))[0] or "application/octet-stream",
            source_url=args.source_url, metadata=metadata, observed_at=args.observed_at,
            stream_key=args.stream_key, idempotency_key=args.idempotency_key)
        print(json.dumps(result, ensure_ascii=False))
    elif args.command == "staging":
        from .ingestion import StagingWorker, staging_queue
        queue = staging_queue(store, config)
        if args.operation == "list":
            result = queue.list(status=args.status, limit=args.limit, offset=args.offset)
        elif args.operation == "show":
            result = queue.get(args.id, include_payload=args.payload)
            if result is None:
                raise ValueError("Staged record not found")
            if args.payload:
                sys.stdout.buffer.write(result["payload"])
                return
        elif args.operation == "work":
            result = StagingWorker(store, config, queue).drain(args.limit)
        elif args.operation == "retry":
            result = queue.retry(args.id, adapter=args.adapter)
        elif args.operation == "prune":
            result = queue.prune(retention_days=float(config.get("staging_retention_days", 7)),
                                 max_completed=int(config.get("staging_max_completed", 10000)))
        else:
            result = queue.stats()
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.command == "seed":
        from .api import public_url
        urls = list(dict.fromkeys(public_url(value) for value in args.urls))
        for url in urls:
            store.enqueue_url(url, "user-seed")
        print(json.dumps({"queued": len(urls)}))
    elif args.command == "import-jsonl":
        count = 0
        batch = {}
        with args.path.open() as source:
            for line in source:
                if not line.strip():
                    continue
                item = json.loads(line)
                if args.kind:
                    batch.setdefault(args.kind, []).append(item)
                else:
                    for key, rows in item.items():
                        batch.setdefault(key, []).extend(rows)
                count += 1
                if count % 1000 == 0:
                    store.ingest(batch)
                    batch = {}
        if batch:
            store.ingest(batch)
        print(json.dumps({"lines": count, "matching": store.reconcile()}))
    elif args.command == "import-sbom":
        from .sbom import parse_sbom
        if args.path.stat().st_size > int(config.get("sbom_max_mb", 20) * 1024 * 1024):
            raise ValueError("SBOM document exceeds the configured size limit")
        with args.path.open(encoding="utf-8") as source:
            document = json.load(source)
        result = parse_sbom(document, args.asset, args.source)
        saved = store.ingest(result["batch"])
        matching = store.reconcile()
        store.prune_events(config.get("events_max_rows", 50000), config.get("events_retention_days", 90))
        print(json.dumps({"saved": saved, "report": result["report"], "matching": matching}, ensure_ascii=False))
    elif args.command == "export":
        methods = {"entities": lambda offset: store.search(args.query, "", 500, offset),
                   "advisories": lambda offset: store.advisories(args.query, False, 500, offset),
                   "alerts": lambda offset: store.alerts(args.query, 500, offset),
                   "articles": lambda offset: store.articles(args.query, 500, offset),
                   "events": lambda offset: store.events(args.query, args.event_kind, 500, offset)}
        offset = 0
        while True:
            result = methods[args.kind](offset)
            if not result["items"]:
                break
            for row in result["items"]:
                print(json.dumps(row, ensure_ascii=False))
            offset += len(result["items"])
            if offset >= result["total"]:
                break
