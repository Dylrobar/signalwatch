"""Authenticated operational diagnostics; public health remains process liveness."""
import os
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path


def ensure_schema(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS worker_heartbeats (
     worker_id TEXT PRIMARY KEY, last_seen_at TEXT NOT NULL, status TEXT NOT NULL
    )""")


def heartbeat(store, worker_id, *, status="ready", clock=None):
    from .jobs import stamp
    clock = time.time() if clock is None else clock
    with store.connection(write=True) as conn:
        ensure_schema(conn)
        conn.execute("""INSERT INTO worker_heartbeats(worker_id,last_seen_at,status) VALUES(?,?,?)
         ON CONFLICT(worker_id) DO UPDATE SET last_seen_at=excluded.last_seen_at,status=excluded.status""",
                     (str(worker_id)[:200], stamp(clock), status))
        conn.execute("DELETE FROM worker_heartbeats WHERE last_seen_at<?", (stamp(clock - 7 * 86400),))


def _age(value, clock):
    try:
        date = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if date.tzinfo is None:
            date = date.replace(tzinfo=timezone.utc)
        return max(0, int(clock - date.timestamp()))
    except (TypeError, ValueError, OverflowError):
        return None


def operations_status(store, config, jobs, *, enabled=None, clock=None):
    from .engine import Engine
    from .jobs import stamp
    clock = time.time() if clock is None else clock
    enabled = bool(os.environ.get("CELERY_BROKER_URL", "").strip()) if enabled is None else enabled
    issues = []
    with store.connection() as conn:
        counts = dict.fromkeys(("queued", "running", "retrying", "succeeded", "failed"), 0)
        counts.update({row[0]: row[1] for row in conn.execute("SELECT status,count(*) FROM collection_jobs GROUP BY status")})
        oldest = conn.execute("SELECT min(created_at) FROM collection_jobs WHERE status IN ('queued','running','retrying')").fetchone()[0]
        stalled = conn.execute("SELECT count(*) FROM collection_jobs WHERE status='running' AND updated_at<?", (stamp(clock - 1800),)).fetchone()[0]
        workers = list(conn.execute("SELECT last_seen_at,status FROM worker_heartbeats ORDER BY last_seen_at DESC"))
        database_bytes = conn.execute("SELECT pg_database_size(current_database())").fetchone()[0] if getattr(store, "is_postgres", False) else None
    recent = [row for row in workers if row[1] == "ready" and (_age(row[0], clock) or 0) < 90]
    worker_status = "disabled" if not enabled else "ready" if recent else "stale" if workers else "unknown"
    if enabled and worker_status != "ready":
        issues.append({"code": "worker_heartbeat", "message": "No recent worker heartbeat; queued jobs may be waiting."})
    oldest_age = _age(oldest, clock)
    if enabled and oldest_age is not None and oldest_age > 3600:
        issues.append({"code": "queue_age", "message": "The oldest active job has been waiting or running for over an hour."})
    if stalled:
        issues.append({"code": "stalled_jobs", "message": "Running jobs have not reported progress for 30 minutes."})
    postgres = getattr(store, "is_postgres", False)
    data_path = Path(config.get("data_dir") or config.get("cache_dir") or ".") if postgres else Path(store.path).parent
    while not data_path.exists() and data_path != data_path.parent:
        data_path = data_path.parent
    usage = shutil.disk_usage(data_path)
    low_disk = usage.free < max(256 * 1024 * 1024, usage.total * .05)
    if low_disk:
        issues.append({"code": "low_disk", "message": "Local data storage has less than 5% or 256 MiB available."})
    if not postgres:
        database_bytes = Path(store.path).stat().st_size if not store.uri and Path(store.path).is_file() else 0
    wal = Path(store.path + "-wal") if not postgres and not store.uri else None
    states = {row["name"]: row for row in store.sources()}
    source_counts = {"stale": 0, "never_collected": 0, "errors": 0, "total": 0}
    engine = Engine(config, store)
    for name in engine.enabled():
        source_counts["total"] += 1
        state = states.get(name, {})
        age = _age(state.get("last_success"), clock)
        source_counts["never_collected"] += age is None
        source_counts["stale"] += age is not None and age > max(engine.interval(name) * 180, 3600)
        source_counts["errors"] += state.get("status") in {"error", "partial", "interrupted"}
    if source_counts["errors"] or source_counts["stale"]:
        issues.append({"code": "source_coverage", "message": "Some enabled sources have errors or stale coverage."})
    return {"generated_at": stamp(clock), "status": "degraded" if issues else "ok", "issues": issues,
            "queue": {"enabled": enabled, "counts": counts, "oldest_active_at": oldest,
                      "oldest_active_seconds": oldest_age, "stalled_running": stalled},
            "workers": {"status": worker_status, "last_seen_at": workers[0][0] if workers else None,
                        "count": len(recent), "stale_after_seconds": 90},
            "storage": {"backend": "postgresql" if postgres else "sqlite", "database_bytes": database_bytes,
                        "wal_bytes": wal.stat().st_size if wal and wal.exists() else None if postgres else 0,
                        "free_bytes": usage.free, "total_bytes": usage.total, "low_disk": low_disk},
            "sources": source_counts}


def register_operations_routes(app, store, config, jobs):
    @app.get("/api/operations")
    def get_operations():
        return operations_status(store, config, jobs)
