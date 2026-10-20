"""Durable collection jobs; Redis transports IDs, the database owns their state."""
import fcntl
import hashlib
import json
import math
import tempfile
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path


SCHEMA = """
CREATE TABLE IF NOT EXISTS collection_jobs (
 id TEXT PRIMARY KEY, kind TEXT NOT NULL, payload TEXT NOT NULL, request_hash TEXT NOT NULL,
 idempotency_key TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'queued',
 attempts INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL,
 available_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
 result TEXT, error TEXT NOT NULL DEFAULT '', last_dispatched_at TEXT, lease_token TEXT,
 CHECK(status IN ('queued','running','retrying','succeeded','failed'))
);
CREATE UNIQUE INDEX IF NOT EXISTS collection_job_idempotency ON collection_jobs(idempotency_key)
 WHERE idempotency_key!='';
CREATE INDEX IF NOT EXISTS collection_job_outbox ON collection_jobs(status,available_at,last_dispatched_at);
CREATE INDEX IF NOT EXISTS collection_job_request ON collection_jobs(request_hash,status);
CREATE INDEX IF NOT EXISTS collection_job_history ON collection_jobs(finished_at,id);
CREATE TABLE IF NOT EXISTS collection_job_progress (
 job_id TEXT PRIMARY KEY REFERENCES collection_jobs(id) ON DELETE CASCADE,
 stage TEXT NOT NULL, completed INTEGER NOT NULL DEFAULT 0, total INTEGER,
 unit TEXT NOT NULL DEFAULT 'sources', message TEXT NOT NULL DEFAULT '',
 updated_at TEXT NOT NULL, partial INTEGER NOT NULL DEFAULT 0
);
"""
ACTIVE = ("queued", "running", "retrying")
TERMINAL = ("succeeded", "failed")
REPUBLISH_SECONDS = 300


class QueueFull(RuntimeError):
    pass


class IdempotencyConflict(ValueError):
    pass


class InvalidJobState(ValueError):
    pass


class LeaseLost(RuntimeError):
    pass


def stamp(clock=None):
    return datetime.fromtimestamp(time.time() if clock is None else clock, timezone.utc).isoformat(timespec="microseconds")


def _json(value, limit, name):
    try:
        result = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    except (ValueError, TypeError, RecursionError) as error:
        raise ValueError(f"Job {name} must contain JSON values") from error
    if len(result.encode("utf-8")) > limit:
        raise ValueError(f"Job {name} exceeds {limit} bytes")
    return result


def _decode(row, *, token=False):
    if row is None:
        return None
    result = dict(row)
    result["payload"] = json.loads(result["payload"])
    result["result"] = json.loads(result["result"]) if result["result"] is not None else None
    result.pop("request_hash", None)
    result["progress"] = {"stage": result.pop("progress_stage", None) or result["status"],
                          "completed": result.pop("progress_completed", None) or 0,
                          "total": result.pop("progress_total", None),
                          "unit": result.pop("progress_unit", None) or "sources",
                          "message": result.pop("progress_message", None) or "",
                          "updated_at": result.pop("progress_updated_at", None) or result["updated_at"],
                          "partial": bool(result.pop("progress_partial", False))}
    if not token:
        result.pop("lease_token", None)
    return result


JOB_SELECT = """SELECT j.*, p.stage AS progress_stage, p.completed AS progress_completed,
 p.total AS progress_total,p.unit AS progress_unit,p.message AS progress_message,
 p.updated_at AS progress_updated_at,p.partial AS progress_partial
 FROM collection_jobs j LEFT JOIN collection_job_progress p ON p.job_id=j.id"""


@contextmanager
def database_lock(store, name, *, path=None):
    """Nonblocking session locks survive transactions and coordinate separate hosts."""
    if getattr(store, "is_postgres", False):
        key = int.from_bytes(hashlib.sha256(("signalwatch:" + name).encode()).digest()[:8], "big", signed=True)
        with store.connection() as conn:
            acquired = conn.advisory_lock(key, wait=False)
            # Session locks remain held after commit; avoid keeping a snapshot
            # idle in transaction throughout long network collection.
            conn.commit()
            try:
                yield acquired
            finally:
                if acquired:
                    conn.advisory_unlock(key)
        return
    if path is None:
        path = (Path(tempfile.gettempdir()) / "signalwatch-job-locks" / hashlib.sha256(store.path.encode()).hexdigest() / "collector.lock"
                if store.uri else Path(store.path + ".collector.lock"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


class Jobs:
    def __init__(self, store, *, max_active=1000, max_completed=1000, retention_days=30):
        for name, value in (("max_active", max_active), ("max_completed", max_completed), ("retention_days", retention_days)):
            if type(value) is not int or value < (1 if name == "max_active" else 0):
                raise ValueError(f"{name} must be a nonnegative integer (max_active must be positive)")
        self.store = store
        self.max_active, self.max_completed, self.retention_days = max_active, max_completed, retention_days
        self.lock_dir = (Path(tempfile.gettempdir()) / "signalwatch-job-locks" / hashlib.sha256(store.path.encode()).hexdigest()
                         if store.uri or getattr(store, "is_postgres", False) else Path(store.path + ".jobs"))
        self.collector_lock = self.lock_dir / "collector.lock" if store.uri or getattr(store, "is_postgres", False) else Path(store.path + ".collector.lock")
        with store.connection(write=True) as conn:
            conn.executescript(SCHEMA)
            from .operations import ensure_schema
            ensure_schema(conn)

    def _lock_path(self, job_id):
        # Fixed stripes bound disk usage without unlinking an inode that a
        # finishing worker still owns. Collisions only defer unrelated jobs.
        stripe = int(hashlib.sha256(str(job_id).encode()).hexdigest()[:8], 16) % 1024
        return self.lock_dir / (f"{stripe:03x}.lock")

    def _prune(self, conn, clock):
        rows = conn.execute("""SELECT id FROM collection_jobs WHERE status IN ('succeeded','failed')
         AND (finished_at<? OR id NOT IN (SELECT id FROM collection_jobs WHERE status IN ('succeeded','failed')
          ORDER BY finished_at DESC,id DESC LIMIT ?))""", (stamp(clock - self.retention_days * 86400), self.max_completed)).fetchall()
        conn.executemany("DELETE FROM collection_jobs WHERE id=?", rows)
        return [row[0] for row in rows]

    def enqueue(self, kind, payload, idempotency_key="", *, deduplicate_active=False):
        if not isinstance(kind, str) or not kind or len(kind) > 100:
            raise ValueError("Job kind must be nonempty text of at most 100 characters")
        if not isinstance(payload, dict):
            raise ValueError("Job payload must be an object")
        if not isinstance(idempotency_key, str) or len(idempotency_key) > 512:
            raise ValueError("Idempotency key must be text of at most 512 characters")
        encoded = _json(payload, 64 * 1024, "payload")
        request_hash = hashlib.sha256((kind + "\0" + encoded).encode()).hexdigest()
        with self.store.connection(write=True) as conn:
            if idempotency_key:
                previous = conn.execute("SELECT * FROM collection_jobs WHERE idempotency_key=?", (idempotency_key,)).fetchone()
                if previous is not None:
                    if previous["request_hash"] != request_hash:
                        raise IdempotencyConflict("Idempotency key already represents a different collection request")
                    return _decode(conn.execute(JOB_SELECT + " WHERE j.id=?", (previous["id"],)).fetchone())
            if deduplicate_active:
                previous = conn.execute("SELECT * FROM collection_jobs WHERE request_hash=? AND status IN ('queued','running','retrying') ORDER BY created_at,id LIMIT 1", (request_hash,)).fetchone()
                if previous is not None:
                    return _decode(conn.execute(JOB_SELECT + " WHERE j.id=?", (previous["id"],)).fetchone())
            if conn.execute("SELECT count(*) FROM collection_jobs WHERE status IN ('queued','running','retrying')").fetchone()[0] >= self.max_active:
                raise QueueFull("Collection job queue is full")
            clock = time.time()
            self._prune(conn, clock)
            job_id, timestamp = uuid.uuid4().hex, stamp(clock)
            conn.execute("""INSERT INTO collection_jobs(id,kind,payload,request_hash,idempotency_key,created_at,updated_at,available_at)
             VALUES(?,?,?,?,?,?,?,?)""", (job_id, kind, encoded, request_hash, idempotency_key, timestamp, timestamp, timestamp))
            result = _decode(conn.execute("SELECT * FROM collection_jobs WHERE id=?", (job_id,)).fetchone())
        return result

    def get(self, job_id):
        with self.store.connection() as conn:
            return _decode(conn.execute(JOB_SELECT + " WHERE j.id=?", (job_id,)).fetchone())

    def _filters(self, *, company_id="", status="", kind=""):
        conditions, values = [], []
        if company_id:
            expression = "(j.payload::jsonb ->> 'company_id')" if getattr(self.store, "is_postgres", False) else "json_extract(j.payload,'$.company_id')"
            conditions.append(expression + "=?")
            values.append(company_id)
        for name, value in (("status", status), ("kind", kind)):
            if value:
                conditions.append("j." + name + "=?")
                values.append(value)
        return (" WHERE " + " AND ".join(conditions) if conditions else ""), values

    def list(self, limit=30, offset=0, **filters):
        where, values = self._filters(**filters)
        with self.store.connection() as conn:
            return [_decode(row) for row in conn.execute(JOB_SELECT + where + " ORDER BY j.created_at DESC,j.id DESC LIMIT ? OFFSET ?",
                     (*values, min(500, max(1, int(limit))), max(0, int(offset))))]

    def count(self, **filters):
        where, values = self._filters(**filters)
        with self.store.connection() as conn:
            return conn.execute("SELECT count(*) FROM collection_jobs j" + where, values).fetchone()[0]

    def record_progress(self, job_id, stage, *, completed=0, total=None, unit="sources", message="", partial=False, lease_token):
        if not lease_token:
            raise LeaseLost("Progress requires the active execution token")
        if not isinstance(stage, str) or not stage or len(stage) > 80:
            raise ValueError("Progress stage must contain at most 80 characters")
        if type(completed) is not int or completed < 0 or completed > 2**31 - 1:
            raise ValueError("Progress completed must be a nonnegative integer")
        if total is not None and (type(total) is not int or total < completed or total > 2**31 - 1):
            raise ValueError("Progress total must be at least completed")
        with self.store.connection(write=True) as conn:
            self._row(conn, job_id, lease_token)
            timestamp = stamp()
            conn.execute("""INSERT INTO collection_job_progress(job_id,stage,completed,total,unit,message,updated_at,partial)
             VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(job_id) DO UPDATE SET stage=excluded.stage,completed=excluded.completed,
             total=excluded.total,unit=excluded.unit,message=excluded.message,updated_at=excluded.updated_at,partial=excluded.partial""",
                         (job_id, stage, completed, total, str(unit)[:30], str(message)[:500], timestamp, int(bool(partial))))
            conn.execute("UPDATE collection_jobs SET updated_at=? WHERE id=?", (timestamp, job_id))

    def pending_dispatch(self, limit=20):
        clock = time.time()
        with self.store.connection() as conn:
            return [_decode(row) for row in conn.execute("""SELECT * FROM collection_jobs WHERE status IN ('queued','retrying')
             AND available_at<=? AND (last_dispatched_at IS NULL OR last_dispatched_at<=?)
             ORDER BY available_at,created_at,id LIMIT ?""", (stamp(clock), stamp(clock - REPUBLISH_SECONDS), min(500, max(1, int(limit)))))]

    def dispatched(self, job_id):
        with self.store.connection(write=True) as conn:
            timestamp = stamp()
            conn.execute("UPDATE collection_jobs SET last_dispatched_at=? WHERE id=? AND status IN ('queued','retrying') AND available_at<=?",
                         (timestamp, job_id, timestamp))

    def claim(self, job_id):
        with self.store.connection(write=True) as conn:
            timestamp = stamp()
            changed = conn.execute("""UPDATE collection_jobs SET status='running',attempts=attempts+1,
             started_at=?,updated_at=?,finished_at=NULL,error='',result=NULL,lease_token=?
             WHERE id=? AND status IN ('queued','retrying') AND available_at<=?""",
                                   (timestamp, timestamp, uuid.uuid4().hex, job_id, timestamp)).rowcount
            if changed:
                conn.execute("DELETE FROM collection_job_progress WHERE job_id=?", (job_id,))
            return _decode(conn.execute("SELECT * FROM collection_jobs WHERE id=?", (job_id,)).fetchone(), token=True) if changed else None

    def _row(self, conn, job_id, lease_token=None):
        row = conn.execute("SELECT * FROM collection_jobs WHERE id=?", (job_id,)).fetchone()
        if row is None:
            raise LookupError("Collection job does not exist")
        if lease_token is not None and (row["status"] != "running" or row["lease_token"] != lease_token):
            raise LeaseLost("Collection job belongs to another execution attempt")
        return row

    def finish(self, job_id, status, result=None, error="", *, lease_token=None):
        if status not in TERMINAL:
            raise ValueError("Finished collection job status must be succeeded or failed")
        encoded = _json(result, 1024 * 1024, "result") if result is not None else None
        with self.store.connection(write=True) as conn:
            row = self._row(conn, job_id, lease_token)
            if row["status"] != "running":
                raise InvalidJobState("Only a running collection job can finish")
            timestamp = stamp()
            sources = result.get("sources", []) if isinstance(result, dict) else []
            sources = sources if isinstance(sources, list) else []
            partial = status == "failed" and any(isinstance(item, dict) and item.get("ok") for item in sources)
            if not partial and status == "failed":
                partial = any(isinstance(item, dict) and isinstance(item.get("counts"), dict) and
                              any(isinstance(item["counts"].get(key), (int, float)) and item["counts"][key] > 0
                                  for key in ("pages", "observations", "fingerprints", "processed", "assets", "records", "staged")) for item in sources)
            conn.execute("""INSERT INTO collection_job_progress(job_id,stage,updated_at,partial) VALUES(?,?,?,?)
             ON CONFLICT(job_id) DO UPDATE SET stage=excluded.stage,updated_at=excluded.updated_at,partial=excluded.partial""",
                         (job_id, "completed" if status == "succeeded" else "failed", timestamp, int(partial)))
            conn.execute("""UPDATE collection_jobs SET status=?,result=?,error=?,finished_at=?,updated_at=?,lease_token=NULL WHERE id=?""",
                         (status, encoded, str(error)[:2000], timestamp, timestamp, job_id))
            return _decode(conn.execute(JOB_SELECT + " WHERE j.id=?", (job_id,)).fetchone())

    def defer(self, job_id, error="", delay=30, *, lease_token=None, attempted=True):
        if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not math.isfinite(delay) or not 0 <= delay <= 7 * 86400:
            raise ValueError("Job retry delay must be finite and between 0 and 604800 seconds")
        with self.store.connection(write=True) as conn:
            row = self._row(conn, job_id, lease_token)
            if row["status"] not in ACTIVE:
                raise InvalidJobState("Only an active collection job can be deferred")
            if row["status"] == "running" and lease_token is None:
                raise LeaseLost("Deferring a running job requires its execution token")
            clock = time.time()
            attempts = row["attempts"] - (1 if row["status"] == "running" and not attempted else 0)
            conn.execute("""UPDATE collection_jobs SET status='retrying',available_at=?,updated_at=?,error=?,
             last_dispatched_at=NULL,lease_token=NULL,attempts=? WHERE id=?""",
                         (stamp(clock + delay), stamp(clock), str(error)[:2000], max(0, attempts), job_id))
            conn.execute("UPDATE collection_job_progress SET stage='waiting',updated_at=? WHERE job_id=?", (stamp(clock), job_id))
            return _decode(conn.execute(JOB_SELECT + " WHERE j.id=?", (job_id,)).fetchone())

    def retry(self, job_id):
        with self.store.connection(write=True) as conn:
            row = self._row(conn, job_id)
            if row["status"] != "failed":
                raise InvalidJobState("Only a failed collection job can be retried")
            if conn.execute("SELECT count(*) FROM collection_jobs WHERE status IN ('queued','running','retrying')").fetchone()[0] >= self.max_active:
                raise QueueFull("Collection job queue is full")
            timestamp = stamp()
            conn.execute("DELETE FROM collection_job_progress WHERE job_id=?", (job_id,))
            conn.execute("""UPDATE collection_jobs SET status='queued',available_at=?,updated_at=?,started_at=NULL,
             finished_at=NULL,last_dispatched_at=NULL,result=NULL,error='',lease_token=NULL,attempts=0 WHERE id=?""", (timestamp, timestamp, job_id))
            return _decode(conn.execute(JOB_SELECT + " WHERE j.id=?", (job_id,)).fetchone())

    @contextmanager
    def worker_lock(self, job_id):
        # Expired Redis messages for pruned history need no lock acquisition.
        if self.get(job_id) is None:
            yield False
            return
        with database_lock(self.store, "job:" + job_id, path=self._lock_path(job_id)) as acquired:
            yield acquired

    def recover(self):
        count = 0
        with database_lock(self.store, "collector", path=self.collector_lock) as acquired:
            if not acquired:
                return 0
            if acquired:
                with self.store.connection() as conn:
                    ids = [row[0] for row in conn.execute("SELECT id FROM collection_jobs WHERE status='running' ORDER BY started_at,id LIMIT ?", (self.max_active,))]
                for job_id in ids:
                    with self.worker_lock(job_id) as acquired:
                        if not acquired:
                            continue
                        with self.store.connection(write=True) as conn:
                            timestamp = stamp()
                            count += conn.execute("""UPDATE collection_jobs SET status='retrying',available_at=?,updated_at=?,
                             error='Previous worker stopped before completing this job; queued for recovery',lease_token=NULL,last_dispatched_at=NULL
                             WHERE id=? AND status='running'""", (timestamp, timestamp, job_id)).rowcount
                with self.store.connection(write=True) as conn:
                    self._prune(conn, time.time())
        return count
