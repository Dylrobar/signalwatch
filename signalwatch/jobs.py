"""Durable collection jobs; Redis transports IDs, SQLite owns their state."""
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
    if not token:
        result.pop("lease_token", None)
    return result


class Jobs:
    def __init__(self, store, *, max_active=1000, max_completed=1000, retention_days=30):
        for name, value in (("max_active", max_active), ("max_completed", max_completed), ("retention_days", retention_days)):
            if type(value) is not int or value < (1 if name == "max_active" else 0):
                raise ValueError(f"{name} must be a nonnegative integer (max_active must be positive)")
        self.store = store
        self.max_active, self.max_completed, self.retention_days = max_active, max_completed, retention_days
        self.lock_dir = (Path(tempfile.gettempdir()) / "signalwatch-job-locks" / hashlib.sha256(store.path.encode()).hexdigest()
                         if store.uri else Path(store.path + ".jobs"))
        self.collector_lock = self.lock_dir / "collector.lock" if store.uri else Path(store.path + ".collector.lock")
        with store.connection(write=True) as conn:
            conn.executescript(SCHEMA)

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
                    return _decode(previous)
            if deduplicate_active:
                previous = conn.execute("SELECT * FROM collection_jobs WHERE request_hash=? AND status IN ('queued','running','retrying') ORDER BY created_at,id LIMIT 1", (request_hash,)).fetchone()
                if previous is not None:
                    return _decode(previous)
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
            return _decode(conn.execute("SELECT * FROM collection_jobs WHERE id=?", (job_id,)).fetchone())

    def list(self, limit=30):
        with self.store.connection() as conn:
            return [_decode(row) for row in conn.execute("SELECT * FROM collection_jobs ORDER BY created_at DESC,id DESC LIMIT ?", (min(500, max(1, int(limit))),))]

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
            conn.execute("""UPDATE collection_jobs SET status=?,result=?,error=?,finished_at=?,updated_at=?,lease_token=NULL WHERE id=?""",
                         (status, encoded, str(error)[:2000], timestamp, timestamp, job_id))
            return _decode(conn.execute("SELECT * FROM collection_jobs WHERE id=?", (job_id,)).fetchone())

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
            return _decode(conn.execute("SELECT * FROM collection_jobs WHERE id=?", (job_id,)).fetchone())

    def retry(self, job_id):
        with self.store.connection(write=True) as conn:
            row = self._row(conn, job_id)
            if row["status"] != "failed":
                raise InvalidJobState("Only a failed collection job can be retried")
            if conn.execute("SELECT count(*) FROM collection_jobs WHERE status IN ('queued','running','retrying')").fetchone()[0] >= self.max_active:
                raise QueueFull("Collection job queue is full")
            timestamp = stamp()
            conn.execute("""UPDATE collection_jobs SET status='queued',available_at=?,updated_at=?,started_at=NULL,
             finished_at=NULL,last_dispatched_at=NULL,result=NULL,error='',lease_token=NULL,attempts=0 WHERE id=?""", (timestamp, timestamp, job_id))
            return _decode(conn.execute("SELECT * FROM collection_jobs WHERE id=?", (job_id,)).fetchone())

    @contextmanager
    def worker_lock(self, job_id):
        # Expired Redis messages for pruned history need no lock acquisition.
        if self.get(job_id) is None:
            yield False
            return
        self.lock_dir.mkdir(parents=True, exist_ok=True)
        with self._lock_path(job_id).open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def recover(self):
        self.collector_lock.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with self.collector_lock.open("a") as guard:
            try:
                fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return 0
            try:
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
            finally:
                fcntl.flock(guard, fcntl.LOCK_UN)
        return count
