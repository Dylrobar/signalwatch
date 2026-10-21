"""Durable raw ingress with ordered streams and fenced, atomic ingestion."""
import hashlib
import json
import time
import uuid
from datetime import datetime, timezone


STAGING_SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_ingress (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 payload BLOB NOT NULL, payload_size INTEGER NOT NULL, payload_hash TEXT NOT NULL,
 source TEXT NOT NULL, adapter TEXT NOT NULL, content_type TEXT NOT NULL,
 source_url TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}',
 observed_at TEXT NOT NULL, stream_key TEXT NOT NULL DEFAULT '',
 idempotency_key TEXT NOT NULL DEFAULT '', context_hash TEXT NOT NULL,
 received_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
 attempts INTEGER NOT NULL DEFAULT 0, available_at REAL NOT NULL,
 lease_until REAL, lease_token TEXT, error TEXT, result TEXT, completed_at TEXT, superseded_by INTEGER,
 CHECK(status IN ('pending','processing','processed','dead'))
);
CREATE UNIQUE INDEX IF NOT EXISTS raw_idempotency ON raw_ingress(source,stream_key,adapter,idempotency_key)
 WHERE idempotency_key!='';
CREATE INDEX IF NOT EXISTS raw_available ON raw_ingress(status,available_at,id);
CREATE INDEX IF NOT EXISTS raw_stream ON raw_ingress(source,stream_key,id,status);
CREATE INDEX IF NOT EXISTS raw_expired_lease ON raw_ingress(status,lease_until,id);
CREATE INDEX IF NOT EXISTS raw_completed ON raw_ingress(status,completed_at,id);
"""

STATUSES = ("pending", "processing", "processed", "dead")
MAX_ATTEMPTS = 3
MAX_METADATA_BYTES = 16 * 1024
MAX_RESULT_BYTES = 16 * 1024
MAX_ERROR_CHARS = 2000
PUBLIC_COLUMNS = "id,payload_size,payload_hash,source,adapter,content_type,source_url,metadata,observed_at,stream_key,idempotency_key,received_at,status,attempts,available_at,lease_until,error,result,completed_at"


class QueueFull(RuntimeError):
    pass


class LeaseLost(RuntimeError):
    pass


def timestamp(value=None):
    if value is None:
        return datetime.fromtimestamp(time.time(), timezone.utc).isoformat(timespec="microseconds")
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise ValueError("observed_at must be an ISO timestamp") from error
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")


def bounded_json(value, limit, name):
    try:
        encoded = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must contain JSON values") from error
    if len(encoded.encode("utf-8")) > limit:
        raise ValueError(f"{name} exceeds {limit} bytes")
    return encoded


def text(value, name, limit, required=False):
    if not isinstance(value, str):
        raise ValueError(f"{name} must be a string")
    value = value.strip()
    if (required and not value) or len(value) > limit:
        raise ValueError(f"{name} must be {'nonempty and ' if required else ''}at most {limit} characters")
    return value


def decode(row, *, include_payload=False, include_token=False):
    if row is None:
        return None
    result = dict(row)
    if not include_payload:
        result.pop("payload", None)
    if not include_token:
        result.pop("lease_token", None)
    result.pop("context_hash", None)
    result.pop("superseded_by", None)
    result["metadata"] = json.loads(result["metadata"])
    result["result"] = json.loads(result["result"]) if result["result"] else None
    return result


def backoff(attempts):
    return min(3600, 30 * 2 ** max(0, attempts - 1))


class StagingQueue:
    def __init__(self, store, max_bytes=512 * 1024 ** 2, max_records=10000, max_payload_bytes=8 * 1024 ** 2):
        for name, value in (("max_bytes", max_bytes), ("max_records", max_records), ("max_payload_bytes", max_payload_bytes)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ValueError(f"{name} must be a positive integer")
        self.store = store
        self.max_bytes = max_bytes
        self.max_records = max_records
        self.max_payload_bytes = max_payload_bytes

    def _make_room(self, conn, size):
        if size > self.max_bytes:
            raise QueueFull("Raw payload cannot fit the queue byte capacity")
        count, total = conn.execute("SELECT count(*),coalesce(sum(payload_size),0) FROM raw_ingress").fetchone()
        if count < self.max_records and total + size <= self.max_bytes:
            return
        removable = conn.execute("SELECT id,payload_size FROM raw_ingress WHERE status='processed' ORDER BY completed_at,id")
        removed = []
        for row in removable:
            removed.append((row["id"],))
            count -= 1
            total -= row["payload_size"]
            if count < self.max_records and total + size <= self.max_bytes:
                break
        if count >= self.max_records or total + size > self.max_bytes:
            raise QueueFull("Raw queue is full; pending, processing, and dead records are retained")
        conn.executemany("DELETE FROM raw_ingress WHERE id=? AND status='processed'", removed)

    def enqueue(self, payload, *, source, adapter="auto", content_type="application/octet-stream", source_url="",
                metadata=None, observed_at=None, stream_key="", idempotency_key=""):
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise ValueError("Raw payload must be bytes")
        payload = bytes(payload)
        if len(payload) > self.max_payload_bytes:
            raise ValueError(f"Raw payload exceeds {self.max_payload_bytes} bytes")
        source = text(source, "source", 256, required=True)
        adapter = text(adapter, "adapter", 128, required=True)
        content_type = text(content_type, "content_type", 512, required=True)
        source_url = text(source_url, "source_url", 4096)
        stream_key = text(stream_key, "stream_key", 512)
        idempotency_key = text(idempotency_key, "idempotency_key", 512)
        metadata = {} if metadata is None else metadata
        if not isinstance(metadata, dict):
            raise ValueError("metadata must be an object")
        metadata_json = bounded_json(metadata, MAX_METADATA_BYTES, "metadata")
        explicit_observed_at = timestamp(observed_at) if observed_at is not None else None
        received_at = timestamp()
        payload_hash = hashlib.sha256(payload).hexdigest()
        context = bounded_json({"content_type": content_type, "source_url": source_url, "metadata": metadata,
                                "observed_at": explicit_observed_at}, MAX_METADATA_BYTES + 8192, "envelope")
        context_hash = hashlib.sha256(context.encode("utf-8")).hexdigest()
        with self.store.connection(write=True) as conn:
            if idempotency_key:
                previous = conn.execute("SELECT " + PUBLIC_COLUMNS + ",context_hash FROM raw_ingress WHERE source=? AND stream_key=? AND adapter=? AND idempotency_key=?",
                                        (source, stream_key, adapter, idempotency_key)).fetchone()
                if previous:
                    if previous["payload_hash"] != payload_hash or previous["context_hash"] != context_hash:
                        raise ValueError("Idempotency key already represents different payload or envelope context")
                    return {**decode(previous), "duplicate": True}
            self._make_room(conn, len(payload))
            cursor = conn.execute("""INSERT INTO raw_ingress(payload,payload_size,payload_hash,source,adapter,content_type,
             source_url,metadata,observed_at,stream_key,idempotency_key,context_hash,received_at,available_at)
             VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                                  (payload, len(payload), payload_hash, source, adapter, content_type, source_url,
                                   metadata_json, explicit_observed_at or received_at, stream_key, idempotency_key,
                                   context_hash, received_at, time.time()))
            return {**decode(conn.execute("SELECT " + PUBLIC_COLUMNS + " FROM raw_ingress WHERE id=?", (cursor.lastrowid,)).fetchone()), "duplicate": False}

    def get(self, item_id, include_payload=False):
        with self.store.connection() as conn:
            select = PUBLIC_COLUMNS + (",payload" if include_payload else "")
            return decode(conn.execute("SELECT " + select + " FROM raw_ingress WHERE id=?", (item_id,)).fetchone(), include_payload=include_payload)

    def list(self, status="", limit=50, offset=0):
        if status and status not in STATUSES:
            raise ValueError("Invalid raw queue status")
        limit, offset = min(500, max(1, int(limit))), max(0, int(offset))
        where, values = (" WHERE status=?", (status,)) if status else ("", ())
        with self.store.connection() as conn:
            total = conn.execute("SELECT count(*) FROM raw_ingress" + where, values).fetchone()[0]
            rows = conn.execute("SELECT " + PUBLIC_COLUMNS + " FROM raw_ingress" + where + " ORDER BY id DESC LIMIT ? OFFSET ?", (*values, limit, offset))
            return {"items": [decode(row) for row in rows], "total": total}

    def stats(self):
        with self.store.connection() as conn:
            counts = {status: 0 for status in STATUSES}
            sizes = {status: 0 for status in STATUSES}
            for row in conn.execute("SELECT status,count(*),coalesce(sum(payload_size),0) FROM raw_ingress GROUP BY status"):
                counts[row[0]], sizes[row[0]] = row[1], row[2]
            oldest = conn.execute("SELECT min(received_at),min(available_at) FROM raw_ingress WHERE status='pending'").fetchone()
            expired = conn.execute("SELECT count(*) FROM raw_ingress WHERE status='processing' AND lease_until<=?", (time.time(),)).fetchone()[0]
            return {"counts": counts, "bytes_by_status": sizes, "total": sum(counts.values()), "bytes": sum(sizes.values()),
                    "oldest_pending_at": oldest[0], "next_available_at": oldest[1], "expired_leases": expired,
                    "capacity": {"max_bytes": self.max_bytes, "max_records": self.max_records, "max_payload_bytes": self.max_payload_bytes}}

    def claim(self, lease_seconds=300):
        if isinstance(lease_seconds, bool) or not isinstance(lease_seconds, (int, float)) or not 0 < lease_seconds <= 86400:
            raise ValueError("lease_seconds must be positive and at most 86400")
        with self.store.connection(write=True) as conn:
            clock = time.time()
            conn.execute("""UPDATE raw_ingress SET status=CASE WHEN attempts>=? THEN 'dead' ELSE 'pending' END,
             available_at=?,lease_until=NULL,lease_token=NULL,error='Worker lease expired'
             WHERE id IN (SELECT id FROM raw_ingress WHERE status='processing' AND lease_until<=? ORDER BY lease_until,id LIMIT 100)""", (MAX_ATTEMPTS, clock, clock))
            row = conn.execute("""SELECT r.id FROM raw_ingress r WHERE r.status='pending' AND r.available_at<=?
             AND NOT EXISTS (SELECT 1 FROM raw_ingress earlier WHERE earlier.source=r.source AND earlier.stream_key=r.stream_key
              AND earlier.id<r.id AND earlier.status IN ('pending','processing'))
             AND NOT EXISTS (SELECT 1 FROM raw_ingress active WHERE active.source=r.source AND active.stream_key=r.stream_key
              AND active.status='processing') ORDER BY r.id LIMIT 1""", (clock,)).fetchone()
            if row is None:
                return None
            token = uuid.uuid4().hex
            conn.execute("""UPDATE raw_ingress SET status='processing',attempts=attempts+1,lease_until=?,lease_token=?
             WHERE id=?""", (clock + lease_seconds, token, row["id"]))
            return decode(conn.execute("SELECT * FROM raw_ingress WHERE id=?", (row["id"],)).fetchone(), include_payload=True, include_token=True)

    def _leased(self, conn, item_id, lease_token):
        row = conn.execute("SELECT " + PUBLIC_COLUMNS + ",lease_token FROM raw_ingress WHERE id=?", (item_id,)).fetchone()
        if row is None or row["status"] != "processing" or not lease_token or row["lease_token"] != lease_token or row["lease_until"] <= time.time():
            raise LeaseLost("Raw queue lease is missing, expired, or belongs to another worker")
        return row

    def complete(self, item_id, lease_token, batch):
        with self.store.connection(write=True) as conn:
            row = self._leased(conn, item_id, lease_token)
            counts = self.store.ingest(batch, conn=conn)
            result = bounded_json(counts, MAX_RESULT_BYTES, "result")
            conn.execute("""UPDATE raw_ingress SET status='processed',result=?,completed_at=?,error=NULL,
             lease_until=NULL,lease_token=NULL WHERE id=?""", (result, timestamp(), item_id))
            conn.execute("""UPDATE raw_ingress SET superseded_by=? WHERE source=? AND stream_key=? AND id<?
             AND superseded_by IS NULL""", (row["id"], row["source"], row["stream_key"], row["id"]))
            return {"id": row["id"], "status": "processed", "result": counts, "attempts": row["attempts"]}

    def fail(self, item_id, lease_token, error, retryable=True):
        message = (str(error) or type(error).__name__)[:MAX_ERROR_CHARS]
        with self.store.connection(write=True) as conn:
            row = self._leased(conn, item_id, lease_token)
            retry = bool(retryable) and row["attempts"] < MAX_ATTEMPTS
            conn.execute("""UPDATE raw_ingress SET status=?,available_at=?,error=?,lease_until=NULL,lease_token=NULL,
             completed_at=NULL,result=NULL WHERE id=?""", ("pending" if retry else "dead",
                                                          time.time() + backoff(row["attempts"]) if retry else time.time(), message, item_id))
            return decode(conn.execute("SELECT " + PUBLIC_COLUMNS + " FROM raw_ingress WHERE id=?", (item_id,)).fetchone())

    def retry(self, item_id, adapter=None):
        if adapter is not None:
            adapter = text(adapter, "adapter", 128, required=True)
        with self.store.connection(write=True) as conn:
            row = conn.execute("SELECT " + PUBLIC_COLUMNS + ",superseded_by FROM raw_ingress WHERE id=?", (item_id,)).fetchone()
            if row is None:
                raise LookupError("Raw queue item does not exist")
            if row["status"] == "processing" or conn.execute("""SELECT 1 FROM raw_ingress WHERE source=? AND stream_key=?
             AND status='processing' LIMIT 1""", (row["source"], row["stream_key"])).fetchone():
                raise ValueError("Cannot retry while this stream has a processing item")
            if row["superseded_by"] is not None or conn.execute("""SELECT 1 FROM raw_ingress WHERE source=? AND stream_key=? AND id>? AND status='processed' LIMIT 1""",
                            (row["source"], row["stream_key"], row["id"])).fetchone():
                raise ValueError("Cannot retry an older item after newer stream data was processed")
            chosen = row["adapter"] if adapter is None else adapter
            if row["idempotency_key"] and conn.execute("""SELECT 1 FROM raw_ingress WHERE source=? AND stream_key=? AND adapter=?
             AND idempotency_key=? AND id!=? LIMIT 1""", (row["source"], row["stream_key"], chosen, row["idempotency_key"], row["id"])).fetchone():
                raise ValueError("Retry adapter conflicts with another item's idempotency scope")
            conn.execute("""UPDATE raw_ingress SET status='pending',adapter=?,attempts=0,available_at=?,lease_until=NULL,
             lease_token=NULL,error=NULL,result=NULL,completed_at=NULL WHERE id=?""", (chosen, time.time(), item_id))
            return decode(conn.execute("SELECT " + PUBLIC_COLUMNS + " FROM raw_ingress WHERE id=?", (item_id,)).fetchone())

    def prune(self, retention_days=7, max_completed=10000):
        if retention_days < 0 or max_completed < 0:
            raise ValueError("Raw retention limits must be nonnegative")
        cutoff = datetime.fromtimestamp(time.time() - retention_days * 86400, timezone.utc).isoformat(timespec="microseconds")
        with self.store.connection(write=True) as conn:
            before = conn.execute("SELECT count(*),coalesce(sum(payload_size),0) FROM raw_ingress").fetchone()
            conn.execute("DELETE FROM raw_ingress WHERE status='processed' AND completed_at<?", (cutoff,))
            conn.execute("""DELETE FROM raw_ingress WHERE status='processed' AND id NOT IN
             (SELECT id FROM raw_ingress WHERE status='processed' ORDER BY completed_at DESC,id DESC LIMIT ?)""", (int(max_completed),))
            after = conn.execute("SELECT count(*),coalesce(sum(payload_size),0) FROM raw_ingress").fetchone()
            return {"removed_records": before[0] - after[0], "removed_bytes": before[1] - after[1]}
