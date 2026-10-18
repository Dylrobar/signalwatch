import asyncio
import csv
import json
import math
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote


INDEX_URL = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
DATA_URL = "https://storage.googleapis.com/osv-vulnerabilities/"


def timestamp(value):
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"OSV timestamp lacks timezone: {value}")
    return parsed.astimezone(timezone.utc)


def select_changes(path, cursor, limit, index_complete=True, start=0):
    upper = timestamp(cursor["upper"])
    lower = timestamp(cursor["lower"])
    before = timestamp(cursor["before"])
    seen = set(cursor.get("seen", []))
    selected = []
    selected_paths = set()
    previous = None
    complete = index_complete
    offset = start
    with path.open("rb") as stream:
        while line := stream.readline():
            line_start = start + stream.tell() - len(line)
            if not index_complete and not line.endswith(b"\n"):
                break
            row = next(csv.reader([line.decode("utf-8")]))
            if not row:
                offset = start + stream.tell()
                continue
            if len(row) != 2:
                raise ValueError("Malformed OSV modified_id.csv row")
            modified = timestamp(row[0])
            location = row[1]
            if not location or "/" not in location or any(part in {"", ".", ".."} for part in location.split("/")):
                raise ValueError("Malformed OSV record path")
            if previous is not None and modified > previous:
                raise ValueError("OSV changes index is not reverse chronological")
            previous = modified
            if modified > upper or modified > before:
                offset = start + stream.tell()
                continue
            if modified < lower:
                complete = True
                break
            if modified == before and location in seen:
                offset = start + stream.tell()
                continue
            if location in selected_paths:
                offset = start + stream.tell()
                continue
            if len(selected) == limit:
                complete = False
                offset = line_start
                break
            selected.append((modified.isoformat(), location))
            selected_paths.add(location)
            offset = start + stream.tell()
    cursor = {**cursor, "index_offset": offset}
    if selected:
        boundary = selected[-1][0]
        boundary_time = timestamp(boundary)
        boundary_seen = seen if boundary_time == before else set()
        boundary_seen.update(location for modified, location in selected if timestamp(modified) == boundary_time)
        cursor = {**cursor, "before": boundary, "seen": sorted(boundary_seen)}
    return selected, cursor, complete


def range_bounds(result, offset, etag=None, total=None):
    headers = {key.lower(): value for key, value in result.headers.items()}
    content_range = headers.get("content-range")
    size = result.path.stat().st_size
    if content_range:
        bounds = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", content_range)
        if bounds is None or int(bounds[1]) != offset or int(bounds[2]) < offset or int(bounds[2]) >= int(bounds[3]) or size != int(bounds[2]) - offset + 1:
            raise ValueError("Invalid OSV index Content-Range")
        length = int(bounds[3])
        complete = int(bounds[2]) + 1 == length
    elif result.status == 206:
        raise ValueError("OSV partial index lacks Content-Range")
    elif offset:
        raise ValueError("OSV index server ignored its requested byte range")
    else:
        length = size
        complete = True
    if etag and headers.get("etag", etag) != etag:
        raise ValueError("OSV index changed while reading its byte ranges")
    if total is not None and length != total:
        raise ValueError("OSV index size changed while reading its byte ranges")
    return length, complete, size


def probe_rows(data, offset, complete, aligned):
    position = 0 if aligned else data.find(b"\n") + 1
    if not aligned and not position:
        raise ValueError("OSV index row exceeds the configured byte chunk size")
    while position < len(data):
        end = data.find(b"\n", position)
        if end < 0:
            if not complete:
                return
            end = len(data)
        row = next(csv.reader([data[position:end].decode("utf-8")]))
        if len(row) != 2:
            raise ValueError("Malformed OSV modified_id.csv row")
        if not row[1] or "/" not in row[1] or any(part in {"", ".", ".."} for part in row[1].split("/")):
            raise ValueError("Malformed OSV record path")
        yield timestamp(row[0]), offset + position, offset + min(end + 1, len(data))
        position = end + 1


async def seek_index(http, first, cursor, chunk_bytes, etag):
    total, complete, size = range_bounds(first, 0, etag)
    target = min(timestamp(cursor["before"]), timestamp(cursor["upper"]))
    data = await asyncio.to_thread(first.path.read_bytes)
    low = 0
    for modified, start, end in probe_rows(data, 0, complete, True):
        if modified <= target:
            return start
        low = end
    if complete:
        return low
    probe_bytes = min(4096, chunk_bytes, size)
    high = total

    async def probe(offset):
        response = await http.get(INDEX_URL, headers={"Range": f"bytes={offset}-{offset + probe_bytes - 1}", "If-Match": etag}, max_bytes=probe_bytes, cache=False, force=True)
        try:
            _, finished, _ = range_bounds(response, offset, etag, total)
            body = await asyncio.to_thread(response.path.read_bytes)
            return body, finished
        finally:
            await asyncio.to_thread(response.path.unlink, missing_ok=True)

    for _ in range(64):
        if high - low <= probe_bytes:
            break
        middle = (low + high) // 2
        body, finished = await probe(middle)
        row = next(probe_rows(body, middle, finished, False), None)
        if row is None:
            raise ValueError("OSV index row exceeds the configured byte chunk size")
        modified, start, end = row
        if modified > target:
            low = end
        else:
            high = min(high, start)
    else:
        raise ValueError("OSV index timestamp seek did not converge")
    for _ in range(3):
        body, finished = await probe(low)
        previous = low
        for modified, start, end in probe_rows(body, low, finished, True):
            if modified <= target:
                return start
            low = end
        if finished:
            return low
        if low == previous:
            raise ValueError("OSV index row exceeds the configured byte chunk size")
    raise ValueError("OSV index timestamp seek exceeded its byte window")


def parse_osv(record):
    record_id = record.get("id")
    if not isinstance(record_id, str) or not record_id:
        raise ValueError("OSV record lacks an id")
    modified = record.get("modified")
    timestamp(modified)
    withdrawn = record.get("withdrawn")
    if withdrawn:
        timestamp(withdrawn)
    source_url = f"https://osv.dev/vulnerability/{quote(record_id, safe='')}"
    affected = []
    for item in record.get("affected", []):
        package = item.get("package") or {}
        ecosystem = package.get("ecosystem")
        name = package.get("name")
        if not isinstance(ecosystem, str) or not ecosystem or not isinstance(name, str) or not name:
            continue
        purl = package.get("purl")
        affected.append({
            "ecosystem": ecosystem,
            "package": name,
            "purl": purl,
            "ranges": item.get("ranges", []),
            "versions": item.get("versions", []),
        })
    scores = []
    for severity in record.get("severity", []):
        if severity.get("type") not in {"CVSS_V2", "CVSS_V3", "CVSS_V4"}:
            continue
        value = severity.get("score")
        if isinstance(value, bool):
            continue
        try:
            value = float(value)
        except (ValueError, TypeError):
            continue
        if math.isfinite(value) and 0 <= value <= 10:
            scores.append(value)
    advisory = {
        "id": "OSV:" + record_id,
        "aliases": list(dict.fromkeys([record_id] + [value for value in record.get("aliases", []) if isinstance(value, str)])),
        "title": record.get("summary") or record_id,
        "summary": record.get("details") or record.get("summary") or "",
        "published": record.get("published") or modified,
        "modified": modified,
        "severity": max(scores) if scores else None,
        "source": "osv", "url": source_url,
        "affected": [] if withdrawn else affected,
        "configurations": {"osv_affected": record.get("affected", []), "withdrawn": withdrawn},
        "references": [item["url"] for item in record.get("references", []) if isinstance(item.get("url"), str)],
        "withdrawn": withdrawn, "rejected": bool(withdrawn), "status": "withdrawn" if withdrawn else "active", "raw": record,
    }
    return {"advisories": [advisory], "entities": [], "edges": []}


async def collect_osv(config, store, http):
    limit = int(config.get("osv_max_records", 500))
    if limit < 1:
        raise ValueError("osv_max_records must be positive")
    state = await asyncio.to_thread(store.source_state, "osv")
    cursor = state.get("cursor")
    observed = datetime.now(timezone.utc)
    if not isinstance(cursor, dict):
        watermark = state.get("watermark")
        lower = timestamp(watermark) - timedelta(seconds=int(config.get("osv_overlap_seconds", 60))) if watermark else observed - timedelta(days=int(config.get("bootstrap_days", 30)))
        cursor = {"upper": observed.isoformat(), "lower": lower.isoformat(), "before": observed.isoformat(), "seen": []}
    chunk_bytes = int(config.get("osv_index_chunk_mb", 1)) * 1024 * 1024
    chunk_limit = int(config.get("osv_index_chunks", 8))
    chunk_cap = int(config.get("osv_index_max_chunks", max(chunk_limit, 32)))
    if chunk_bytes < 1 or chunk_limit < 1:
        raise ValueError("OSV index chunk settings must be positive")
    if chunk_cap < chunk_limit:
        raise ValueError("osv_index_max_chunks must be at least osv_index_chunks")
    chunk_limit = min(chunk_cap, chunk_limit * 2 ** min(max(0, int(state.get("no_progress_runs", 0))), chunk_cap.bit_length()))
    result = await http.get(INDEX_URL, headers={"Range": f"bytes=0-{chunk_bytes - 1}"}, max_bytes=chunk_bytes)
    headers = {key.lower(): value for key, value in result.headers.items()}
    etag = headers.get("etag")
    revision_changed = bool(cursor.get("index_etag") and etag and etag != cursor["index_etag"])
    total, _, _ = range_bounds(result, 0, etag)
    offset = int(cursor.get("index_offset", 0)) if etag and etag == cursor.get("index_etag") else 0
    if etag and etag != cursor.get("index_etag"):
        offset = await seek_index(http, result, cursor, chunk_bytes, etag)
    next_cursor = {**cursor, "index_etag": etag, "index_offset": offset}
    changes = []
    complete = offset == total
    for index in range(0 if complete else chunk_limit):
        if offset:
            range_headers = {"Range": f"bytes={offset}-{offset + chunk_bytes - 1}"}
            if etag:
                range_headers["If-Match"] = etag
            result = await http.get(INDEX_URL, headers=range_headers, max_bytes=chunk_bytes)
            headers = {key.lower(): value for key, value in result.headers.items()}
        _, index_complete, _ = range_bounds(result, offset, etag)
        selected, next_cursor, complete = await asyncio.to_thread(select_changes, result.path, next_cursor, limit - len(changes), index_complete, offset)
        changes.extend(selected)
        previous_offset = offset
        offset = next_cursor["index_offset"]
        if complete or len(changes) == limit:
            break
        if offset == previous_offset:
            raise ValueError("OSV index row exceeds the configured byte chunk size")
    semaphore = asyncio.Semaphore(int(config.get("concurrency", 32)))

    async def fetch(change):
        _, location = change
        async with semaphore:
            response = await http.get(DATA_URL + quote(location, safe="/") + ".json")
            record = await asyncio.to_thread(lambda: json.loads(response.path.read_text(encoding="utf-8")))
            if record.get("id") != location.rsplit("/", 1)[-1]:
                raise ValueError("OSV record id differs from its index path")
            return parse_osv(record)

    batches = await asyncio.gather(*(fetch(change) for change in changes))
    batch = {key: [item for part in batches for item in part[key]] for key in ("advisories", "entities", "edges")}
    counts = await asyncio.to_thread(store.ingest, batch) if changes else {}
    no_progress_runs = int(state.get("no_progress_runs", 0)) + 1 if not changes and not complete else 0
    errors = []
    if no_progress_runs >= 3 and revision_changed:
        errors.append(f"OSV backlog produced no records for {no_progress_runs} runs across index revisions. An equal-timestamp group may exceed the scan budget ({chunk_limit}/{chunk_cap} chunks). Retries grow to the cap; if this persists, increase osv_index_max_chunks or osv_index_chunk_mb. The watermark has not advanced.")
    if complete:
        await asyncio.to_thread(store.update_source, "osv", watermark=cursor["upper"], cursor=None, no_progress_runs=0)
    else:
        await asyncio.to_thread(store.update_source, "osv", cursor=next_cursor, no_progress_runs=no_progress_runs)
    return {**(counts or {}), "records": len(changes), "pending": not complete, "no_progress_runs": no_progress_runs, "index_chunks": chunk_limit, "index_revision_changed": revision_changed, "errors": errors, "withdrawn": sum(bool(item["withdrawn"]) for item in batch["advisories"])}
