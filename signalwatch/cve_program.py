import asyncio
import hashlib
import json
import math
import re
import zipfile
from datetime import datetime, timezone

from .async_utils import gather, to_thread
from .extract import product_entities
from .matching import cpe_fields


DELTA_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/delta.json"
RELEASE_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases/latest"
RAW_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
CVE_ID = re.compile(r"CVE-(\d{4})-(\d{4,})")


def date(value):
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed.astimezone(timezone.utc)


def description(values):
    return next((item.get("value", "") for item in values if item.get("lang", "").startswith("en")), next((item.get("value", "") for item in values), ""))


def parse_cve5(record):
    metadata = record.get("cveMetadata", {})
    native_id = str(metadata.get("cveId", "")).upper()
    if record.get("dataType") != "CVE_RECORD" or not str(record.get("dataVersion", "")).startswith("5.") or CVE_ID.fullmatch(native_id) is None:
        raise ValueError("Expected a CVE JSON 5 record")
    state = metadata.get("state")
    if state not in {"PUBLISHED", "REJECTED"}:
        raise ValueError(f"Unsupported public CVE state: {state}")
    containers = record.get("containers", {})
    cna = containers.get("cna", {})
    all_containers = [cna, *containers.get("adp", [])]
    affected = []
    unverified_products = []
    scores = []
    references = []
    for container in all_containers:
        references.extend(item["url"] for item in container.get("references", []) if isinstance(item.get("url"), str))
        for metric in container.get("metrics", []):
            for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                value = (metric.get(key) or {}).get("baseScore")
                if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 10:
                    scores.append(float(value))
        for product in container.get("affected", []):
            versions = product.get("versions", [])
            if product.get("defaultStatus") != "affected" and not any(item.get("status") == "affected" for item in versions):
                continue
            identities = []
            for cpe in product.get("cpes", []):
                fields = cpe_fields(cpe)
                if fields.get("part") in {"a", "h", "o"} and fields.get("vendor") not in {None, "", "*", "-"} and fields.get("product") not in {None, "", "*", "-"}:
                    identities.append({**fields, "criteria": cpe})
            if not identities:
                unverified_products.append(product)
            for identity in identities:
                affected.append({
                    **identity, "version": "*", "version_unverified": True,
                    "cve_versions": versions, "cve_default_status": product.get("defaultStatus"),
                    "cve_product": product, "source_container": container.get("providerMetadata", {}).get("shortName"),
                })
    rejected = state == "REJECTED"
    summary = description(cna.get("rejectedReasons" if rejected else "descriptions", []))
    return {
        "id": "CVE5:" + native_id, "aliases": [native_id], "title": cna.get("title") or native_id,
        "summary": summary, "published": metadata.get("datePublished"),
        "modified": metadata.get("dateUpdated") or metadata.get("datePublished") or metadata.get("dateReserved"),
        "severity": max(scores) if scores else None, "source": "cve_program",
        "url": f"https://www.cve.org/CVERecord?id={native_id}",
        "affected": [] if rejected else affected, "references": list(dict.fromkeys(references)),
        "configurations": {"cve_state": state, "dataVersion": record["dataVersion"], "containers": containers, "unverified_products": unverified_products},
        "rejected": rejected, "raw": record,
    }


def changed(record, digest, seen):
    native_id = record.get("cveMetadata", {}).get("cveId", "").upper()
    previous = seen.get(native_id, {})
    modified = record.get("cveMetadata", {}).get("dateUpdated") or record.get("cveMetadata", {}).get("datePublished")
    if previous.get("digest") == digest:
        return False
    if previous.get("modified") and modified and date(previous["modified"]) > date(modified):
        return False
    return True


def read_archive(path, seen, excluded, limit):
    selected = []
    pending = False
    with zipfile.ZipFile(path) as archive:
        for member in sorted(archive.infolist(), key=lambda item: item.filename):
            if member.is_dir() or not member.filename.endswith(".json"):
                continue
            body = archive.read(member)
            record = json.loads(body)
            if not isinstance(record, dict) or "cveMetadata" not in record:
                continue
            native_id = record["cveMetadata"].get("cveId", "").upper()
            digest = hashlib.sha256(body).hexdigest()
            if native_id in excluded or not changed(record, digest, seen):
                continue
            if len(selected) == limit:
                pending = True
                break
            selected.append((record, digest))
    return selected, pending


async def collect_cve_program(config, store, http):
    state = await to_thread(store.source_state, "cve_program")
    limit = int(config.get("cve_max_records", 250))
    zip_limit = int(config.get("cve_max_zip_mb", 16)) * 1024 * 1024
    if limit < 1 or zip_limit < 1:
        raise ValueError("CVE collection limits must be positive")
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if config.get("github_token"):
        headers["Authorization"] = "Bearer " + config["github_token"]
    fetched = await gather(http.get(DELTA_URL, max_bytes=2 * 1024 * 1024), http.get(RELEASE_URL, headers=headers, max_bytes=2 * 1024 * 1024), return_exceptions=True)
    if all(isinstance(item, BaseException) for item in fetched):
        raise fetched[0]
    gaps = [reason for reason in state.get("gap_reasons", []) if reason.startswith("Unverified rollover interval")]
    delta = {}
    delta_result = fetched[0]
    if isinstance(delta_result, BaseException):
        gaps.append("Latest CNA update batch unavailable.")
    else:
        delta = await asyncio.to_thread(lambda: json.loads(delta_result.path.read_text(encoding="utf-8")))
        if not isinstance(delta, dict) or not isinstance(delta.get("new", []), list) or not isinstance(delta.get("updated", []), list):
            raise ValueError("Malformed CVE delta manifest")
    manifest = {}
    if isinstance(fetched[1], BaseException):
        gaps.append("Release manifest unavailable; missed CNA update batches are unverified.")
    else:
        manifest = await asyncio.to_thread(lambda: json.loads(fetched[1].path.read_text(encoding="utf-8")))
    asset = next((item for item in manifest.get("assets", []) if "_delta_CVEs_at_" in item.get("name", "") and item.get("name", "").endswith(".zip")), None)
    release_match = re.fullmatch(r"cve_(\d{4}-\d{2}-\d{2})_(\d{2})(\d{2})Z", manifest.get("tag_name", ""))
    cutoff = f"{release_match[1]}T{release_match[2]}:{release_match[3]}:00+00:00" if release_match else None
    day = release_match[1] if release_match else datetime.now(timezone.utc).date().isoformat()
    seen = dict(state.get("seen_records", {})) if state.get("seen_day") == day else {}
    if state.get("seen_day") and state["seen_day"] != day and state.get("coverage_through") and date(state["coverage_through"]) < date(day + "T00:00:00Z"):
        gaps.append(f"Unverified rollover interval {state['coverage_through']} to {day}T00:00:00Z.")
    delta_done = set(state.get("delta_done", [])) if not isinstance(delta_result, BaseException) and state.get("delta_digest") == delta_result.digest else set()
    changes = {item["cveId"].upper(): item for item in [*delta.get("new", []), *delta.get("updated", [])] if isinstance(item, dict) and CVE_ID.fullmatch(str(item.get("cveId", "")).upper())}
    raw_ids = sorted(set(changes) - delta_done)
    pending = len(raw_ids) > limit
    semaphore = asyncio.Semaphore(min(8, int(config.get("concurrency", 32))))

    async def fetch_record(native_id):
        matched = CVE_ID.fullmatch(native_id)
        url = f"{RAW_BASE}{matched[1]}/{matched[2][:-3]}xxx/{native_id}.json"
        async with semaphore:
            response = await http.get(url, max_bytes=8 * 1024 * 1024)
            record = await asyncio.to_thread(lambda: json.loads(response.path.read_text(encoding="utf-8")))
            if record.get("cveMetadata", {}).get("cveId", "").upper() != native_id:
                raise ValueError("CVE record id differs from its delta manifest")
            return record, response.digest

    records = await gather(*(fetch_record(native_id) for native_id in raw_ids[:limit]))
    delta_done.update(raw_ids[:limit])
    excluded = {record["cveMetadata"]["cveId"].upper() for record, _ in records}
    archive_complete = False
    archive_digest = None
    if asset is None or cutoff is None:
        gaps.append("No supported cumulative hourly delta release is available.")
    elif int(asset.get("size", 0)) > zip_limit:
        gaps.append("Cumulative hourly delta exceeds the configured archive size limit.")
    else:
        try:
            archive_result = await http.get(asset["browser_download_url"], max_bytes=zip_limit)
            archive_digest = archive_result.digest
            if state.get("archive_complete_digest") == archive_digest:
                archive_records, archive_pending = [], False
            else:
                archive_records, archive_pending = await asyncio.to_thread(read_archive, archive_result.path, seen, excluded, limit - len(records))
            records.extend(archive_records)
            pending = pending or archive_pending
            archive_complete = not archive_pending
        except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
            gaps.append(f"Cumulative hourly delta unavailable: {str(exc)[:200]}")
    advisories = [parse_cve5(record) for record, _ in records]
    entities = [entity for advisory in advisories for entity in product_entities([item for item in advisory["affected"] if item.get("criteria")], advisory["url"], advisory["modified"])]
    counts = await to_thread(store.ingest, {"advisories": advisories, "entities": entities}) if advisories else {}
    for (record, digest), advisory in zip(records, advisories):
        seen[record["cveMetadata"]["cveId"].upper()] = {"digest": digest, "modified": advisory["modified"]}
    if delta.get("error"):
        gaps.append("CVE Program reports errors in its latest update manifest.")
    gaps = list(dict.fromkeys(gaps))[-20:]
    possible_floor = day + "T00:00:00+00:00" if archive_digest else delta.get("fetchTime")
    floors = [value for value in (state.get("coverage_floor"), possible_floor) if value]
    floor = min(floors, key=date) if floors else None
    through = cutoff if archive_complete else state.get("coverage_through")
    fields = {
        "seen_day": day, "seen_records": seen, "delta_done": sorted(delta_done),
        "coverage_scope": "recent_delta", "coverage_floor": floor, "coverage_through": through,
        "raw_delta_fetch_time": delta.get("fetchTime") or state.get("raw_delta_fetch_time"),
        "history_complete": False, "pending": pending, "gap_reasons": gaps, "gap": "; ".join(gaps),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
    if not isinstance(delta_result, BaseException):
        fields["delta_digest"] = delta_result.digest
    if archive_complete:
        fields["archive_complete_digest"] = archive_digest
    await to_thread(store.update_source, "cve_program", **fields)
    return {**(counts or {}), "records": len(advisories), "pending": pending, "coverage_scope": "recent_delta", "coverage_floor": floor, "coverage_through": through, "raw_delta_fetch_time": fields["raw_delta_fetch_time"], "gap": fields["gap"], "history_complete": False}
