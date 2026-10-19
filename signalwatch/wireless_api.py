import asyncio
import hashlib
import json
import uuid
from pathlib import Path
from typing import Any, Literal
from urllib.parse import unquote

from fastapi import HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field


class WirelessDecision(BaseModel):
    company_id: str = Field(min_length=1, max_length=300)
    status: Literal["confirmed", "rejected"]
    evidence: str = Field(min_length=1, max_length=10000)
    source_url: str = Field(min_length=1, max_length=2000)


class FacilityRequest(BaseModel):
    name: str = Field(min_length=1, max_length=500)
    latitude: float = Field(ge=-90, le=90)
    longitude: float = Field(ge=-180, le=180)
    company_id: str = Field(default="", max_length=300)
    website: str = Field(default="", max_length=2000)
    source_url: str = Field(min_length=1, max_length=2000)
    evidence: dict[str, Any] = Field(default_factory=dict)


class EnrichmentRequest(BaseModel):
    manufacturers: bool = True
    facilities: bool = True
    lookup_businesses: bool = False
    bbox: list[float] | None = Field(default=None, min_length=4, max_length=4)
    cells: int = Field(default=12, ge=1, le=32)


def dataset_row(row):
    metadata = row.get("metadata") or {}
    return {**row, "observations": row.get("observation_count", 0), "devices": row.get("device_count", row.get("devices", 0)),
            "timestamp_timezone": metadata.get("timestamp_timezone", "unspecified")}


def device_row(row):
    return {**row, "name": row.get("ssid") or row.get("identifier") or row["id"], "type": row.get("radio_type"),
            "observations": row.get("observation_count", 0), "gps_accuracy": row.get("accuracy_meters"),
            "timestamp_timezone": (row.get("metadata") or {}).get("timestamp_timezone", "unspecified"),
            "company_links": row.get("company_links", [])}


def register_wireless_routes(app, config, store, imports):
    from . import wireless as data
    from . import wireless_attribution as attribution
    from .api import public_url
    from .ingestion import staging_queue
    from .http import PublicHTTP
    from .staging import QueueFull

    enrichment = {"task": None}
    if store.source_state("wireless_enrichment").get("status") == "running":
        store.update_source("wireless_enrichment", status="interrupted", phase="interrupted",
                            error="Server restarted during company matching; run enrichment again to resume.")

    async def retain(payload, source, location, content_type, metadata, version):
        try:
            return await asyncio.to_thread(staging_queue(store, config).enqueue, payload, source=source, adapter="opaque",
                                           source_url=location, content_type=content_type, metadata=metadata,
                                           idempotency_key=hashlib.sha256(payload + location.encode() + version.encode()).hexdigest())
        except QueueFull as error:
            raise HTTPException(503, str(error), headers={"Retry-After": "30"}) from error

    @app.get("/api/wireless/datasets")
    def datasets(limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
        result = data.datasets(store, limit=limit, offset=offset)
        return {"items": [dataset_row(row) for row in result["items"]], "total": result["total"]}

    @app.get("/api/wireless/datasets/{dataset_id}/source")
    def dataset_source(dataset_id: str):
        try:
            path = imports.archive(dataset_id)
        except LookupError as error:
            raise HTTPException(404, str(error)) from error
        return FileResponse(path, media_type="application/octet-stream", filename=imports.state(dataset_id).get("dataset_name", path.name), headers={"X-Content-Type-Options": "nosniff"})

    @app.get("/api/wireless/datasets/{dataset_id}")
    def dataset(dataset_id: str):
        rows = data.datasets(store, limit=500)["items"]
        row = next((row for row in rows if row["id"] == dataset_id), None)
        if row is None:
            raise HTTPException(404, "Wireless dataset does not exist")
        state = imports.state(dataset_id)
        return {**dataset_row(row), "job": {key: state[key] for key in ("status", "queued_rows", "expected_rows", "chunks", "error") if key in state}}

    @app.get("/api/wireless/stats")
    def stats(dataset_id: str = ""):
        return data.stats(store, dataset_id=dataset_id)

    @app.get("/api/wireless/devices")
    def devices(q: str = "", type: str = "", dataset_id: str = "", company_id: str = "",
                limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
        result = data.devices(store, q=q, radio_type=type, dataset_id=dataset_id, company_id=company_id, limit=limit, offset=offset)
        with store.connection() as conn:
            items = []
            for row in result["items"]:
                links = attribution.device_company_links(conn, row["id"])
                items.append({**device_row(row), "company_links": links["items"],
                              "attribution": {key: value for key, value in links.items() if key != "items"}})
        return {"items": items, "total": result["total"]}

    @app.get("/api/wireless/devices/{device_id}")
    def device(device_id: str, limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        try:
            row = data.device_detail(store, device_id, limit=limit, offset=offset)
        except LookupError as error:
            raise HTTPException(404, str(error)) from error
        if row is None:
            raise HTTPException(404, "Wireless device does not exist")
        with store.connection() as conn:
            links = attribution.device_company_links(conn, device_id)
        records = row.pop("observations", [])
        locations = [{"latitude": value["latitude"], "longitude": value["longitude"],
                      "gps_accuracy": value.get("accuracy_meters"), "rssi": value.get("rssi"),
                      "first_seen": value.get("observed_at"), "last_seen": value.get("observed_at"),
                      "observations": 1} for value in records if value.get("latitude") is not None and value.get("longitude") is not None]
        return {**device_row(row), "company_links": links["items"],
                "attribution": {key: value for key, value in links.items() if key != "items"},
                "observation_records": records, "locations": locations,
                "locations_total": row["observations_total"],
                "locations_truncated": offset + len(records) < row["observations_total"],
                "provenance": {"location_basis": "scan_observation", "representative_observation": (row.get("metadata") or {}).get("representative_observation"),
                               "datasets": list({value["dataset_id"]: {"id": value["dataset_id"], "name": value.get("dataset_name"), "source_url": value.get("source_url")} for value in records}.values())}}

    @app.get("/api/wireless/map")
    def map_data(bbox: str, zoom: int = Query(8, ge=0, le=22), dataset_id: str = "", type: str = "", q: str = "", company_id: str = "",
                 limit: int = Query(2000, ge=1, le=5000)):
        try:
            bounds = [float(value) for value in bbox.split(",")]
            result = data.map_clusters(store, bounds, zoom=zoom, dataset_id=dataset_id, radio_type=type, q=q, company_id=company_id, limit=limit)
            return {"type": "FeatureCollection", "features": [
                {"type": "Feature", "geometry": {"type": "Point", "coordinates": [point["longitude"], point["latitude"]]},
                 "properties": {"count": point["observations"], "devices": point["devices"], "device_id": point.get("device_id"),
                                "type": point.get("type"), "name": point.get("name"), "rssi": point.get("max_rssi")}}
                for point in result["items"]], "total": result["total"], "truncated": result["truncated"],
                    "bbox": result["bbox"], "location_basis": result["location_basis"]}
        except (TypeError, ValueError) as error:
            raise HTTPException(400, str(error)) from error

    @app.post("/api/import/wigle", status_code=202)
    async def upload(request: Request):
        maximum = int(float(config.get("wireless_import_max_mb", 32)) * 1024 * 1024)
        size, digest = 0, hashlib.sha256()
        name = Path(unquote(request.headers.get("X-Filename", "WiGLE-export.csv.gz"))).name
        name = "".join(char for char in name if ord(char) >= 32)[:240] or "WiGLE-export.csv.gz"
        temporary = imports.directory / (uuid.uuid4().hex + ".part")
        try:
            with temporary.open("wb") as stream:
                async for block in request.stream():
                    size += len(block)
                    if size > maximum:
                        raise HTTPException(413, "Wireless upload exceeds the configured compressed file size limit")
                    digest.update(block)
                    stream.write(block)
            if not size:
                raise HTTPException(400, "Wireless upload is empty")
            value = digest.hexdigest()
            with temporary.open("rb") as stream:
                suffix = ".csv.gz" if stream.read(2) == b"\x1f\x8b" else ".csv"
            archive = imports.directory / (value + suffix)
            if archive.exists():
                temporary.unlink()
            else:
                temporary.replace(archive)
            return await imports.start(archive, name, value, request.headers.get("X-Source-Url", ""))
        finally:
            temporary.unlink(missing_ok=True)

    @app.post("/api/wireless/devices/{device_id}/company")
    def decide_company(device_id: str, request: WirelessDecision):
        try:
            attribution.set_device_company(store, device_id, request.company_id, request.status, request.evidence, public_url(request.source_url))
            return device(device_id, limit=100, offset=0)
        except LookupError as error:
            raise HTTPException(404, str(error)) from error
        except ValueError as error:
            raise HTTPException(400, str(error)) from error

    @app.get("/api/wireless/facilities")
    def facilities(company_id: str = "", limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
        return attribution.list_facilities(store, company_id=company_id, limit=limit, offset=offset)

    @app.post("/api/wireless/facilities")
    def save_facility(request: FacilityRequest):
        try:
            values = request.model_dump()
            values["source_url"] = public_url(values["source_url"])
            if values["website"]:
                values["website"] = public_url(values["website"])
            return attribution.upsert_facility(store, **values)
        except (LookupError, ValueError) as error:
            raise HTTPException(400, str(error)) from error

    @app.post("/api/wireless/registries")
    async def registry(request: Request, registry: str, source_url: str = "", version: str = ""):
        if registry not in attribution.REGISTRY_URLS:
            raise HTTPException(400, "Unknown manufacturer registry")
        payload = bytearray()
        async for block in request.stream():
            if len(payload) + len(block) > 8 * 1024 * 1024:
                raise HTTPException(413, "Registry exceeds 8 MiB")
            payload.extend(block)
        try:
            location = public_url(source_url or attribution.REGISTRY_URLS[registry])
        except ValueError as error:
            raise HTTPException(400, str(error)) from error
        raw = bytes(payload)
        await retain(raw, "wireless-registry:" + registry, location, request.headers.get("Content-Type", "text/plain"),
                     {"registry": registry, "version": version}, version)
        try:
            return await asyncio.to_thread(attribution.import_manufacturer_registry, store, raw, registry, location, version=version)
        except (ValueError, UnicodeError) as error:
            raise HTTPException(400, str(error)) from error

    @app.post("/api/wireless/device-enrichment")
    async def device_enrichment(request: Request, source_url: str, version: str = ""):
        try:
            location = public_url(source_url)
        except ValueError as error:
            raise HTTPException(400, str(error)) from error
        payload = bytearray()
        async for block in request.stream():
            if len(payload) + len(block) > 8 * 1024 * 1024:
                raise HTTPException(413, "Device enrichment exceeds 8 MiB")
            payload.extend(block)
        try:
            records = json.loads(payload)
            if not isinstance(records, list) or len(records) > 10000:
                raise ValueError("Enrichment requires up to 10000 records")
            raw = bytes(payload)
            await retain(raw, "wireless-device-enrichment", location, "application/json", {"version": version}, version)
            return await asyncio.to_thread(attribution.import_device_enrichment, store, records, location, version)
        except (ValueError, TypeError, UnicodeError) as error:
            raise HTTPException(400, str(error)) from error

    @app.post("/api/wireless/business-import")
    async def business_import(request: Request, source_url: str):
        try:
            location = public_url(source_url)
        except ValueError as error:
            raise HTTPException(400, str(error)) from error
        payload = bytearray()
        async for block in request.stream():
            if len(payload) + len(block) > 8 * 1024 * 1024:
                raise HTTPException(413, "Business import exceeds 8 MiB")
            payload.extend(block)
        try:
            records = json.loads(payload)
            raw = bytes(payload)
            await retain(raw, "wireless-business-import", location, "application/json", {}, "")
            return await asyncio.to_thread(attribution.import_osm_facilities, store, records)
        except (ValueError, TypeError, UnicodeError) as error:
            raise HTTPException(400, str(error)) from error

    async def run_enrichment(request):
        await asyncio.to_thread(store.update_source, "wireless_enrichment", status="running", error=None,
                                phase="manufacturer_matching" if request.manufacturers else "business_matching")
        try:
            result = {}
            if request.manufacturers:
                result["manufacturers"] = await asyncio.to_thread(attribution.enrich_manufacturers, store)
            if request.facilities:
                cells = []
                if request.lookup_businesses:
                    cells = [[request.bbox[1], request.bbox[0], request.bbox[3], request.bbox[2]]] if request.bbox else await asyncio.to_thread(attribution.dense_scan_cells, store, limit=request.cells)
                fetched, errors = [], []
                await asyncio.to_thread(store.update_source, "wireless_enrichment", phase="business_lookup", cells_total=len(cells), cells_completed=0)
                async with PublicHTTP({**config, "timeout": max(60, float(config.get("timeout", 30)))}) as http:
                    for index, cell in enumerate(cells):
                        bounds = cell.get("bbox") if isinstance(cell, dict) else cell
                        try:
                            fetched.append(await attribution.fetch_business_facilities(http, store, bounds))
                        except Exception as error:
                            errors.append((str(error) or type(error).__name__)[:300])
                        await asyncio.to_thread(store.update_source, "wireless_enrichment", cells_completed=index+1,
                                                facilities_imported=sum(row["imported"] for row in fetched), lookup_errors=len(errors))
                result["facilities"] = fetched
                await asyncio.to_thread(store.update_source, "wireless_enrichment", phase="spatial_matching")
                matches, cursor = [], ""
                while True:
                    page = await asyncio.to_thread(attribution.match_facilities, store, after_facility_id=cursor)
                    matches.append(page)
                    if not page["has_more"]:
                        break
                    cursor = page["next_cursor"]
                result["matches"] = matches
                result["errors"] = errors
            await asyncio.to_thread(store.update_source, "wireless_enrichment", status="partial" if result.get("errors") else "complete", phase="finished", counts=result)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            await asyncio.to_thread(store.update_source, "wireless_enrichment", status="failed", error=(str(error) or type(error).__name__)[:1000])

    @app.get("/api/wireless/enrichment")
    def enrichment_status():
        return store.source_state("wireless_enrichment")

    @app.post("/api/wireless/enrichment", status_code=202)
    async def enrich(request: EnrichmentRequest):
        if request.bbox:
            try:
                west, south, east, north = data._bbox(request.bbox)
                if not west < east or not south < north or east-west > 1 or north-south > 1:
                    raise ValueError("Business query requires a positive box no wider than one degree")
            except (ValueError, TypeError) as error:
                raise HTTPException(400, str(error)) from error
        task = enrichment["task"]
        if task is not None and not task.done():
            return {"status": "running", "queued": False}
        enrichment["task"] = asyncio.create_task(run_enrichment(request), name="wireless-enrichment")
        return {"status": "queued", "queued": True}

    app.state.wireless_enrichment = enrichment
