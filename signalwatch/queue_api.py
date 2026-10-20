"""Authenticated durable collection controls, sharing the existing API middleware."""

import asyncio
from typing import Literal

from fastapi import HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field

from .jobs import QueueFull


class JobRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    kind: Literal["collect", "passive_scan", "web_probe", "cve_match"]
    sources: list[str] | None = Field(default=None, max_length=100)
    company_id: str = Field(default="", max_length=300)
    primary_domain: str | None = Field(default=None, max_length=253)
    idempotency_key: str = Field(default="", max_length=200)


async def enqueue_job(jobs, kind, payload, idempotency_key=""):
    try:
        job = await asyncio.to_thread(jobs.enqueue, kind, payload, idempotency_key=idempotency_key)
    except ValueError as error:
        raise HTTPException(409, str(error)) from error
    except QueueFull as error:
        raise HTTPException(503, str(error), headers={"Retry-After": "30"}) from error
    return {"queued": job["status"] in {"queued", "retrying", "running"}, "job": job,
            "sources": payload.get("sources", [])}


def register_job_routes(app, config, engine, jobs, enabled):
    def require_queue():
        if not enabled:
            raise HTTPException(503, "Background jobs require the Redis broker and SignalWatch queue runtime")

    @app.get("/api/jobs")
    def list_jobs(limit: int = Query(30, ge=1, le=100)):
        return {"enabled": enabled, "jobs": jobs.list(limit=limit)}

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str):
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "Collection job not found")
        return job

    @app.post("/api/jobs")
    async def submit_job(request: JobRequest):
        require_queue()
        if request.kind in {"passive_scan", "web_probe"}:
            if not request.company_id or request.sources is not None:
                raise HTTPException(422, "Company jobs require company_id and do not accept sources")
            try:
                await asyncio.to_thread(engine.company_scope, request.company_id, request.primary_domain)
            except LookupError as error:
                raise HTTPException(404, str(error)) from error
            except ValueError as error:
                raise HTTPException(422, str(error)) from error
            payload = {"company_id": request.company_id}
            if request.primary_domain:
                payload["primary_domain"] = request.primary_domain
        else:
            if request.company_id or request.primary_domain:
                raise HTTPException(422, "Only company jobs accept company_id or primary_domain")
            if request.kind == "cve_match":
                if request.sources is not None:
                    raise HTTPException(422, "CVE matching always refreshes CISA KEV before reconciliation")
                payload = {}
            else:
                names = sorted(set(request.sources if request.sources is not None else engine.enabled()))
                if set(names) - set(config["sources"]):
                    raise HTTPException(400, "Unknown collector name")
                payload = {"sources": names}
        return await enqueue_job(jobs, request.kind, payload, request.idempotency_key)

    @app.post("/api/jobs/{job_id}/retry")
    async def retry_job(job_id: str):
        require_queue()
        try:
            job = await asyncio.to_thread(jobs.retry, job_id)
        except LookupError as error:
            raise HTTPException(404, str(error)) from error
        except ValueError as error:
            raise HTTPException(409, str(error)) from error
        except QueueFull as error:
            raise HTTPException(503, str(error), headers={"Retry-After": "30"}) from error
        return {"queued": True, "job": job, "sources": job["payload"].get("sources", [])}
