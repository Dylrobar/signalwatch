"""ID-only Celery tasks with fresh configuration and asyncio clients per job."""

import asyncio
import os
import socket
import time
import logging
from datetime import datetime, timezone

from .celery_app import EXECUTE_TASK, SCHEDULE_TASK, app
from .config import load_config
from .engine import Engine, source_outcome
from .http import public_error
from .jobs import Jobs
from .operations import heartbeat
from .store import Store

MAX_RECOVERY_ATTEMPTS = 3


def _context():
    config = load_config(os.environ.get("SIGNALWATCH_CONFIG") or "config.json")
    store = Store(config["db"])
    return config, store, Jobs(store)


async def _execute(config, store, job):
    # Engine entry normally seeds the global crawl queue. Company-scoped work
    # must not enqueue unrelated configured websites before run_company scopes it.
    run_config = {**config, "seed_urls": []} if job["kind"] in {"passive_scan", "web_probe"} else config
    async with Engine(run_config, store) as engine:
        jobs = Jobs(store)
        engine.progress_callback = lambda stage, **fields: jobs.record_progress(
            job["id"], stage, lease_token=job["lease_token"], **fields)
        await asyncio.to_thread(engine.progress_callback, "preparing")
        payload = job["payload"]
        if job["kind"] == "collect":
            return await engine.run(payload.get("sources"), scheduled=bool(payload.get("scheduled", False)))
        if job["kind"] in {"passive_scan", "web_probe"}:
            return await engine.run_company(job["kind"], payload["company_id"], payload.get("primary_domain"))
        if job["kind"] == "cve_match":
            return await engine.run(["kev"])
        raise ValueError("Unknown queued job kind")


def _outcome(result):
    if not isinstance(result, dict):
        return "failed", "Collection did not return a result"
    if result.get("error"):
        return "failed", str(result["error"])[:2000]
    if not isinstance(result.get("sources", []), list):
        return "failed", "Collection returned invalid source outcomes"
    failures = []
    for row in result.get("sources", []):
        if not isinstance(row, dict):
            failures.append("Source did not return a valid result")
            continue
        source = str(row.get("source") or "Source")
        if row.get("ok") is not True:
            failures.append(source + ": " + str(row.get("error") or "Collection did not complete successfully"))
        elif isinstance(row.get("counts"), dict):
            status, errors, succeeded = source_outcome(row["counts"])
            if status != "ok" or not succeeded:
                failures.append(source + ": " + ("; ".join(errors) or "Collection returned incomplete coverage"))
    return ("failed", "; ".join(failures)[:2000]) if failures else ("succeeded", "")


@app.task(name=EXECUTE_TASK, ignore_result=True, acks_late=True, reject_on_worker_lost=True)
def execute_job(job_id):
    """Only IDs cross the broker; the database and a lock fence redeliveries."""
    if not isinstance(job_id, str) or not job_id or len(job_id) > 128:
        raise ValueError("Invalid job identifier")
    config, store, jobs = _context()
    jobs.recover()
    with jobs.worker_lock(job_id) as acquired:
        if not acquired:
            return {"job_id": job_id, "status": "already_running"}
        job = jobs.claim(job_id)
        if job is None:
            return {"job_id": job_id, "status": "not_available"}
        lease = job["lease_token"]
        if job["attempts"] > MAX_RECOVERY_ATTEMPTS:
            jobs.finish(job_id, "failed", error="Job stopped after repeated worker interruptions",
                        lease_token=lease)
            return {"job_id": job_id, "status": "failed"}
        try:
            result = asyncio.run(_execute(config, store, job))
        except Exception as error:
            jobs.finish(job_id, "failed", error=public_error(error), lease_token=lease)
            return {"job_id": job_id, "status": "failed"}
        if isinstance(result, dict) and result.get("busy"):
            jobs.defer(job_id, error="Another collection is running; this job will retry", delay=30,
                       attempted=False, lease_token=lease)
            return {"job_id": job_id, "status": "retrying"}
        status, error = _outcome(result)
        try:
            jobs.finish(job_id, status, result=result, error=error, lease_token=lease)
        except ValueError:
            # Do not repeat completed network work merely because its diagnostic
            # result cannot fit the bounded JSON ledger column.
            status = "failed"
            jobs.finish(job_id, status, error="Collection finished, but its result could not be recorded",
                        lease_token=lease)
        return {"job_id": job_id, "status": status}


# Celery emits heartbeat_sent from its parent process, including while idle or
# while a child waits on a slow source. Limit database writes to once per 20s.
_heartbeat_state = {"pid": None, "last": 0, "store": None}


def _worker_heartbeat(sender=None, *, stopped=False, force=False, **kwargs):
    clock = time.monotonic()
    state = _heartbeat_state
    if not force and state["pid"] == os.getpid() and clock - state["last"] < 20:
        return
    try:
        if state["pid"] != os.getpid() or state["store"] is None:
            _, state["store"], _ = _context()
            state["pid"] = os.getpid()
        heartbeat(state["store"], socket.gethostname() + ":" + str(os.getpid()), status="stopped" if stopped else "ready")
        state["last"] = clock
    except Exception:
        # Credentials and source URLs must not enter Celery logs on DB failure.
        logging.getLogger("signalwatch").warning("Worker heartbeat could not be saved")


from celery.signals import heartbeat_sent, worker_ready, worker_shutdown
heartbeat_sent.connect(_worker_heartbeat, weak=False)
worker_ready.connect(lambda **kwargs: _worker_heartbeat(force=True, **kwargs), weak=False)
worker_shutdown.connect(lambda **kwargs: _worker_heartbeat(stopped=True, force=True, **kwargs), weak=False)


async def _due(config, store):
    # No HTTP clients are opened merely to decide whether scheduled work is due.
    engine = Engine(config, store)
    return (await engine._due(engine.enabled(), persist=False))[0]


@app.task(name=SCHEDULE_TASK, ignore_result=True)
def enqueue_scheduled():
    config, store, jobs = _context()
    if not os.environ.get("CELERY_BROKER_URL", "").strip():
        return {"queued": False}
    if not asyncio.run(_due(config, store)):
        return {"queued": False}
    # A minute key absorbs duplicate Beat ticks, while active request dedup keeps
    # a slow collection from generating a backlog of identical scheduled jobs.
    key = "scheduled:" + datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M")
    job = jobs.enqueue("collect", {"sources": None, "scheduled": True},
                       idempotency_key=key, deduplicate_active=True)
    return {"queued": True, "job_id": job["id"]}
