# Background jobs on the existing Render service

When `CELERY_BROKER_URL` is set, SignalWatch accepts background jobs through Redis and runs them in a separate Celery worker process. The API remains available while collection, web fingerprinting, and CVE matching run. Existing collection controls use the same job system.

The deployment keeps the existing Render web service and its persistent `/data` disk. Its `signalwatch runtime` supervisor starts:

- One API process with automatic in-process collection disabled.
- One Celery worker using the **prefork** pool, concurrency **1**, and prefetch multiplier **1**.
- One Celery Beat process, enabled by default, that checks scheduled work every minute.

All processes receive the same absolute `SIGNALWATCH_CONFIG=/data/config.json`. Relative database/cache paths in that configuration resolve against the same directory. The runtime rejects a different or relative `SIGNALWATCH_CONFIG`, prevents a second runtime from using the same configuration, and forces `WEB_CONCURRENCY=1`.

This shares CPU and memory on the current instance, but keeps request handling outside collection tasks. The configured database owns accepted jobs and progress. Local installations can keep SQLite; `SIGNALWATCH_DATABASE_URL` selects PostgreSQL after a verified migration. PostgreSQL uses session advisory locks across processes and hosts; SQLite uses local file locks. Keep one worker at concurrency 1 during this rollout. Wireless source archives still live on the `/data` disk, so do not split API and archive-dependent work across hosts until that storage is shared. See [recovery and migration](recovery.md).

## Render configuration

The repository's `render.yaml` describes the existing `signalwatch` Docker web service and a **free**, internal-only Key Value instance named `signalwatch-queue` in the same region. Its `noeviction` policy prevents Redis from discarding queued messages to make room; a full broker instead rejects publishing. Accepted jobs stay in the database outbox and retry dispatch after the broker recovers.

Bind or update the **existing** web service and retain its current instance plan, existing disk identity, 50 GB allocation, `/data` mount, API token, CORS origins, and provider credentials. Do not apply the file as a new independent web deployment. The blueprint omits the web plan to avoid requesting a resize; when importing an existing service into a blueprint, review Render's plan/disk diff before applying it. The broker uses `plan: free`. PostgreSQL provisioning and its connection URL are managed separately; see the migration runbook before activating it.

Set these environment variables on the existing service:

| Variable | Value |
| --- | --- |
| `CELERY_BROKER_URL` | The broker's internal connection string; keep it server-side. |
| `SIGNALWATCH_CONFIG` | `/data/config.json` |
| `SIGNALWATCH_CELERY_BEAT` | `true` for this one deployment; `false` disables automatic scheduling. |
| `WEB_CONCURRENCY` | `1` |

The Docker image installs pinned queue/PostgreSQL dependencies from `requirements-deploy.txt` and includes PostgreSQL backup tools and uses `signalwatch --config /data/config.json runtime --host 0.0.0.0`. Without a broker URL, this command replaces itself with the existing `serve` process and normal local scheduling. `signalwatch serve` remains available for local use. To run the supervised setup outside Docker:

```sh
pip install -r requirements-deploy.txt
pip install --no-deps .
export SIGNALWATCH_CONFIG=/absolute/path/to/config.json
# Set CELERY_BROKER_URL in the process environment or a secret manager.
signalwatch --config "$SIGNALWATCH_CONFIG" runtime --host 127.0.0.1
```

Do not start another Beat instance alongside the supervised one. Use `runtime --no-collect` or `SIGNALWATCH_CELERY_BEAT=false` for a deployment that should accept only manually submitted jobs.

Free Render Key Value is an initial queue deployment, not a durable or highly available broker. Broker restarts or a full allocation can interrupt dispatch; monitor job state and retry failed jobs after restoring the broker. Acknowledged database writes stay on `/data`. Do not assume an HTTP acceptance receipt proves that a job has completed.

## Job API

All job routes use the existing API authentication:

- `POST /api/jobs` accepts `kind` (`passive_scan`, `web_probe`, `cve_match`, or `collect`), with `company_id`, `primary_domain`, `sources`, and `idempotency_key` where applicable.
- `GET /api/jobs?limit=30&offset=0&company_id=...&status=failed&kind=web_probe` filters and pages recent jobs; all filters are optional.
- `GET /api/jobs/{id}` returns an individual job's state and outcome.
- `POST /api/jobs/{id}/retry` retries a failed job.
- Existing `POST /api/collect` submissions return a job receipt when queue mode is enabled.

Job responses include `progress` with `stage`, `completed`, nullable `total`, `unit`, `message`, `updated_at`, and `partial`. Counters describe attempted work in the current stage, not proof that every source succeeded. A failed run with some saved results remains failed with `progress.partial=true`; `available_at` tells when a retry is eligible. Progress writes require the current execution lease, so a stopped worker cannot overwrite a replacement attempt.

`GET /api/operations` reports worker heartbeats, queued/running/retrying counts, oldest active job age, stalled progress, database size, local free space, and stale/error source coverage. It uses API authentication. `/health` remains public liveness and does not fail merely because an external feed is down.

Use the same idempotency key when checking a submission whose response was lost; follow the returned job until it finishes. Inspect failure details before requesting a retry. The broker URL and provider credentials never belong in a browser request.

## Shutdown and recovery

If the API, worker, or Beat unexpectedly exits, the supervisor stops its siblings and exits nonzero so Render can restart the complete unit. On `SIGTERM` or `SIGINT`, it asks process leaders to shut down, allows up to 20 seconds for graceful exit, and then kills remaining process groups. An in-progress job may therefore be interrupted during deployment; consult its recorded state and recovery/retry behavior after restart.

The worker uses one process until the PostgreSQL rollout is validated; existing database admission, collection locks, and idempotency checks still apply. The job layer does not promise exactly-once execution across process or broker failures. Retain the existing `/data` disk during rollouts and backups.
