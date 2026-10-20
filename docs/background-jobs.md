# Background jobs on the existing Render service

When `CELERY_BROKER_URL` is set, SignalWatch accepts background jobs through Redis and runs them in a separate Celery worker process. The API remains available while collection, web fingerprinting, and CVE matching run. Existing collection controls use the same job system.

The deployment keeps the existing Render web service and its persistent `/data` disk. Its `signalwatch runtime` supervisor starts:

- One API process with automatic in-process collection disabled.
- One Celery worker using the **prefork** pool, concurrency **1**, and prefetch multiplier **1**.
- One Celery Beat process, enabled by default, that checks scheduled work every minute.

All processes receive the same absolute `SIGNALWATCH_CONFIG=/data/config.json`. Relative database/cache paths in that configuration resolve against the same directory. The runtime rejects a different or relative `SIGNALWATCH_CONFIG`, prevents a second runtime from using the same configuration, and forces `WEB_CONCURRENCY=1`.

This shares CPU and memory on the current instance, but keeps request handling outside collection tasks. SQLite remains the local source of truth. A separate Render worker service would have a different filesystem and must **not** be pointed at another copy of this SQLite database. Multiple web instances, multiple workers, and higher worker concurrency are not supported by this deployment. Moving workers to separate services requires a shared database/storage design first.

## Render configuration

The repository's `render.yaml` describes the existing `signalwatch` Docker web service and a **free**, internal-only Key Value instance named `signalwatch-queue` in the same region. Its `noeviction` policy prevents Redis from discarding queued messages to make room; a full broker instead rejects publishing. Accepted jobs stay in the SQLite outbox and retry dispatch after the broker recovers.

Bind or update the **existing** web service and retain its current instance plan, existing disk identity, 50 GB allocation, `/data` mount, API token, CORS origins, and provider credentials. Do not apply the file as a new independent web deployment. The blueprint omits the web plan to avoid requesting a resize; when importing an existing service into a blueprint, review Render's plan/disk diff before applying it. Only the broker is a new resource, and it uses `plan: free`.

Set these environment variables on the existing service:

| Variable | Value |
| --- | --- |
| `CELERY_BROKER_URL` | The broker's internal connection string; keep it server-side. |
| `SIGNALWATCH_CONFIG` | `/data/config.json` |
| `SIGNALWATCH_CELERY_BEAT` | `true` for this one deployment; `false` disables automatic scheduling. |
| `WEB_CONCURRENCY` | `1` |

The Docker image installs `.[queue]` and uses `signalwatch --config /data/config.json runtime --host 0.0.0.0`. Without a broker URL, this command replaces itself with the existing `serve` process and normal local scheduling. `signalwatch serve` remains available for local use. To run the supervised setup outside Docker:

```sh
pip install '.[queue]'
export SIGNALWATCH_CONFIG=/absolute/path/to/config.json
# Set CELERY_BROKER_URL in the process environment or a secret manager.
signalwatch --config "$SIGNALWATCH_CONFIG" runtime --host 127.0.0.1
```

Do not start another Beat instance alongside the supervised one. Use `runtime --no-collect` or `SIGNALWATCH_CELERY_BEAT=false` for a deployment that should accept only manually submitted jobs.

Free Render Key Value is an initial queue deployment, not a durable or highly available broker. Broker restarts or a full allocation can interrupt dispatch; monitor job state and retry failed jobs after restoring the broker. Acknowledged database writes stay on `/data`. Do not assume an HTTP acceptance receipt proves that a job has completed.

## Job API

All job routes use the existing API authentication:

- `POST /api/jobs` accepts `kind` (`passive_scan`, `web_probe`, `cve_match`, or `collect`), with `company_id`, `primary_domain`, `sources`, and `idempotency_key` where applicable.
- `GET /api/jobs?limit=30` lists recent jobs.
- `GET /api/jobs/{id}` returns an individual job's state and outcome.
- `POST /api/jobs/{id}/retry` retries a failed job.
- Existing `POST /api/collect` submissions return a job receipt when queue mode is enabled.

Use the same idempotency key when checking a submission whose response was lost; follow the returned job until it finishes. Inspect failure details before requesting a retry. The broker URL and provider credentials never belong in a browser request.

## Shutdown and recovery

If the API, worker, or Beat unexpectedly exits, the supervisor stops its siblings and exits nonzero so Render can restart the complete unit. On `SIGTERM` or `SIGINT`, it asks process leaders to shut down, allows up to 20 seconds for graceful exit, and then kills remaining process groups. An in-progress job may therefore be interrupted during deployment; consult its recorded state and recovery/retry behavior after restart.

The worker uses one process to limit simultaneous SQLite writers; existing database admission, collection locks, and idempotency checks still apply. The job layer does not promise exactly-once execution across process or broker failures. Retain the existing `/data` disk during rollouts and backups.
