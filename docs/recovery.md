# Operations, backup, and PostgreSQL migration

The authenticated Operations view uses `GET /api/operations`. A worker writes a heartbeat at startup, shutdown, and every 20 seconds while idle or collecting. After 90 seconds without a ready heartbeat, the dashboard reports a stale worker. Queue age measures the oldest queued, running, or retrying job. A running job without progress for 30 minutes warrants inspection; some large sources can legitimately take longer. Source errors, stale coverage, and local disk pressure are separate from API process liveness at `/health`.

Job history is retained for 30 days, bounded to 1,000 terminal jobs by default. Active jobs are never pruned. Each collection records stage progress under its execution lease. Company history filters compare the explicit company ID exactly. Source/target counts show attempts, including failures; inspect the saved outcome and `partial` flag before interpreting coverage.

## Backup and restore

Run these commands on the host that owns the archive disk. Keep backups outside the live data directory and copy completed backup directories to protected off-host storage.

```sh
signalwatch --config /data/config.json backup /backups/signalwatch-2026-10-20
signalwatch --config /data/config.json restore /backups/signalwatch-2026-10-20 --destination /data/rehearsal
```

`backup` uses SQLite's online snapshot API, including committed WAL data, or PostgreSQL `pg_dump` with an exported repeatable-read snapshot. Raw staging payloads are inside that database snapshot. Installed wireless archives are immutable; backup copies only archives referenced by the same database snapshot and fails if a referenced file is missing or changes during copying. New uploads can continue because an archive is installed before its database reference is written.

The private backup directory contains the database, raw archives, and a versioned SHA-256/size/table-count manifest. It excludes application configuration and does not print database connection credentials. Store the original configuration and provider secrets separately in your secret manager. Backups themselves contain private application data and should receive the same access controls as production.

Restores validate every file hash and size before writing, verify database integrity and table counts, then rewrite archive references for the new destination. The destination directory must not exist. A SQLite restore creates `signalwatch.db` and `wireless-imports/` beneath it. Point a separate test configuration at those files and run checks with automatic collection disabled before switching production. Restore does not overwrite or activate an existing installation.

For PostgreSQL, provide a newly created database with an empty `public` schema and pass the name of an environment variable containing its URL:

```sh
# Set RESTORE_DATABASE_URL securely in the process environment.
signalwatch --config /data/config.json restore /backups/signalwatch-2026-10-20 \
  --destination /data/rehearsal --database-url-env RESTORE_DATABASE_URL
```

PostgreSQL restore uses `pg_restore --single-transaction --exit-on-error`, checks table counts, and updates archive references. Keep the target database isolated until all checks finish. If verification fails after the restore transaction, discard that target database and repeat with a new one; the command will refuse to overwrite it. Backup and restore verify that client tools, source/target servers, and the backup manifest use the same PostgreSQL major version. The Docker image and CI install PostgreSQL 16 tools; use a separate tested migration process for major upgrades.

## SQLite to PostgreSQL cutover

The migration tool copies real rows, raw bytes, IDs, and scoped relationships into PostgreSQL; it verifies each source table with row counts and order-independent content checksums, repairs identity sequences, and writes an activation manifest. Keep the original SQLite file and its WAL-backed backup for rollback. Do not run two installations against separate database copies.

1. Provision an empty PostgreSQL database and set `SIGNALWATCH_DATABASE_URL` through the deployment's secret environment. Use a direct PostgreSQL connection or a session pool; transaction pooling cannot preserve the session advisory locks that fence running workers. Keep the existing archive disk mounted. Local raw archives use `data_dir` when set, otherwise the preserved SQLite database directory during migration, or the parent of `cache_dir` for PostgreSQL-only installations.
2. Run read-only checks. This command never initializes or migrates either database:

   ```sh
   signalwatch --config /data/config.json migration-preflight --source /data/data/signalwatch.db
   ```

3. Stop scheduled collection and uploads, allow active work to settle, then stop the runtime. Create and verify a backup while the configuration still selects SQLite. If the environment already selects PostgreSQL, use a separate backup configuration with that environment variable unset for the SQLite snapshot.
4. Run the migration with the actual SQLite path:

   ```sh
   signalwatch --config /data/config.json migrate-postgres --source /data/data/signalwatch.db
   ```

5. Check the committed manifest reports `verified: true`, then start one runtime with the PostgreSQL URL. The deployment can perform this copy before starting children when `SIGNALWATCH_MIGRATE_SQLITE=true`; its local `db` configuration identifies the preserved SQLite source. It must not serve requests until verification completes.
6. Verify Operations, company isolation, search, a small collection, matching, job retry/recovery, and a fresh PostgreSQL backup/restore rehearsal. Only increase concurrency after workload measurements. Keep archive-dependent processes on the same data disk until shared object storage is implemented.

If startup migration fails, fix the reported integrity/target problem before starting collection. A populated database from another source is never overwritten. Once PostgreSQL has accepted new production writes, rolling back to the old SQLite file would lose those writes; first stop writes and plan a controlled data reconciliation.

On Render, set `TMPDIR=/data` before migrating a large database so the consistent
snapshot uses the persistent disk rather than the 2 GB temporary-storage volume.
Ensure the disk has room for both the original database and its snapshot. During
runtime migration, a maintenance listener binds the configured application port
and returns HTTP 503 with `ready: false` on every route, including `/health`.
This permits port discovery without exposing application data or reporting
readiness. Keep HTTP readiness checks pointed at `/health`. A TCP-only deployment
status is not evidence that migration completed: check the verified migration
log and the application's normal HTTP 200 health response. Snapshot progress,
integrity checks, source checksums, table copies and verification are logged
without credentials or row contents. After a verified cutover, set
`SIGNALWATCH_MIGRATE_SQLITE=false` while retaining the PostgreSQL URL, so later
restarts do not snapshot and recheck the preserved SQLite database.

## Reproducible checks

Production and CI install `requirements-deploy.txt`; tests add `requirements-test.txt`. Update the pins intentionally and run the regression workflow before deployment. Backend CI runs SQLite tests, a genuine Redis/prefork integration, and PostgreSQL migration/contracts against PostgreSQL 16. The local PostgreSQL tests require `SIGNALWATCH_TEST_POSTGRES_URL`; backup roundtrips also require `pg_dump` and `pg_restore` on `PATH`. The dedicated test database role needs permission to create temporary databases. Redis integration uses `SIGNALWATCH_TEST_REDIS_SERVER=/path/to/redis-server` and temporary local data without live feeds.
