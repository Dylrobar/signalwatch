"""Consistent database snapshots and verified restores to clean destinations.

Configuration and secrets are deliberately not included. Raw ingress bytes live
inside the database; immutable wireless exports are copied from snapshot refs.
"""
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


def is_postgres(value):
    return str(value).startswith(("postgres://", "postgresql://"))


def _digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _file(path, root):
    return {"path": path.relative_to(root).as_posix(), "bytes": path.stat().st_size, "sha256": _digest(path)}


def _sqlite(path):
    conn = sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    conn.execute("PRAGMA query_only=ON")
    return conn


def _sqlite_check(conn):
    if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
        raise ValueError("Database integrity check failed")
    if conn.execute("PRAGMA foreign_key_check").fetchone() is not None:
        raise ValueError("Database foreign-key integrity check failed")


def _table_counts(conn, postgres=False):
    if postgres:
        names = [row[0] for row in conn.execute("SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename")]
    else:
        names = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")]
    return {name: conn.execute('SELECT count(*) FROM "' + name.replace('"', '""') + '"').fetchone()[0] for name in names}


def _archives(conn):
    return [(row[0], json.loads(row[1])) for row in conn.execute("SELECT name,state FROM sources WHERE name LIKE 'wireless-import:%'")
            if json.loads(row[1]).get("archive_path")]


def _pg_env(dsn):
    # A private environment avoids credentials in process argv and error output.
    from psycopg.conninfo import conninfo_to_dict
    mapping = {"host": "PGHOST", "hostaddr": "PGHOSTADDR", "port": "PGPORT", "dbname": "PGDATABASE",
               "user": "PGUSER", "password": "PGPASSWORD", "sslmode": "PGSSLMODE", "sslrootcert": "PGSSLROOTCERT",
               "sslcert": "PGSSLCERT", "sslkey": "PGSSLKEY", "connect_timeout": "PGCONNECT_TIMEOUT",
               "options": "PGOPTIONS", "channel_binding": "PGCHANNELBINDING", "application_name": "PGAPPNAME"}
    params = conninfo_to_dict(dsn)
    if set(params) - set(mapping):
        raise ValueError("Database URL contains unsupported backup connection options")
    env = {key: value for key, value in os.environ.items() if not key.startswith("PG")}
    env.update({mapping[key]: value for key, value in params.items()})
    env.setdefault("PGCONNECT_TIMEOUT", "10")
    return env


def _pg_command(command, dsn):
    try:
        subprocess.run(command, env=_pg_env(dsn), check=True, capture_output=True, timeout=3600)
    except FileNotFoundError:
        raise RuntimeError("PostgreSQL client tools are required for backup and restore") from None
    except (subprocess.SubprocessError, OSError):
        raise RuntimeError("PostgreSQL backup/restore command failed; destination was not accepted as complete") from None


def _require_pg_major(program, major):
    try:
        result = subprocess.run([program, "--version"], check=True, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("PostgreSQL client tools are required for backup and restore") from None
    match = re.search(r"PostgreSQL\)\s+(\d+)", result.stdout)
    if not match or int(match[1]) != major:
        raise ValueError(f"{program} major version must match the PostgreSQL {major} server; install matching client tools")


@contextmanager
def _destination(destination):
    destination = Path(destination).resolve()
    if destination.exists():
        raise ValueError("Destination must not exist; use a new empty location")
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".signalwatch-recovery-", dir=destination.parent))
    try:
        yield staging, destination
        if destination.exists():
            raise ValueError("Destination appeared during recovery; refusing to overwrite it")
        staging.rename(destination)
    finally:
        if staging.exists():
            shutil.rmtree(staging)


def create_backup(config, destination):
    from .config import VERSION, data_directory
    from .jobs import stamp
    postgres = is_postgres(config["db"])
    archive_root = data_directory(config) / "wireless-imports"
    with _destination(destination) as (root, final):
        db_path = root / ("database.dump" if postgres else "database.sqlite")
        if postgres:
            import psycopg
            try:
                with psycopg.connect(config["db"], connect_timeout=10) as conn:
                    postgres_major = conn.info.server_version // 10000
                    _require_pg_major("pg_dump", postgres_major)
                    conn.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
                    snapshot = conn.execute("SELECT pg_export_snapshot()").fetchone()[0]
                    counts, archives = _table_counts(conn, True), _archives(conn)
                    _pg_command(["pg_dump", "--format=custom", "--no-owner", "--no-acl", "--snapshot=" + snapshot,
                                 "--file=" + str(db_path)], config["db"])
            except psycopg.Error:
                raise RuntimeError("PostgreSQL backup snapshot could not be created") from None
        else:
            with _sqlite(config["db"]) as source, sqlite3.connect(db_path) as target:
                source.backup(target)
                _sqlite_check(target)
                counts, archives = _table_counts(target), _archives(target)
        db_path.chmod(0o600)
        manifest = {"format": 1, "version": VERSION, "created_at": stamp(), "backend": "postgresql" if postgres else "sqlite",
                    "database": _file(db_path, root), "tables": counts, "archives": []}
        if postgres:
            manifest["postgres_major"] = postgres_major
        for name, state in archives:
            original = Path(state["archive_path"]).resolve()
            if not original.is_relative_to(archive_root.resolve()) or not original.is_file():
                raise ValueError("A database-referenced wireless archive is missing or outside its data directory")
            before = original.stat()
            target = root / "archives" / (hashlib.sha256(name.encode()).hexdigest() + original.suffix)
            target.parent.mkdir(exist_ok=True, mode=0o700)
            shutil.copyfile(original, target)
            target.chmod(0o600)
            after = original.stat()
            if (before.st_size, before.st_mtime_ns, before.st_ino) != (after.st_size, after.st_mtime_ns, after.st_ino):
                raise ValueError("Wireless archive changed during backup; retry the snapshot")
            manifest["archives"].append({**_file(target, root), "source": name})
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        (root / "manifest.json").chmod(0o600)
    return {"backup": str(final), "backend": manifest["backend"], "tables": len(counts), "archives": len(archives)}


def validate_backup(path):
    root = Path(path).resolve()
    manifest_path = root / "manifest.json"
    if manifest_path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("Backup manifest is too large")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("format") != 1 or manifest.get("backend") not in {"sqlite", "postgresql"}:
        raise ValueError("Unsupported backup manifest")
    seen = set()
    for item in [manifest["database"], *manifest["archives"]]:
        relative = Path(item["path"])
        target = root / relative
        if relative.is_absolute() or ".." in relative.parts or target.is_symlink() or not target.resolve().is_relative_to(root):
            raise ValueError("Backup manifest contains an unsafe file path")
        if item["path"] in seen:
            raise ValueError("Backup manifest contains duplicate paths")
        seen.add(item["path"])
        if target.stat().st_size != item["bytes"] or _digest(target) != item["sha256"]:
            raise ValueError("Backup file integrity verification failed")
    if not isinstance(manifest.get("tables"), dict):
        raise ValueError("Backup manifest has no table counts")
    return manifest


def _rebind_archives(conn, archives, destination, *, postgres=False):
    placeholder = "%s" if postgres else "?"
    for item in archives:
        row = conn.execute("SELECT state FROM sources WHERE name=" + placeholder, (item["source"],)).fetchone()
        if row is None:
            raise ValueError("Archive reference is missing from the restored database")
        state = json.loads(row[0])
        state["archive_path"] = str(destination / "wireless-imports" / Path(item["path"]).name)
        conn.execute("UPDATE sources SET state=" + placeholder + " WHERE name=" + placeholder, (json.dumps(state), item["source"]))


def restore_backup(path, destination, *, database_url=None):
    root = Path(path).resolve()
    manifest = validate_backup(root)
    postgres = manifest["backend"] == "postgresql"
    if postgres and not database_url:
        raise ValueError("PostgreSQL restores require a target database URL environment variable")
    if not postgres and database_url:
        raise ValueError("Use migrate-postgres to migrate a SQLite backup to PostgreSQL")
    with _destination(destination) as (staging, final):
        for item in manifest["archives"]:
            target = staging / "wireless-imports" / Path(item["path"]).name
            target.parent.mkdir(exist_ok=True, mode=0o700)
            shutil.copyfile(root / item["path"], target)
            target.chmod(0o600)
        if postgres:
            import psycopg
            try:
                with psycopg.connect(database_url, connect_timeout=10) as conn:
                    postgres_major = conn.info.server_version // 10000
                    if manifest.get("postgres_major") != postgres_major:
                        raise ValueError("Restore target PostgreSQL major version must match the backup manifest")
                    _require_pg_major("pg_restore", postgres_major)
                    # Reject all existing application objects, not just a known
                    # table list. Never restore over an active installation.
                    if conn.execute("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'").fetchone()[0]:
                        raise ValueError("PostgreSQL restore target must have an empty public schema")
                _pg_command(["pg_restore", "--no-owner", "--no-acl", "--exit-on-error", "--single-transaction",
                             "--dbname=" + _pg_env(database_url).get("PGDATABASE", "postgres"), str(root / manifest["database"]["path"])], database_url)
                with psycopg.connect(database_url, connect_timeout=10) as conn:
                    if _table_counts(conn, True) != manifest["tables"]:
                        raise ValueError("Restored PostgreSQL table counts do not match the backup")
                    _rebind_archives(conn, manifest["archives"], final, postgres=True)
            except psycopg.Error:
                raise RuntimeError("PostgreSQL restore verification failed") from None
        else:
            target = staging / "signalwatch.db"
            shutil.copyfile(root / manifest["database"]["path"], target)
            target.chmod(0o600)
            with sqlite3.connect(target) as conn:
                _sqlite_check(conn)
                if _table_counts(conn) != manifest["tables"]:
                    raise ValueError("Restored SQLite table counts do not match the backup")
                _rebind_archives(conn, manifest["archives"], final)
                _sqlite_check(conn)
    return {"restored": str(final), "backend": manifest["backend"], "tables": len(manifest["tables"]),
            "archives": len(manifest["archives"])}


def migration_preflight(source, *, database_url=None):
    """Read-only checks; never initialize Store or create the target schema."""
    source = Path(source).resolve()
    report = {"ready": False, "source_backend": "sqlite", "source_exists": source.is_file(),
              "integrity": "unchecked", "tables": {}, "active_jobs": 0, "target": "not_configured", "blockers": [],
              "plan": ["Stop collection and uploads", "Create and verify a backup", "Copy the SQLite snapshot into an empty PostgreSQL database",
                       "Verify table counts and foreign keys", "Start one worker and verify collection before scaling"]}
    if not source.is_file():
        report["blockers"].append("SQLite source does not exist")
        return report
    try:
        with _sqlite(source) as conn:
            conn.execute("BEGIN")
            _sqlite_check(conn)
            report["integrity"] = "ok"
            report["tables"] = _table_counts(conn)
            if "collection_jobs" in report["tables"]:
                report["active_jobs"] = conn.execute("SELECT count(*) FROM collection_jobs WHERE status IN ('queued','running','retrying')").fetchone()[0]
            if report["active_jobs"]:
                report["blockers"].append("Active collection jobs must finish or be stopped before migration")
    except (sqlite3.Error, ValueError):
        report["integrity"] = "failed"
        report["blockers"].append("SQLite integrity verification failed")
    if database_url:
        try:
            import psycopg
            with psycopg.connect(database_url, connect_timeout=10) as conn:
                conn.execute("SET TRANSACTION READ ONLY")
                tables = _table_counts(conn, True)
                report["target"] = "populated" if tables else "empty"
                if tables:
                    report["blockers"].append("PostgreSQL target already contains tables; inspect migration status before proceeding")
        except Exception:
            report["target"] = "unavailable"
            report["blockers"].append("PostgreSQL target could not be checked")
    else:
        report["blockers"].append("PostgreSQL target URL is not configured")
    report["ready"] = not report["blockers"]
    return report
