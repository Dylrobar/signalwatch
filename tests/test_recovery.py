import hashlib
import json
import os
import shutil
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from signalwatch.config import load_config
from signalwatch.jobs import Jobs
from signalwatch.recovery import create_backup, migration_preflight, restore_backup, validate_backup
from signalwatch.staging import StagingQueue
from signalwatch.store import Store


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        config = self.root / "config.json"
        config.write_text(json.dumps({"db": "data/live.db", "api_token": "do-not-back-up-config"}))
        self.config = load_config(config)
        self.store = Store(self.config["db"])
        self.jobs = Jobs(self.store)

    def test_restore_preserves_wal_data_raw_payloads_and_rebinds_archives(self):
        raw = b'{"url":"https://example.test","unchanged":"payload"}'
        StagingQueue(self.store).enqueue(raw, source="test", adapter="auto")
        archive = Path(self.config["db"]).parent / "wireless-imports" / "upload.csv"
        archive.parent.mkdir()
        archive.write_bytes(b"immutable wireless export")
        self.store.update_source("wireless-import:test", archive_path=str(archive), status="complete")
        self.jobs.enqueue("web_probe", {"company_id": "company:example"})
        backup = self.root / "snapshot"
        create_backup(self.config, backup)
        manifest = validate_backup(backup)
        self.assertEqual(manifest["tables"]["raw_ingress"], 1)
        self.assertNotIn("do-not-back-up-config", (backup / "manifest.json").read_text())
        destination = self.root / "restored"
        restore_backup(backup, destination)
        with sqlite3.connect(destination / "signalwatch.db") as conn:
            self.assertEqual(conn.execute("SELECT payload FROM raw_ingress").fetchone()[0], raw)
            state = json.loads(conn.execute("SELECT state FROM sources WHERE name='wireless-import:test'").fetchone()[0])
            self.assertEqual(Path(state["archive_path"]).read_bytes(), archive.read_bytes())
            self.assertTrue(Path(state["archive_path"]).is_relative_to(destination))
            self.assertEqual(conn.execute("PRAGMA integrity_check").fetchone()[0], "ok")
        with self.assertRaises(ValueError):
            restore_backup(backup, destination)

    def test_corruption_missing_archives_and_traversal_fail_closed(self):
        backup = self.root / "snapshot"
        create_backup(self.config, backup)
        manifest = json.loads((backup / "manifest.json").read_text())
        database = backup / manifest["database"]["path"]
        with database.open("ab") as file:
            file.write(b"corruption")
        with self.assertRaisesRegex(ValueError, "integrity"):
            restore_backup(backup, self.root / "corrupt-restore")
        self.assertFalse((self.root / "corrupt-restore").exists())
        manifest["database"]["path"] = "../config.json"
        (backup / "manifest.json").write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            validate_backup(backup)
        self.store.update_source("wireless-import:missing", archive_path=str(self.root / "missing.csv"))
        with self.assertRaisesRegex(ValueError, "archive"):
            create_backup(self.config, self.root / "missing-backup")
        self.assertFalse((self.root / "missing-backup").exists())

    def test_preflight_reads_without_creating_or_migrating_databases(self):
        missing = self.root / "missing.db"
        self.assertFalse(migration_preflight(missing)["ready"])
        self.assertFalse(missing.exists())
        original = self.root / "old.db"
        with sqlite3.connect(original) as conn:
            conn.execute("CREATE TABLE legacy(value TEXT)")
            conn.execute("INSERT INTO legacy VALUES('preserved')")
        before = hashlib.sha256(original.read_bytes()).digest()
        report = migration_preflight(original)
        self.assertEqual(report["tables"], {"legacy": 1})
        self.assertEqual(report["integrity"], "ok")
        self.assertEqual(hashlib.sha256(original.read_bytes()).digest(), before)


@unittest.skipUnless(os.environ.get("SIGNALWATCH_TEST_POSTGRES_URL") and shutil.which("pg_dump") and shutil.which("pg_restore"),
                     "Set SIGNALWATCH_TEST_POSTGRES_URL and install PostgreSQL client tools")
class PostgresRecoveryTests(unittest.TestCase):
    def test_exported_snapshot_roundtrip_to_empty_database(self):
        import psycopg
        from psycopg import sql
        base = os.environ["SIGNALWATCH_TEST_POSTGRES_URL"]
        names = ["sw_recovery_" + uuid.uuid4().hex for _ in range(2)]
        def drop():
            with psycopg.connect(base, autocommit=True) as admin:
                for name in names:
                    admin.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name)))
        self.addCleanup(drop)
        with psycopg.connect(base, autocommit=True) as admin:
            for name in names:
                admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        # Recovery accepts URI config just as production load_config supplies it.
        from urllib.parse import urlsplit, urlunsplit
        parts = urlsplit(base)
        urls = [urlunsplit((parts.scheme, parts.netloc, "/" + name, parts.query, "")) for name in names]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = {"db": urls[0], "cache_dir": str(root / "cache")}
            store = Store(config["db"])
            jobs = Jobs(store)
            job = jobs.enqueue("web_probe", {"company_id": "company:isolated"})
            lease = jobs.claim(job["id"])["lease_token"]
            jobs.record_progress(job["id"], "collecting", completed=1, total=2, lease_token=lease)
            StagingQueue(store).enqueue(b"PostgreSQL raw payload", source="fixture")
            archive = root / "wireless-imports" / "input.csv"
            archive.parent.mkdir()
            archive.write_bytes(b"raw archive")
            store.update_source("wireless-import:pg", archive_path=str(archive), status="complete")
            backup = root / "backup"
            create_backup(config, backup)
            restored = root / "restored"
            restore_backup(backup, restored, database_url=urls[1])
            with psycopg.connect(urls[1]) as conn:
                self.assertEqual(bytes(conn.execute("SELECT payload FROM raw_ingress").fetchone()[0]), b"PostgreSQL raw payload")
                self.assertEqual(conn.execute("SELECT completed FROM collection_job_progress").fetchone()[0], 1)
                state = json.loads(conn.execute("SELECT state FROM sources WHERE name='wireless-import:pg'").fetchone()[0])
                self.assertEqual(Path(state["archive_path"]).read_bytes(), b"raw archive")
            with self.assertRaisesRegex(ValueError, "empty public schema"):
                restore_backup(backup, root / "refused", database_url=urls[1])
            self.assertFalse((root / "refused").exists())

