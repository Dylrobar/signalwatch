import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from unittest.mock import Mock, patch

from signalwatch.store import Store


class StoreWriterAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "state.db")

    def test_local_writer_waits_before_sqlite_while_wal_readers_continue(self):
        self.store.update_source("first", status="committed")
        started = threading.Event()
        opened = threading.Event()
        connect = sqlite3.connect

        def track_connection(*args, **kwargs):
            if threading.current_thread().name.startswith("pending-writer"):
                opened.set()
            return connect(*args, **kwargs)

        def write():
            started.set()
            self.store.update_source("second", status="done")

        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="pending-writer") as writers:
            with patch("signalwatch.store.sqlite3.connect", side_effect=track_connection):
                with self.store.connection(write=True) as conn:
                    conn.execute("UPDATE sources SET state=? WHERE name='first'", ('{"status":"uncommitted"}',))
                    pending = writers.submit(write)
                    self.assertTrue(started.wait(1))
                    with self.assertRaises(TimeoutError):
                        pending.result(timeout=0.1)
                    self.assertFalse(opened.is_set(), "A queued writer must not consume SQLite's busy timeout")
                    # WAL readers still see the last committed snapshot immediately.
                    self.assertEqual(self.store.source_state("first")["status"], "committed")
                pending.result(timeout=2)
        self.assertTrue(opened.is_set())
        self.assertEqual(self.store.source_state("first")["status"], "uncommitted")
        self.assertEqual(self.store.source_state("second")["status"], "done")

    def assert_next_writer_runs(self):
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(self.store.update_source, "next", status="done").result(timeout=2)
        self.assertEqual(self.store.source_state("next")["status"], "done")

    def test_rollback_releases_writer_and_does_not_publish_partial_changes(self):
        with self.assertRaisesRegex(RuntimeError, "abort"):
            with self.store.connection(write=True) as conn:
                conn.execute("INSERT INTO sources(name,state) VALUES('partial','{}')")
                raise RuntimeError("abort")
        with self.store.connection() as conn:
            self.assertIsNone(conn.execute("SELECT name FROM sources WHERE name='partial'").fetchone())
        self.assert_next_writer_runs()

    def test_connection_and_setup_failures_release_writer(self):
        with patch("signalwatch.store.sqlite3.connect", side_effect=sqlite3.OperationalError("cannot open")):
            with self.assertRaises(sqlite3.OperationalError):
                with self.store.connection(write=True):
                    self.fail("Failed connection must not enter body")
        self.assert_next_writer_runs()
        connection = Mock()
        connection.execute.side_effect = sqlite3.OperationalError("setup failed")
        with patch("signalwatch.store.sqlite3.connect", return_value=connection):
            with self.assertRaises(sqlite3.OperationalError):
                with self.store.connection(write=True):
                    self.fail("Failed setup must not enter body")
        connection.close.assert_called_once()
        self.assert_next_writer_runs()

    def test_commit_failure_rolls_back_closes_and_releases_writer(self):
        connection = Mock()
        connection.commit.side_effect = sqlite3.OperationalError("commit failed")
        with patch("signalwatch.store.sqlite3.connect", return_value=connection):
            with self.assertRaises(sqlite3.OperationalError):
                with self.store.connection(write=True):
                    pass
        connection.rollback.assert_called_once()
        connection.close.assert_called_once()
        self.assert_next_writer_runs()
