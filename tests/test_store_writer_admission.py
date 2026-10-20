import sqlite3
import multiprocessing
import subprocess
import sys
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from pathlib import Path
from unittest.mock import Mock, patch

from signalwatch.store import Store


def _forked_write(store, connection):
    store.update_source("child", status="done")
    connection.send("done")
    connection.close()


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

    def test_store_instances_share_reentrant_writer_admission_for_same_path(self):
        other = Store(Path(self.temp.name) / "." / "state.db")
        self.assertIs(self.store._writer_lock, other._writer_lock)
        with self.store._writer_lock, other._writer_lock:
            self.store.update_source("nested-admission", status="done")
        self.assertEqual(other.source_state("nested-admission")["status"], "done")

    def test_other_process_waits_before_sqlite_and_readers_stay_available(self):
        self.store.update_source("first", status="committed")
        marker = Path(self.temp.name) / "child-opened-sqlite"
        script = '''import sqlite3, sys
from pathlib import Path
from signalwatch.store import Store
store = Store(sys.argv[1])
connect = sqlite3.connect
def track(*args, **kwargs):
    Path(sys.argv[2]).touch()
    return connect(*args, **kwargs)
sqlite3.connect = track
print("ready", flush=True)
sys.stdin.readline()
store.update_source("child", status="done")
'''
        child = subprocess.Popen([sys.executable, "-c", script, self.store.path, str(marker)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(lambda: child.poll() is None and child.kill())
        self.assertEqual(child.stdout.readline().strip(), "ready")
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE sources SET state=? WHERE name='first'", ('{"status":"uncommitted"}',))
            child.stdin.write("go\n")
            child.stdin.flush()
            with self.assertRaises(subprocess.TimeoutExpired):
                child.wait(timeout=0.15)
            self.assertFalse(marker.exists(), "Cross-process writers must wait before consuming SQLite's timeout")
            self.assertEqual(self.store.source_state("first")["status"], "committed")
        _, error = child.communicate(timeout=3)
        self.assertEqual(child.returncode, 0, error)
        self.assertEqual(self.store.source_state("child")["status"], "done")

    def test_forked_store_does_not_inherit_parent_admission_ownership(self):
        context = multiprocessing.get_context("fork")
        parent, child = context.Pipe(duplex=False)
        process = context.Process(target=_forked_write, args=(self.store, child))
        with self.store._writer_lock:
            process.start()
            self.assertFalse(parent.poll(0.15), "Child must wait for the parent's file lock")
        process.join(timeout=3)
        if process.is_alive():
            process.kill()
            process.join()
            self.fail("Forked writer did not resume")
        self.assertEqual(process.exitcode, 0)
        self.assertEqual(parent.recv(), "done")
        parent.close()
        child.close()
        self.assertEqual(self.store.source_state("child")["status"], "done")
