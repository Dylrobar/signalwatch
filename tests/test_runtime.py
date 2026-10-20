import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.cli import parser
from signalwatch.runtime import _runtime_lock, run


class RuntimeConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "config.json"

    def test_existing_serve_command_is_unchanged_and_runtime_is_explicit(self):
        self.assertEqual(parser().parse_args(["serve"]).command, "serve")
        args = parser().parse_args(["--config", str(self.path), "runtime", "--no-collect", "--port", "9999"])
        self.assertEqual((args.command, args.no_collect, args.port), ("runtime", True, 9999))

    def test_no_broker_executes_normal_serve_with_the_same_absolute_config(self):
        with patch.dict(os.environ, {}, clear=True), patch("signalwatch.runtime.os.execvpe") as execute:
            self.assertEqual(run(self.path, host="127.0.0.1", port=9999), 0)
        interpreter, command, env = execute.call_args.args
        self.assertEqual(interpreter, sys.executable)
        self.assertEqual(command, [sys.executable, "-m", "signalwatch", "--config", str(self.path), "serve", "--host", "127.0.0.1", "--port", "9999"])
        self.assertEqual(env["SIGNALWATCH_CONFIG"], str(self.path))
        self.assertNotIn("--no-collect", command)

    def test_queue_runtime_shares_config_and_uses_one_prefork_worker_and_one_beat(self):
        with patch.dict(os.environ, {"CELERY_BROKER_URL": "redis://localhost/0", "WEB_CONCURRENCY": "5"}, clear=True), \
                patch("signalwatch.runtime.supervise", return_value=0) as supervise:
            self.assertEqual(run(self.path), 0)
        commands, env = supervise.call_args.args
        self.assertEqual([name for name, _ in commands], ["api", "worker", "beat"])
        self.assertEqual(env["SIGNALWATCH_CONFIG"], str(self.path))
        self.assertEqual(env["WEB_CONCURRENCY"], "1")
        self.assertNotIn("--no-collect", dict(commands)["api"])
        for option in ("--pool=prefork", "--concurrency=1", "--prefetch-multiplier=1"):
            self.assertIn(option, dict(commands)["worker"])
        beat = dict(commands)["beat"]
        self.assertEqual(beat[beat.index("--schedule") + 1], str(self.path.parent / "celerybeat-schedule"))

    def test_beat_can_be_disabled_without_disabling_the_worker(self):
        for no_collect, value in ((True, "true"), (False, "false")):
            with self.subTest(no_collect=no_collect, value=value), \
                    patch.dict(os.environ, {"CELERY_BROKER_URL": "redis://localhost/0", "SIGNALWATCH_CELERY_BEAT": value}, clear=True), \
                    patch("signalwatch.runtime.supervise", return_value=0) as supervise:
                run(self.path, no_collect=no_collect)
                self.assertEqual([name for name, _ in supervise.call_args.args[0]], ["api", "worker"])
                self.assertEqual("--no-collect" in dict(supervise.call_args.args[0])["api"], no_collect)

    def test_mismatched_or_relative_environment_config_fails_before_children_start(self):
        for configured in ("config.json", str(self.path.parent / "other.json")):
            with self.subTest(configured=configured), patch.dict(os.environ, {"SIGNALWATCH_CONFIG": configured}, clear=True), \
                    patch("signalwatch.runtime.supervise") as supervise, self.assertRaises(ValueError):
                run(self.path)
            supervise.assert_not_called()

    def test_duplicate_runtime_lock_is_rejected_and_released(self):
        with _runtime_lock(self.path):
            with self.assertRaisesRegex(RuntimeError, "already using"):
                with _runtime_lock(self.path):
                    self.fail("Duplicate runtime acquired the lock")
        with _runtime_lock(self.path):
            pass

    def test_invalid_beat_setting_is_not_silently_enabled(self):
        with patch.dict(os.environ, {"CELERY_BROKER_URL": "redis://localhost/0", "SIGNALWATCH_CELERY_BEAT": "maybe"}, clear=True), \
                self.assertRaisesRegex(ValueError, "true or false"):
            run(self.path)

    def test_invalid_broker_cannot_fall_back_to_localhost_or_leak_credentials(self):
        for broker in ("redis:///0", "amqp://localhost", "redis://:SECRET@queue.example:invalid/0"):
            with self.subTest(broker=broker), patch.dict(os.environ, {"CELERY_BROKER_URL": broker}, clear=True), \
                    patch("signalwatch.runtime.supervise") as supervise, self.assertRaises(ValueError) as error:
                run(self.path)
            self.assertNotIn("SECRET", str(error.exception))
            supervise.assert_not_called()

    def test_broker_whitespace_is_normalized_for_every_child(self):
        with patch.dict(os.environ, {"CELERY_BROKER_URL": "  rediss://queue.example:6379/0  "}, clear=True), \
                patch("signalwatch.runtime.supervise", return_value=0) as supervise:
            run(self.path)
        self.assertEqual(supervise.call_args.args[1]["CELERY_BROKER_URL"], "rediss://queue.example:6379/0")

    def test_postgres_activation_waits_for_verified_migration(self):
        env = {'CELERY_BROKER_URL': 'redis://localhost/0', 'SIGNALWATCH_DATABASE_URL': 'postgresql://localhost/target',
               'SIGNALWATCH_MIGRATE_SQLITE': 'true'}
        manifest = {'total_rows': 12, 'tables': {'entities': {}}, 'already_migrated': False, 'verified': True}
        with patch.dict(os.environ, env, clear=True), patch('signalwatch.postgres_migrate.migrate_sqlite', return_value=manifest) as migrate, \
                patch('signalwatch.runtime.supervise', return_value=0) as supervise:
            run(self.path)
            self.assertEqual(migrate.call_args.args[1], env['SIGNALWATCH_DATABASE_URL'])
            self.assertTrue(migrate.call_args.args[0].startswith(self.temp.name))
            supervise.assert_called_once()
        with patch.dict(os.environ, env, clear=True), patch('signalwatch.postgres_migrate.migrate_sqlite', side_effect=RuntimeError('verification failed')), \
                patch('signalwatch.runtime.supervise') as supervise, self.assertRaisesRegex(RuntimeError, 'verification failed'):
            run(self.path)
        supervise.assert_not_called()

    def test_migration_flag_cannot_create_an_empty_database_without_a_source(self):
        with patch.dict(os.environ, {'SIGNALWATCH_MIGRATE_SQLITE': 'true'}, clear=True), \
                patch('signalwatch.runtime.os.execvpe') as execute, self.assertRaisesRegex(ValueError, 'original SQLite'):
            run(self.path)
        execute.assert_not_called()
        with patch.dict(os.environ, {'SIGNALWATCH_MIGRATE_SQLITE': 'typo'}, clear=True), \
                patch('signalwatch.runtime.os.execvpe') as execute, self.assertRaisesRegex(ValueError, 'true or false'):
            run(self.path)
        execute.assert_not_called()


class RuntimeProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def spawn(self, commands):
        code = "from signalwatch.runtime import supervise; import os; raise SystemExit(supervise(" + repr(commands) + ", dict(os.environ), shutdown_timeout=0.2))"
        process = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.cleanup_processes, process)
        return process

    def cleanup_processes(self, process):
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)
        for path in self.root.glob("*.pid"):
            try:
                os.killpg(int(path.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass

    def child(self, name, *, stubborn=False):
        path = self.root / f"{name}.pid"
        code = "import os,signal,time; from pathlib import Path; "
        if stubborn:
            code += "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        code += f"Path({str(path)!r}).write_text(str(os.getpid())); time.sleep(60)"
        return name, [sys.executable, "-c", code]

    def wait_ready(self, names, process):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if all((self.root / f"{name}.pid").exists() for name in names):
                return
            if process.poll() is not None:
                self.fail(process.communicate()[1].decode())
            time.sleep(0.02)
        self.fail("Supervisor children did not start")

    def assert_children_gone(self):
        for path in self.root.glob("*.pid"):
            with self.assertRaises(ProcessLookupError):
                os.kill(int(path.read_text()), 0)

    def test_sigterm_stops_and_reaps_all_children(self):
        process = self.spawn([self.child("api"), self.child("worker")])
        self.wait_ready(["api", "worker"], process)
        process.send_signal(signal.SIGTERM)
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0)
        self.assert_children_gone()

    def test_child_failure_fails_fast_and_kills_a_stubborn_sibling(self):
        path = self.root / "worker.pid"
        failing = "import time; from pathlib import Path\nwhile not Path(" + repr(str(path)) + ").exists(): time.sleep(0.01)\nraise SystemExit(7)"
        process = self.spawn([self.child("worker", stubborn=True), ("api", [sys.executable, "-c", failing])])
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 7)
        self.assert_children_gone()

    def test_unexpected_clean_exit_is_still_a_failure(self):
        process = self.spawn([("api", [sys.executable, "-c", "pass"])])
        process.communicate(timeout=5)
        self.assertEqual(process.returncode, 1)
