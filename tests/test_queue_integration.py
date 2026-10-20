"""Opt-in real Redis/prefork checks, using temporary data and no external feeds.

Run with SIGNALWATCH_TEST_REDIS_SERVER=/path/to/redis-server. Redis must have its
shared libraries available through the normal loader or LD_LIBRARY_PATH.
"""

import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from signalwatch.config import DEFAULTS


REDIS_SERVER = os.environ.get("SIGNALWATCH_TEST_REDIS_SERVER")
ROOT = Path(__file__).resolve().parents[1]


def unused_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@unittest.skipUnless(REDIS_SERVER, "Set SIGNALWATCH_TEST_REDIS_SERVER to run real Redis/prefork integration")
class QueueIntegrationTests(unittest.TestCase):
    def setUp(self):
        from redis import Redis

        self.temp = tempfile.TemporaryDirectory(prefix="signalwatch-queue-integration-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.runtime = self.redis_process = None
        self.log_files = []
        self.addCleanup(self.close)
        self.redis_port, self.api_port = unused_port(), unused_port()
        self.broker_url = f"redis://127.0.0.1:{self.redis_port}/0"
        self.redis = Redis.from_url(self.broker_url, socket_connect_timeout=1, socket_timeout=1)
        self.addCleanup(self.redis.close)
        self.base_url = f"http://127.0.0.1:{self.api_port}"
        self.token = "integration-" + uuid.uuid4().hex
        self.config_path = self.folder / "config.json"
        self.config_path.write_text(json.dumps({
            "db": str(self.folder / "signalwatch.db"),
            "cache_dir": str(self.folder / "cache"),
            "sources": {name: False for name in DEFAULTS["sources"]},
            "seed_urls": [], "feeds": [], "csaf_feeds": [], "source_targets": [],
        }))
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(("SIGNALWATCH_", "CELERY_"))}
        self.env.update({
            "CELERY_BROKER_URL": self.broker_url,
            "SIGNALWATCH_CONFIG": str(self.config_path),
            "SIGNALWATCH_CELERY_BEAT": "false",
            "SIGNALWATCH_API_TOKEN": self.token,
            "PYTHONUNBUFFERED": "1",
        })
        self.runtime_log = self.folder / "runtime.log"
        self.redis_log = self.folder / "redis.log"
        self.start_redis()
        self.start_runtime()

    def log(self):
        return self.runtime_log.read_text(errors="replace") if self.runtime_log.exists() else ""

    def wait_for(self, predicate, *, timeout=60, description="condition"):
        deadline = time.monotonic() + timeout
        last_error = None
        while time.monotonic() < deadline:
            if self.runtime is not None and self.runtime.poll() is not None:
                self.fail(f"Runtime exited with {self.runtime.returncode}:\n{self.log()[-8000:]}")
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, urllib.error.URLError) as error:
                last_error = error
            time.sleep(0.1)
        self.fail(f"Timed out waiting for {description}; last error={last_error}:\n{self.log()[-8000:]}")

    def start_redis(self):
        log = self.redis_log.open("ab")
        self.log_files.append(log)
        self.redis_process = subprocess.Popen([
            REDIS_SERVER, "--bind", "127.0.0.1", "--port", str(self.redis_port),
            "--save", "", "--appendonly", "yes", "--dir", str(self.folder),
            "--protected-mode", "yes",
        ], cwd=ROOT, env=self.env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)

        def ready():
            try:
                return self.redis.ping()
            except Exception:
                if self.redis_process.poll() is not None:
                    self.fail(self.redis_log.read_text(errors="replace"))
                return False

        self.wait_for(ready, timeout=10, description="Redis readiness")

    def stop_redis(self):
        if self.redis_process is not None:
            self.redis_process.terminate()
            try:
                self.redis_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.redis_process.kill()
                self.redis_process.wait(timeout=5)
            self.redis_process = None

    def start_runtime(self):
        previous_logs = len(self.log())
        log = self.runtime_log.open("ab")
        self.log_files.append(log)
        self.runtime = subprocess.Popen([
            sys.executable, "-m", "signalwatch", "--config", str(self.config_path),
            "runtime", "--host", "127.0.0.1", "--port", str(self.api_port),
        ], cwd=ROOT, env=self.env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        self.wait_for(lambda: self.request("/health").get("service") == "SignalWatch",
                      description="API readiness")
        self.assertTrue(self.request("/api/jobs")["enabled"])
        self.wait_for(lambda: "ready." in self.log()[previous_logs:], description="prefork worker readiness")
        self.assertIn("concurrency: 1 (prefork)", self.log()[previous_logs:])

    def stop_runtime(self):
        if self.runtime is None:
            return
        process = self.runtime
        self.runtime = None
        if process.poll() is None:
            children_file = Path(f"/proc/{process.pid}/task/{process.pid}/children")
            children = children_file.read_text().split() if children_file.exists() else []
            process.terminate()
            try:
                process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                for pid in [*children, str(process.pid)]:
                    try:
                        os.killpg(int(pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                process.wait(timeout=5)

    def close(self):
        try:
            self.stop_runtime()
        finally:
            self.stop_redis()
            for stream in self.log_files:
                stream.close()

    def request(self, path, body=None):
        request = urllib.request.Request(self.base_url + path,
                                         data=json.dumps(body).encode() if body is not None else None,
                                         headers={"Authorization": "Bearer " + self.token,
                                                  "Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.load(response)

    def wait_job(self, job_id, expected="succeeded", *, timeout=60):
        def ready():
            job = self.request("/api/jobs/" + job_id)
            if job["status"] == "failed":
                self.fail(f"Job failed: {job['error']}\n{self.log()[-8000:]}")
            return job if job["status"] == expected else None

        return self.wait_for(ready, timeout=timeout, description=f"job {job_id} {expected}")

    def test_api_job_is_durable_and_duplicate_delivery_does_not_execute_again(self):
        from celery import Celery

        payload = {"sources": [], "idempotency_key": "integration-once"}
        accepted = self.request("/api/collect", payload)
        self.assertTrue(accepted["queued"])
        job_id = accepted["job"]["id"]
        completed = self.wait_job(job_id)
        self.assertEqual(completed["attempts"], 1)
        self.assertEqual(completed["result"]["sources"], [])
        self.assertEqual(self.request("/api/collect", payload)["job"]["id"], job_id)

        delivery_id = "duplicate-" + uuid.uuid4().hex
        client = Celery("integration", broker=self.broker_url)
        try:
            client.send_task("signalwatch.execute_job", args=[job_id], task_id=delivery_id,
                             queue="signalwatch", ignore_result=True, retry=False)
            self.wait_for(lambda: f"signalwatch.execute_job[{delivery_id}] succeeded" in self.log(),
                          description="duplicate delivery acknowledgement")
        finally:
            client.close()
        duplicate = self.request("/api/jobs/" + job_id)
        self.assertEqual(duplicate["attempts"], 1)
        self.assertEqual(duplicate["finished_at"], completed["finished_at"])

        self.stop_runtime()
        self.start_runtime()
        restored = self.request("/api/jobs/" + job_id)
        self.assertEqual(restored, duplicate)

    def test_broker_outage_keeps_accepted_job_and_recovers_without_resubmission(self):
        self.stop_redis()
        self.assertEqual(self.request("/health")["service"], "SignalWatch")
        accepted = self.request("/api/collect", {"sources": [], "idempotency_key": "integration-outage"})
        self.assertTrue(accepted["queued"])
        job_id = accepted["job"]["id"]
        deferred = self.wait_job(job_id, "retrying", timeout=10)
        self.assertEqual(deferred["attempts"], 0)
        self.assertIsNone(deferred["last_dispatched_at"])
        self.assertIn("broker unavailable", deferred["error"].lower())
        self.start_redis()
        completed = self.wait_job(job_id, timeout=60)
        self.assertEqual(completed["id"], job_id)
        self.assertEqual(completed["attempts"], 1)
        self.assertEqual(completed["result"]["sources"], [])
        self.assertEqual(len(self.request("/api/jobs")["jobs"]), 1)


if __name__ == "__main__":
    unittest.main()
