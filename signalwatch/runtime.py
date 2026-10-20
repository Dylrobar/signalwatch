"""Supervise API and workers; activate verified database migrations first."""

import fcntl
import logging
import os
import signal
import subprocess
import sys
import time
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from contextlib import contextmanager, nullcontext
from pathlib import Path
from urllib.parse import urlsplit

from .config import load_config


log = logging.getLogger("signalwatch.runtime")
SHUTDOWN_SECONDS = 20


@contextmanager
def _migration_listener(host, port):
    """Bind the deployment port while keeping every application route unavailable."""
    class MaintenanceHandler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(2)

        def respond(self):
            body = b'{"service":"SignalWatch","status":"migrating","ready":false}'
            self.send_response(503)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('Retry-After', '30')
            self.send_header('Connection', 'close')
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(body)
            self.close_connection = True

        do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = respond

        def log_message(self, *_args):
            # Request paths and headers can contain secrets; this listener has
            # no application routes and deliberately logs neither.
            pass

    server = ThreadingHTTPServer((host, port), MaintenanceHandler)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.1}, daemon=True)
    thread.start()
    log.info('Migration maintenance listener started; application readiness remains HTTP 503')
    try:
        yield server.server_address
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


def _enabled(value, *, default=True):
    if value is None:
        return default
    value = value.strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    raise ValueError("SIGNALWATCH_CELERY_BEAT must be true or false")


def child_commands(config, *, host=None, port=None, no_collect=False, beat=True):
    """All child commands use one absolute config and the current interpreter."""
    path = str(Path(config["config_path"]).resolve())
    api = [sys.executable, "-m", "signalwatch", "--config", path, "serve",
           "--host", host or config["host"], "--port", str(port if port is not None else config["port"])]
    if no_collect:
        api.append("--no-collect")
    celery = [sys.executable, "-m", "celery", "-A", "signalwatch.celery_app:app"]
    children = [("api", api), ("worker", [*celery, "worker", "--pool=prefork", "--concurrency=1",
                                         "--prefetch-multiplier=1", "--loglevel=INFO"])]
    if beat and not no_collect:
        schedule = str(Path(config["config_path"]).parent / "celerybeat-schedule")
        children.append(("beat", [*celery, "beat", "--loglevel=INFO", "--schedule", schedule,
                                  "--pidfile", ""]))
    return children


@contextmanager
def _runtime_lock(config_path):
    path = Path(config_path).with_name(Path(config_path).name + ".runtime.lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RuntimeError("Another SignalWatch runtime is already using this config") from error
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _stop(children, shutdown_timeout):
    # TERM the leaders first: Celery can finish its current task and reap its
    # prefork child. After the grace period, kill entire groups so a crashed
    # leader cannot leave a collector, nmap, or worker process behind.
    for _, child in children:
        if child.poll() is None:
            try:
                child.send_signal(signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + shutdown_timeout
    while any(child.poll() is None for _, child in children) and time.monotonic() < deadline:
        time.sleep(0.05)
    for _, child in children:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    deadline = time.monotonic() + 2
    for _, child in children:
        try:
            child.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            log.error("A supervised process did not exit after SIGKILL")


def supervise(commands, env, *, shutdown_timeout=SHUTDOWN_SECONDS):
    """Exit on any unexpected child death; Render then restarts the whole unit."""
    children, stopping = [], []
    previous = {}

    def request_stop(signum, _frame):
        stopping.append(signum)

    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, request_stop)
    try:
        for name, command in commands:
            if stopping:
                return 0
            child = subprocess.Popen(command, env=env, start_new_session=True)
            children.append((name, child))
            log.info("Started SignalWatch %s process", name)
        while not stopping:
            for name, child in children:
                code = child.poll()
                if code is not None:
                    log.error("SignalWatch %s exited unexpectedly (code %s)", name, code)
                    return code if code > 0 else 128 - code if code < 0 else 1
            time.sleep(0.1)
        log.info("Stopping SignalWatch runtime after signal %s", stopping[0])
        return 0
    finally:
        try:
            _stop(children, shutdown_timeout)
        finally:
            for signum, handler in previous.items():
                signal.signal(signum, handler)


def run(config_path, *, host=None, port=None, no_collect=False):
    path = Path(config_path).expanduser().resolve()
    env = os.environ.copy()
    configured = env.get("SIGNALWATCH_CONFIG")
    if configured and (not Path(configured).is_absolute() or Path(configured).resolve() != path):
        raise ValueError("SIGNALWATCH_CONFIG must be absolute and match --config")
    env["SIGNALWATCH_CONFIG"] = str(path)
    config = load_config(path)
    migration_value = env.get("SIGNALWATCH_MIGRATE_SQLITE", "false").strip().lower()
    if migration_value not in {"0", "1", "true", "false", "yes", "no", "on", "off"}:
        raise ValueError("SIGNALWATCH_MIGRATE_SQLITE must be true or false")
    migrate = migration_value in {"1", "true", "yes", "on"}
    with (_runtime_lock(path) if migrate or env.get("CELERY_BROKER_URL", "").strip() else nullcontext()):
        if migrate:
            from .postgres_migrate import migrate_sqlite
            source = config.get("sqlite_db")
            if not source or not str(config["db"]).startswith(("postgres://", "postgresql://")):
                raise ValueError("SQLite migration requires an original SQLite db in config and SIGNALWATCH_DATABASE_URL")
            log.info("Verifying SQLite snapshot and PostgreSQL migration before starting application processes")
            with _migration_listener(host or config['host'], port if port is not None else config['port']):
                manifest = migrate_sqlite(source, config["db"])
            log.info("PostgreSQL migration verified: %s rows across %s tables; already_migrated=%s",
                     manifest["total_rows"], len(manifest["tables"]), manifest["already_migrated"])
        if not env.get("CELERY_BROKER_URL", "").strip():
            command = [sys.executable, "-m", "signalwatch", "--config", str(path), "serve"]
            if host is not None:
                command.extend(["--host", host])
            if port is not None:
                command.extend(["--port", str(port)])
            if no_collect:
                command.append("--no-collect")
            os.execvpe(sys.executable, command, env)
            return 0
        # Raw wireless archives still use this service's persistent disk. Keep
        # co-located processes until an external archive store is configured.
        broker = env["CELERY_BROKER_URL"].strip()
        try:
            parsed = urlsplit(broker)
            valid = parsed.scheme in {"redis", "rediss"} and bool(parsed.hostname)
            parsed.port
        except ValueError:
            valid = False
        if not valid:
            raise ValueError("CELERY_BROKER_URL must be a Redis or TLS Redis URL with an explicit host")
        env["CELERY_BROKER_URL"] = broker
        env["WEB_CONCURRENCY"] = "1"
        commands = child_commands(config, host=host, port=port, no_collect=no_collect,
                                  beat=_enabled(env.get("SIGNALWATCH_CELERY_BEAT")))
        return supervise(commands, env)
