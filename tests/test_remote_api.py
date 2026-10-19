import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from signalwatch.config import VERSION, load_config
from signalwatch.store import Store


class Server:
    def __init__(self, token="", origins="", root_path="", fail_status=False):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = self.root / "config.json"
        self.config.write_text(json.dumps({"db": "test.db", "cache_dir": "cache", "seed_urls": [], "api_token": "file-token-private", "cors_origins": ["https://file.example"]}))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.url = f"http://127.0.0.1:{port}"
        self.logs = tempfile.TemporaryFile()
        environment = {**os.environ, "SIGNALWATCH_API_TOKEN": token, "SIGNALWATCH_CORS_ORIGINS": origins}
        script = "import sys,uvicorn\nfrom signalwatch.api import create_app\nfrom signalwatch.config import load_config\napp=create_app(load_config(sys.argv[1]),auto_collect=False)\nif sys.argv[4]=='1':\n app.state.store.stats=lambda:1/0\nuvicorn.run(app,host='127.0.0.1',port=int(sys.argv[2]),root_path=sys.argv[3])"
        self.process = subprocess.Popen([sys.executable, "-c", script, str(self.config), str(port), root_path, "1" if fail_status else "0"], env=environment, stdout=self.logs, stderr=self.logs)
        for _ in range(100):
            try:
                if self.request("/health")[0] == 200:
                    break
            except urllib.error.URLError:
                pass
            if self.process.poll() is not None:
                self.logs.seek(0)
                raise RuntimeError(self.logs.read().decode())
            time.sleep(.05)
        else:
            self.close()
            raise RuntimeError("API did not start")

    def request(self, path, data=None, headers=None, method=None):
        body = json.dumps(data).encode() if data is not None else None
        request = urllib.request.Request(self.url + path, data=body, method=method, headers={"Content-Type": "application/json", **(headers or {})})
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            body = response.read().decode()
            return response.status, response.headers, json.loads(body) if "application/json" in response.headers.get("Content-Type", "") else body

    def close(self):
        self.process.terminate()
        self.process.wait(timeout=10)
        self.logs.close()
        self.temp.cleanup()


class RemoteConfigTests(unittest.TestCase):
    def test_environment_overrides_and_exact_origins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"api_token": "file-private", "cors_origins": ["https://file.example"]}))
            with patch.dict(os.environ, {"SIGNALWATCH_API_TOKEN": "environment-private", "SIGNALWATCH_CORS_ORIGINS": " https://APP.EXAMPLE/, http://localhost:5173,https://app.example "}):
                config = load_config(path)
            self.assertEqual(config["api_token"], "environment-private")
            self.assertEqual(config["cors_origins"], ["https://app.example", "http://localhost:5173"])
            with patch.dict(os.environ, {"SIGNALWATCH_API_TOKEN": "", "SIGNALWATCH_CORS_ORIGINS": ""}):
                config = load_config(path)
            self.assertEqual((config["api_token"], config["cors_origins"]), ("", []))

    def test_wildcards_paths_and_credentials_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            with patch.dict(os.environ, {}, clear=True):
                for origins in (["*"], ["https://*.example"], ["https://app.example/path"], ["https://user:pass@app.example"], "https://app.example"):
                    with self.subTest(origins=origins):
                        path.write_text(json.dumps({"cors_origins": origins}))
                        with self.assertRaises(ValueError):
                            load_config(path)


class RemoteApiTests(unittest.TestCase):
    token = "remote-private-bearer-value"
    origin = "https://signalwatch.example"

    @classmethod
    def setUpClass(cls):
        cls.server = Server(cls.token, cls.origin)

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def headers(self):
        return {"Authorization": "Bearer " + self.token, "Origin": self.origin}

    def test_health_is_public_minimal_and_schema_contains_no_credentials(self):
        status, _, body = self.server.request("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body, {"service": "SignalWatch", "version": VERSION, "auth_required": True})
        for path, headers in (("/openapi.json", {}), ("/api/status", self.headers())):
            status, _, body = self.server.request(path, headers=headers)
            self.assertEqual(status, 200)
            serialized = json.dumps(body)
            self.assertNotIn(self.token, serialized)
            self.assertNotIn("file-token-private", serialized)
            self.assertNotIn('"api_token"', serialized)

    def test_reads_exports_and_mutations_fail_closed_before_side_effects(self):
        reads = ["/api/status", "/api/search", "/api/advisories", "/api/alerts", "/api/articles", "/api/events", "/api/event?id=1", "/api/entity?id=anything", "/api/export?kind=entities", "/api/export?kind=events"]
        reads.extend(["/api/staging", "/api/staging/stats", "/api/staging/1", "/api/staging/1/payload"])
        mutations = {
            "/api/collect": {"sources": []}, "/api/seeds": {"urls": ["https://unauthorized.example"]},
            "/api/sources/feed": {"name": "Unauthorized", "url": "https://unauthorized.example/feed"},
            "/api/observations": {"asset_url": "https://unauthorized.example", "vendor": "x", "product": "x", "evidence": "x"},
            "/api/import/sbom": {"asset_url": "https://unauthorized.example", "document": {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": []}},
            "/api/companies/profile": {"name": "Unauthorized"},
            "/api/companies/assets": {"company_id": "company:unauthorized", "asset_url": "https://unauthorized.example", "status": "automatic"},
            "/api/staging": {"source": "unauthorized", "payload": "not accepted"},
            "/api/staging/1/retry": {},
        }
        store = Store(self.server.root / "test.db")
        before = store.stats()
        for authorization in (None, "Bearer wrong-token", "Basic " + self.token, "Bearer"):
            headers = {"Origin": self.origin, **({"Authorization": authorization} if authorization is not None else {})}
            for path, data in [*((path, None) for path in reads), *mutations.items()]:
                with self.subTest(path=path, authorization=authorization):
                    status, response_headers, body = self.server.request(path, data, headers)
                    self.assertEqual(status, 401)
                    self.assertEqual(response_headers["WWW-Authenticate"], "Bearer")
                    self.assertEqual(response_headers["Access-Control-Allow-Origin"], self.origin)
                    self.assertNotIn(self.token, json.dumps(body))
        self.assertEqual(store.stats(), before)
        self.assertNotIn("Unauthorized", self.server.config.read_text())

    def test_authorized_mutations_and_exports_work(self):
        status, _, result = self.server.request("/api/seeds", {"urls": ["https://authorized.example"]}, self.headers())
        self.assertEqual((status, result["count"]), (200, 1))
        status, _, result = self.server.request("/api/observations", {"asset_url": "https://authorized.example", "vendor": "nginx", "product": "nginx", "version": "1.26.0", "evidence": "Supplied inventory"}, self.headers())
        self.assertEqual((status, result["saved"]), (200, True))
        status, _, exported = self.server.request("/api/export?kind=entities&q=authorized.example", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertTrue(exported)

    def test_preflight_requires_no_token_and_restricts_origin_method_headers(self):
        headers = {"Origin": self.origin, "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type"}
        status, response_headers, _ = self.server.request("/api/import/sbom", headers=headers, method="OPTIONS")
        self.assertEqual(status, 200)
        self.assertEqual(response_headers["Access-Control-Allow-Origin"], self.origin)
        self.assertIn("POST", response_headers["Access-Control-Allow-Methods"])
        self.assertNotIn("Access-Control-Allow-Credentials", response_headers)
        for changed in ({"Origin": "https://signalwatch.example.attacker.test"}, {"Access-Control-Request-Method": "DELETE"}, {"Access-Control-Request-Headers": "X-Not-Allowed"}):
            with self.subTest(changed=changed):
                status, _, _ = self.server.request("/api/import/sbom", headers={**headers, **changed}, method="OPTIONS")
                self.assertEqual(status, 400)
        status, response_headers, _ = self.server.request("/api/status", headers={**self.headers(), "Origin": "https://file.example"})
        self.assertEqual(status, 200)
        self.assertNotIn("Access-Control-Allow-Origin", response_headers)

    def test_authorized_client_errors_keep_cors_headers(self):
        for path, data, expected in (("/api/entity?id=missing", None, 404), ("/api/seeds", {}, 422), ("/api/collect", {"sources": ["missing"]}, 400)):
            with self.subTest(path=path):
                status, headers, body = self.server.request(path, data, self.headers())
                self.assertEqual(status, expected)
                self.assertEqual(headers["Access-Control-Allow-Origin"], self.origin)
                self.assertNotIn(self.token, json.dumps(body))


class RemoteCompatibilityTests(unittest.TestCase):
    def test_unexpected_server_errors_keep_cors_and_log_trace_without_leaking_it(self):
        origin = "https://signalwatch.example"
        for token in ("failure-private-token", ""):
            with self.subTest(auth_required=bool(token)):
                server = Server(token, origin, fail_status=True)
                try:
                    headers = {"Origin": origin, **({"Authorization": "Bearer " + token} if token else {})}
                    status, response_headers, body = server.request("/api/status", headers=headers)
                    self.assertEqual(status, 500)
                    self.assertEqual(response_headers["Access-Control-Allow-Origin"], origin)
                    self.assertEqual(body, {"detail": "Internal Server Error"})
                    self.assertEqual(server.request("/health")[0], 200)
                    server.logs.seek(0)
                    logs = server.logs.read().decode()
                    self.assertIn("ZeroDivisionError", logs)
                    self.assertIn("HTTP request failed", logs)
                finally:
                    server.close()

    def test_empty_token_keeps_local_behavior(self):
        server = Server()
        try:
            self.assertFalse(server.request("/health")[2]["auth_required"])
            self.assertEqual(server.request("/api/status")[0], 200)
            self.assertEqual(server.request("/api/seeds", {"urls": ["https://local.example"]})[0], 200)
        finally:
            server.close()

    def test_reverse_proxy_root_path_does_not_bypass_authentication(self):
        server = Server("root-private-token", root_path="/signalwatch")
        try:
            self.assertEqual(server.request("/api/status")[0], 401)
            self.assertEqual(server.request("/api/status", headers={"Authorization": "Bearer root-private-token"})[0], 200)
        finally:
            server.close()
