import base64
import hashlib
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from signalwatch.extension_hardware import SOURCE_DEFINITIONS, collect_hardware_sources, normalize_hardware
from signalwatch.http import FetchResult
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.normalization import NormalizationError
from signalwatch.store import Store


class HardwareSourceTests(unittest.IsolatedAsyncioTestCase):
    def item(self, provider, value, **metadata):
        payload = value.encode() if isinstance(value, str) else json.dumps(value).encode()
        return {"id": 17, "source": "public:" + provider, "source_url": "https://index.example/export", "stream_key": "query", "payload": payload, "payload_hash": hashlib.sha256(payload).hexdigest(), "observed_at": "2026-10-19T00:00:00+00:00", "metadata": {"provider": provider, **metadata}}

    def config(self, *providers):
        return {"provider_settings": {row["id"]: {"enabled": row["id"] in providers} for row in SOURCE_DEFINITIONS}, "provider_credentials": {}, "public_source_batch": 3}

    def test_wigle_netid_uses_wireless_normalization_without_vendor_or_company_inference(self):
        item = self.item("wigle", {"success": True, "results": [{"netid": "02-AA-BB-CC-DD-EE", "ssid": "Office", "trilat": 40.0, "trilong": -74.0, "lasttime": "2020-01-01T00:00:00Z"}]})
        batch = normalize_hardware(item)
        self.assertEqual(len(batch["entities"]), 1)
        entity = batch["entities"][0]
        self.assertEqual(entity["kind"], "wireless")
        self.assertEqual(entity["value"], "02:aa:bb:cc:dd:ee")
        self.assertTrue(entity["metadata"]["randomization_possible"])
        self.assertEqual(entity["metadata"]["fields"]["ssid"], "Office")
        self.assertEqual(entity["metadata"]["fields"]["lasttime"], "2020-01-01T00:00:00Z")
        self.assertEqual(entity["metadata"]["staging"]["payload_hash"], item["payload_hash"])
        self.assertEqual(entity["metadata"]["staging"]["raw_reference"], "staging:17")
        self.assertNotIn("vendor", entity["metadata"])
        self.assertNotIn("observations", batch)

    def test_wigle_invalid_coordinates_addresses_or_response_fail(self):
        rows = [{"netid": "not-a-mac"}, {"netid": "00:11:22:33:44:55", "trilat": 91, "trilong": 0}, {"netid": "00:11:22:33:44:55", "trilat": 0, "trilong": -181}, {"netid": "00:11:22:33:44:55", "trilat": 0}, {"netid": "00:11:22:33:44:55", "trilat": True, "trilong": 0}, {"netid": "00:11:22:33:44:55", "trilat": "NaN", "trilong": 0}]
        for row in rows:
            with self.subTest(row=row), self.assertRaises(NormalizationError):
                normalize_hardware(self.item("wigle", {"success": True, "results": [row]}))
        with self.assertRaises(NormalizationError):
            normalize_hardware(self.item("wigle", {"success": False, "message": "too many queries"}))
        self.assertEqual(normalize_hardware(self.item("wigle", {"success": True, "results": []})), {"entities": []})

    def test_fcc_json_csv_and_html_retain_actual_fields_only(self):
        fixtures = [({"records": [{"call_sign": "TEST", "frequency": 3650, "licensee": "Company"}]}, "frequency", 3650), ("call_sign,frequency,licensee\nTEST,3650,Company\n", "licensee", "Company"), ("<table><tr><th>call_sign</th><th>equipment</th></tr><tr><td>TEST</td><td>Radio</td></tr></table>", "equipment", "Radio")]
        for value, field, expected in fixtures:
            with self.subTest(field=field):
                batch = normalize_hardware(self.item("fcc_uls", value))
                self.assertEqual(batch["entities"][0]["metadata"]["provider_fields"][field], expected)
                self.assertEqual({entity["kind"] for entity in batch["entities"]}, {"source_record"})
                self.assertNotIn("observations", batch)
        self.assertEqual(len(normalize_hardware(self.item("fcc_equipment", [{"fcc_id": str(i)} for i in range(5)]), max_records=2)["entities"]), 2)

    def test_industrial_indexers_preserve_provider_identity_and_raw_reference(self):
        fixtures = {"shodan_ics": {"matches": [{"ip_str": "192.0.2.1", "port": 502, "product": "Modbus"}]}, "censys_devices": {"result": {"hits": [{"host_v1": {"resource": {"ip": "192.0.2.1"}}}]}}}
        for provider, value in fixtures.items():
            with self.subTest(provider=provider):
                batch = normalize_hardware(self.item(provider, value))
                entity = next(row for row in batch["entities"] if row["kind"] == "source_record")
                self.assertTrue(entity["id"].startswith("source_record:" + provider + ":"))
                self.assertEqual(entity["metadata"]["provider"], provider)
                self.assertEqual(entity["metadata"]["staging"]["source"], "public:" + provider)
                self.assertEqual(batch["edges"][0]["from_id"], entity["id"])
                self.assertNotIn("observations", batch)

    async def test_missing_credentials_queries_and_export_urls_are_unconfigured(self):
        config = self.config("wigle", "fcc_uls", "shodan_ics", "censys_devices")
        config["provider_credentials"] = {"shodan": "key", "censys": "pat", "wigle": {"api_name": "name", "api_token": "token"}}
        http = types.SimpleNamespace(get=AsyncMock(), post=AsyncMock())
        counts = await collect_hardware_sources(config, None, http)
        self.assertEqual(counts["errors"], [])
        self.assertEqual(counts["provider_health"]["wigle"]["status"], "unconfigured")
        self.assertEqual(counts["provider_health"]["shodan_ics"]["requirements"], ["query"])
        self.assertEqual(counts["provider_health"]["fcc_uls"]["requirements"], ["url"])
        http.get.assert_not_awaited()
        http.post.assert_not_awaited()

    async def test_actual_raw_staging_to_worker_retains_bytes_and_provider_fields(self):
        raw = b'{ "success": true, "results": [{"netid":"00:11:22:33:44:55","ssid":"Lab","trilat":40,"trilong":-74}] }\n'
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            path = Path(folder) / "raw.json"
            path.write_bytes(raw)
            config = self.config("wigle")
            config["provider_credentials"]["wigle"] = {"api_name": "name", "api_token": "token"}
            config["provider_settings"]["wigle"]["netid"] = "00:11:22:33:44:55"
            http = types.SimpleNamespace(get=AsyncMock(return_value=FetchResult(path, 200, {}, "https://api.wigle.net/", True, hashlib.sha256(raw).hexdigest())))
            counts = await collect_hardware_sources(config, store, http)
            self.assertEqual(counts["staged"], 1)
            queued = staging_queue(store, config).get(1, include_payload=True)
            self.assertEqual(queued["payload"], raw)
            self.assertNotIn("token", queued["source_url"])
            result = StagingWorker(store, config).drain()
            self.assertEqual(result["processed"], 1)
            with store.connection() as conn:
                row = conn.execute("SELECT metadata FROM entities WHERE kind='wireless'").fetchone()
                self.assertEqual(json.loads(row[0])["fields"]["ssid"], "Lab")
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 0)
            headers = http.get.await_args.kwargs["headers"]
            self.assertEqual(headers["Authorization"], "Basic " + base64.b64encode(b"name:token").decode())
            self.assertFalse(http.get.await_args.kwargs["allow_redirects"])

    async def test_actual_fcc_staging_rotation_and_duplicate_counts(self):
        raw = b'call_sign,licensee\nTEST,Company\n'
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            path = Path(folder) / "raw.csv"
            path.write_bytes(raw)
            config = self.config("fcc_uls")
            config["public_source_batch"] = 1
            config["provider_settings"]["fcc_uls"]["urls"] = ["https://data.example/a", "https://data.example/b"]
            http = types.SimpleNamespace(get=AsyncMock(return_value=FetchResult(path, 200, {"Content-Type": "text/csv"}, "https://data.example/", True, hashlib.sha256(raw).hexdigest())))
            first = await collect_hardware_sources(config, store, http)
            second = await collect_hardware_sources(config, store, http)
            third = await collect_hardware_sources(config, store, http)
            self.assertEqual([call.args[0] for call in http.get.await_args_list], ["https://data.example/a", "https://data.example/b", "https://data.example/a"])
            self.assertEqual([first["staged"], second["staged"], third["staged"]], [1, 1, 0])
            self.assertEqual(third["unchanged"], 1)
            self.assertEqual(first["pending_targets"], 1)
            result = StagingWorker(store, config).drain()
            self.assertEqual(result["processed"], 2)
            self.assertEqual(staging_queue(store, config).get(1, include_payload=True)["payload"], raw)

    async def test_wigle_invalid_query_never_sends_unbounded_request(self):
        config = self.config("wigle")
        config["provider_credentials"]["wigle"] = {"api_name": "name", "api_token": "token"}
        config["provider_settings"]["wigle"].update(latrange1=0, latrange2=1, longrange1=0)
        http = types.SimpleNamespace(get=AsyncMock())
        counts = await collect_hardware_sources(config, None, http)
        self.assertEqual(counts["provider_health"]["wigle"]["status"], "error")
        self.assertTrue(counts["errors"])
        http.get.assert_not_awaited()
