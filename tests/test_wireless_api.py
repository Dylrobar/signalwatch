import csv
import gzip
import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def observation(identifier="02:00:00:00:10:01", name="Example network", latitude="44", longitude="-73", radio_type="WIFI", timestamp="2026-01-01 12:00:00"):
    return [identifier, name, "[WPA2]", timestamp, "6", "2437", "-60", latitude, longitude, "50", "5", "", "", radio_type]


def archive_bytes(rows):
    output = io.StringIO(newline="")
    writer = csv.writer(output)
    writer.writerow(["WigleWifi-1.6", "appRelease=2.111"])
    writer.writerow(["MAC", "SSID", "AuthMode", "FirstSeen", "Channel", "Frequency", "RSSI", "CurrentLatitude", "CurrentLongitude", "AltitudeMeters", "AccuracyMeters", "RCOIs", "MfgrId", "Type"])
    writer.writerows(rows)
    return gzip.compress(output.getvalue().encode(), mtime=0)


class WirelessApiTests(unittest.TestCase):
    token = "synthetic-wireless-api-token"
    origin = "https://wireless.example.test"

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        config = cls.root / "config.json"
        config.write_text(json.dumps({"db": "monitor.db", "cache_dir": "cache", "seed_urls": [],
                                     "wireless_chunk_rows": 2, "wireless_import_max_mb": 0.003,
                                     "staging_poll_seconds": 0.02}))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        cls.base = f"http://127.0.0.1:{port}"
        cls.logs = tempfile.TemporaryFile()
        environment = {**os.environ, "SIGNALWATCH_API_TOKEN": cls.token, "SIGNALWATCH_CORS_ORIGINS": cls.origin}
        script = "import sys,uvicorn\nfrom unittest.mock import AsyncMock\nimport signalwatch.wireless_attribution as attribution\nfrom signalwatch.api import create_app\nfrom signalwatch.config import load_config\nattribution.fetch_business_facilities=AsyncMock(side_effect=AssertionError('Unexpected external business lookup'))\napp=create_app(load_config(sys.argv[1]),auto_collect=False)\nuvicorn.run(app,host='127.0.0.1',port=int(sys.argv[2]))"
        cls.process = subprocess.Popen([sys.executable, "-c", script, str(config), str(port)],
                                       env=environment, stdout=cls.logs, stderr=cls.logs)
        for _ in range(100):
            try:
                if cls.request("/health")[0] == 200:
                    return
            except urllib.error.URLError:
                pass
            if cls.process.poll() is not None:
                cls.logs.seek(0)
                raise RuntimeError(cls.logs.read().decode())
            time.sleep(0.05)
        cls.process.terminate()
        cls.process.wait(timeout=10)
        raise RuntimeError("Wireless API failed to start")

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=10)
        cls.logs.close()
        cls.temp.cleanup()

    @classmethod
    def request(cls, path, data=None, *, headers=None, authorized=True, method=None, chunked=False):
        values = {"Origin": cls.origin, **({"Authorization": "Bearer " + cls.token} if authorized else {}), **(headers or {})}
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode()
            values.setdefault("Content-Type", "application/json")
        else:
            body = data
        if chunked and body is not None:
            contents = body
            body = iter(contents[index:index + 17] for index in range(0, len(contents), 17))
        request = urllib.request.Request(cls.base + path, data=body, headers=values, method=method)
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw = response.read()
            result = json.loads(raw) if "application/json" in response.headers.get("Content-Type", "") else raw
            return response.status, response.headers, result

    def upload(self, name, rows, *, chunked=False):
        raw = archive_bytes(rows)
        status, _, started = self.request("/api/import/wigle", raw, chunked=chunked,
                                          headers={"Content-Type": "application/gzip", "X-Filename": name,
                                                   "X-Source-Url": "https://example.test/public-export"})
        self.assertEqual(status, 202, started)
        self.wait_import(started["dataset_id"])
        return started["dataset_id"], raw

    def wait_import(self, dataset_id, expected="complete"):
        deadline = time.monotonic() + 10
        path = "/api/wireless/datasets/" + urllib.parse.quote(dataset_id, safe="")
        while time.monotonic() < deadline:
            status, _, result = self.request(path)
            self.assertEqual(status, 200, result)
            state = result["job"].get("status")
            if state in {"complete", "failed"}:
                self.assertEqual(state, expected, result["job"].get("error"))
                return result
            time.sleep(0.03)
        self.fail("Wireless API import did not finish")

    def test_authentication_covers_upload_download_queries_and_attribution(self):
        before = self.request("/api/wireless/stats")[2]
        archives = sorted((self.root / "wireless-imports").iterdir())
        reads = ["/api/wireless/stats", "/api/wireless/datasets", "/api/wireless/datasets/missing",
                 "/api/wireless/datasets/missing/source", "/api/wireless/devices", "/api/wireless/devices/missing",
                 "/api/wireless/map?bbox=-180,-90,180,90", "/api/wireless/facilities", "/api/wireless/enrichment"]
        writes = ["/api/import/wigle", "/api/wireless/devices/missing/company", "/api/wireless/facilities",
                  "/api/wireless/enrichment", "/api/wireless/registries?registry=MA-L",
                  "/api/wireless/device-enrichment?source_url=https://example.test/",
                  "/api/wireless/business-import?source_url=https://example.test/"]
        for authorization in (None, "Bearer invalid", "Basic " + self.token):
            headers = {"Authorization": authorization} if authorization else {}
            for path in reads + writes:
                with self.subTest(path=path, authorization=authorization):
                    status, response_headers, body = self.request(path, b"{}" if path in writes else None,
                                                                  headers=headers, authorized=False)
                    self.assertEqual(status, 401)
                    self.assertEqual(response_headers["WWW-Authenticate"], "Bearer")
                    self.assertEqual(response_headers["Access-Control-Allow-Origin"], self.origin)
                    self.assertNotIn(self.token, json.dumps(body))
        self.assertEqual(self.request("/api/wireless/stats")[2], before)
        self.assertEqual(sorted((self.root / "wireless-imports").iterdir()), archives)

    def test_business_import_preserves_valid_and_invalid_raw_records_and_company_facilities(self):
        document = {"osm3s": {"timestamp_osm_base": "2026-01-01T00:00:00Z"}, "elements": [
            {"type": "node", "id": 900001, "lat": 44, "lon": -73,
             "tags": {"name": "Example imported shop", "shop": "convenience", "brand": "Example imported brand"}},
            {"type": "node", "id": 900002, "lat": 44, "lon": -73, "tags": {"building": "yes"}},
        ]}
        location = "https://example.test/overpass-snapshot"
        raw = json.dumps(document, indent=2).encode()
        path = "/api/wireless/business-import?" + urllib.parse.urlencode({"source_url": location})
        status, _, result = self.request(path, raw, headers={"Content-Type": "application/json"})
        self.assertEqual((status, result["imported"], result["skipped"]), (200, 1, 1))
        facilities = self.request("/api/wireless/facilities")[2]["items"]
        facility = next(row for row in facilities if row["name"] == "Example imported shop")
        self.assertEqual(facility["source_url"], "https://www.openstreetmap.org/node/900001")
        self.assertEqual(facility["evidence"]["attribution"], "OpenStreetMap contributors")
        company_path = "/api/entity?" + urllib.parse.urlencode({"id": facility["company_id"]})
        status, _, company = self.request(company_path)
        self.assertEqual((status, company["name"]), (200, "Example imported brand"))
        self.assertEqual(company["company_profile"]["legal_name"], "")
        bad_location = location + "-bad"
        bad = b'{ "unexpected": [] }'
        status, _, _ = self.request("/api/wireless/business-import?" + urllib.parse.urlencode({"source_url": bad_location}), bad)
        self.assertEqual(status, 400)
        for source_url, payload in ((location, raw), (bad_location, bad)):
            staged = next(row for row in self.request("/api/staging?limit=500")[2]["items"]
                          if row["source"] == "wireless-business-import" and row["source_url"] == source_url)
            self.assertEqual(staged["payload_hash"], hashlib.sha256(payload).hexdigest())
            self.assertEqual(self.request(f'/api/staging/{staged["id"]}/payload')[2], payload)
        self.assertEqual(self.request("/api/wireless/business-import?source_url=file:///invalid", raw)[0], 400)

    def test_default_enrichment_matches_existing_facilities_without_external_lookup(self):
        dataset_id, _ = self.upload("Default enrichment.csv.gz", [observation("02:00:00:00:50:01", "Example local-only signal")])
        status, _, company = self.request("/api/companies/profile", {"name": "Example local-only business"})
        self.assertEqual(status, 200)
        status, _, _ = self.request("/api/wireless/facilities", {"name": "Example existing facility", "latitude": 44,
                                                               "longitude": -73, "company_id": company["id"],
                                                               "source_url": "https://example.test/existing-facility"})
        self.assertEqual(status, 200)
        status, _, result = self.request("/api/wireless/enrichment", {})
        self.assertEqual(status, 202, result)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            state = self.request("/api/wireless/enrichment")[2]
            if state.get("status") in {"complete", "partial", "failed"}:
                break
            time.sleep(0.02)
        self.assertEqual(state["status"], "complete", state)
        self.assertEqual(state["counts"]["facilities"], [])
        self.assertEqual(state["counts"]["errors"], [])
        self.assertGreater(sum(page["facilities_processed"] for page in state["counts"]["matches"]), 0)
        item = self.request("/api/wireless/devices?" + urllib.parse.urlencode({"dataset_id": dataset_id}))[2]["items"][0]
        self.assertIn((company["id"], "candidate_business"), [(row["company_id"], row["role"]) for row in item["company_links"]])
        self.assertFalse(item["attribution"]["operator_confirmed"])

    def test_streamed_upload_preserves_original_archive_and_dataset_statistics(self):
        first = observation(name="Example streamed network")
        dataset_id, raw = self.upload("Example streamed.csv.gz", [first, first, observation("C2:00:00:00:10:02", radio_type="BLE")], chunked=True)
        detail = self.wait_import(dataset_id)
        self.assertEqual((detail["observations"], detail["devices"], detail["timestamp_timezone"]), (3, 2, "UTC"))
        status, _, statistics = self.request("/api/wireless/stats?" + urllib.parse.urlencode({"dataset_id": dataset_id}))
        self.assertEqual(status, 200)
        self.assertEqual((statistics["datasets"], statistics["observations"], statistics["devices"]), (1, 3, 2))
        self.assertEqual(statistics["signal_types"], {"BLE": 1, "WIFI": 1})
        self.assertEqual(statistics["located_devices"], 2)
        source = "/api/wireless/datasets/" + urllib.parse.quote(dataset_id, safe="") + "/source"
        status, headers, downloaded = self.request(source)
        self.assertEqual(status, 200)
        self.assertEqual(downloaded, raw)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("attachment", headers["Content-Disposition"])
        status, _, duplicate = self.request("/api/import/wigle", raw, headers={"X-Filename": "Renamed.csv.gz"})
        self.assertEqual(status, 202)
        self.assertEqual(duplicate["dataset_id"], dataset_id)
        self.assertTrue(duplicate["duplicate"])
        self.assertEqual(self.wait_import(dataset_id)["observations"], 3)

    def test_detail_company_links_are_arrays_and_locations_keep_provenance(self):
        rows = [observation("02:00:00:00:20:01", "Example detail network"),
                observation("02:00:00:00:20:01", "Example detail network", "44.001", "-73.001", timestamp="2026-01-02 12:00:00")]
        dataset_id, _ = self.upload("Detail.csv.gz", rows)
        query = urllib.parse.urlencode({"dataset_id": dataset_id})
        status, _, listed = self.request("/api/wireless/devices?" + query)
        self.assertEqual(status, 200)
        identity = listed["items"][0]["id"]
        self.assertIsInstance(listed["items"][0]["company_links"], list)
        path = "/api/wireless/devices/" + urllib.parse.quote(identity, safe="")
        status, _, detail = self.request(path + "?limit=1")
        self.assertEqual(status, 200)
        self.assertEqual(detail["observations"], 2)
        self.assertEqual(len(detail["locations"]), 1)
        self.assertEqual(detail["locations_total"], 2)
        self.assertTrue(detail["locations_truncated"])
        self.assertEqual(detail["locations"][0]["gps_accuracy"], 5)
        self.assertEqual(detail["provenance"]["location_basis"], "scan_observation")
        self.assertEqual(detail["provenance"]["datasets"][0]["id"], dataset_id)
        self.assertEqual(detail["observation_records"][0]["raw"]["SSID"], "Example detail network")
        status, _, company = self.request("/api/companies/profile", {"name": "Example wireless operator"})
        self.assertEqual(status, 200)
        decision = {"company_id": company["id"], "status": "confirmed", "evidence": "Synthetic inventory association", "source_url": "file:///invalid"}
        self.assertEqual(self.request(path + "/company", decision)[0], 400)
        decision["source_url"] = "https://example.test/inventory"
        status, _, decided = self.request(path + "/company", decision)
        self.assertEqual(status, 200)
        self.assertIsInstance(decided["company_links"], list)
        self.assertEqual([(row["company_id"], row["role"], row["status"]) for row in decided["company_links"]],
                         [(company["id"], "confirmed_operator", "confirmed")])
        self.assertTrue(decided["attribution"]["operator_confirmed"])
        status, _, filtered = self.request("/api/wireless/devices?" + urllib.parse.urlencode({"company_id": company["id"]}))
        self.assertEqual((status, filtered["total"]), (200, 1))

    def test_map_geojson_retains_full_total_when_returned_groups_are_truncated(self):
        rows = [observation("02:00:00:00:30:01", "100% Example map", "44", "-73"),
                observation("02:00:00:00:30:01", "100% Example map", "44.001", "-73.001"),
                observation("02:00:00:00:30:02", "Other example", "45", "-74"),
                observation("C2:00:00:00:30:03", "Example beacon", "43", "-72", "BLE")]
        dataset_id, _ = self.upload("Map.csv.gz", rows)
        parameters = {"bbox": "-180,-90,180,90", "zoom": "20", "dataset_id": dataset_id, "limit": "1"}
        status, _, result = self.request("/api/wireless/map?" + urllib.parse.urlencode(parameters))
        self.assertEqual(status, 200)
        self.assertEqual(result["type"], "FeatureCollection")
        self.assertEqual(result["total"], 4)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["features"]), 1)
        self.assertEqual(result["features"][0]["geometry"]["type"], "Point")
        self.assertLess(result["features"][0]["properties"]["count"], result["total"])
        for extra, expected in (({"type": "BLE"}, 1), ({"q": "100%"}, 2), ({"bbox": "0,0,1,1"}, 0)):
            status, _, filtered = self.request("/api/wireless/map?" + urllib.parse.urlencode({**parameters, **extra, "limit": "50"}))
            self.assertEqual((status, filtered["total"]), (200, expected))
        for bbox in ("1,2,3", "0,nan,1,2", "0,0,200,2"):
            self.assertEqual(self.request("/api/wireless/map?" + urllib.parse.urlencode({"bbox": bbox}))[0], 400)

    def test_empty_and_oversize_uploads_have_no_dataset_or_file_side_effects(self):
        before = self.request("/api/wireless/datasets")[2]["total"]
        archives = sorted((self.root / "wireless-imports").iterdir())
        for raw, expected, chunked in ((b"", 400, False), (b"x" * 4000, 413, True)):
            with self.subTest(size=len(raw)):
                status, _, _ = self.request("/api/import/wigle", raw, chunked=chunked, method="POST")
                self.assertEqual(status, expected)
        self.assertEqual(self.request("/api/wireless/datasets")[2]["total"], before)
        self.assertEqual(sorted((self.root / "wireless-imports").iterdir()), archives)

    def test_invalid_export_is_inspectable_failed_job_without_observations(self):
        raw = gzip.compress(b"invalid,export\n", mtime=0)
        status, _, started = self.request("/api/import/wigle", raw, headers={"X-Filename": "Invalid.csv.gz"})
        self.assertEqual(status, 202)
        result = self.wait_import(started["dataset_id"], expected="failed")
        self.assertEqual(result["observations"], 0)
        self.assertTrue(result["job"]["error"])
        self.assertEqual(self.request("/api/wireless/datasets/" + urllib.parse.quote(started["dataset_id"], safe="") + "/source")[2], raw)

    def test_invalid_registry_and_enrichment_inputs_return_client_errors(self):
        cases = [
            ("/api/wireless/registries?registry=unknown", b"bad"),
            ("/api/wireless/registries?registry=MA-L&source_url=file:///invalid", b"bad"),
            ("/api/wireless/registries?registry=MA-L", b"Assignment,Organization Name\n00005E\n"),
            ("/api/wireless/registries?registry=Bluetooth%20SIG", b"[{}]"),
            ("/api/wireless/device-enrichment?source_url=file:///invalid", b"[]"),
            ("/api/wireless/device-enrichment?source_url=https://example.test/atlas", b"not-json"),
            ("/api/wireless/device-enrichment?source_url=https://example.test/atlas", {}),
            ("/api/wireless/device-enrichment?source_url=https://example.test/atlas", [{}]),
            ("/api/wireless/device-enrichment?source_url=https://example.test/atlas", [{"identifier": "02:00:00:00:10:01", "radio_type": "WIFI", "labels": []}]),
        ]
        for path, payload in cases:
            with self.subTest(path=path, payload=payload):
                status, _, body = self.request(path, payload)
                self.assertEqual(status, 400, body)
                self.assertNotIn("Traceback", json.dumps(body))

    def test_facility_urls_are_validated_before_inserting_records(self):
        status, _, company = self.request("/api/companies/profile", {"name": "Example facility company"})
        self.assertEqual(status, 200)
        request = {"name": "Example business facility", "latitude": 44, "longitude": -73,
                   "company_id": company["id"], "source_url": "https://example.test/locations"}
        for replacement in ({"source_url": "file:///invalid"}, {"website": "file:///invalid"}):
            with self.subTest(replacement=replacement):
                self.assertEqual(self.request("/api/wireless/facilities", {**request, **replacement})[0], 400)
        query = urllib.parse.urlencode({"company_id": company["id"]})
        self.assertEqual(self.request("/api/wireless/facilities?" + query)[2]["total"], 0)
        status, _, saved = self.request("/api/wireless/facilities", request)
        self.assertEqual(status, 200)
        status, _, listed = self.request("/api/wireless/facilities?" + query)
        self.assertEqual((status, listed["total"]), (200, 1))
        self.assertEqual(listed["items"][0]["id"], saved["id"])

    def test_imported_labels_remain_provider_claims_and_support_repeat_updates(self):
        dataset_id, _ = self.upload("Labels.csv.gz", [observation("02:00:00:00:40:01", "Example label network")])
        body = [{"identifier": "02:00:00:00:40:01", "radio_type": "WIFI", "labels": {"provider": "Example advertised provider", "model_hint": "Unverified hint"}, "evidence": {"basis": "Synthetic previous export"}}]
        path = "/api/wireless/device-enrichment?" + urllib.parse.urlencode({"source_url": "https://example.test/previous-atlas", "version": "example-version"})
        for _ in range(2):
            status, _, result = self.request(path, body)
            self.assertEqual((status, result["matched_devices"]), (200, 1))
        listed = self.request("/api/wireless/devices?" + urllib.parse.urlencode({"dataset_id": dataset_id}))[2]["items"][0]
        self.assertEqual([(row["role"], row["status"]) for row in listed["company_links"]], [("advertised_provider", "claimed")])
        self.assertFalse(listed["attribution"]["operator_confirmed"])
        self.assertEqual(listed["metadata"]["imported_enrichment"]["labels"]["model_hint"], "Unverified hint")

    def test_wireless_upload_preflight_allows_filename_and_source_headers(self):
        status, headers, _ = self.request("/api/import/wigle", authorized=False, method="OPTIONS", headers={
            "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization,content-type,x-filename,x-source-url"})
        self.assertEqual(status, 200)
        self.assertEqual(headers["Access-Control-Allow-Origin"], self.origin)
        self.assertIn("X-Filename", headers["Access-Control-Allow-Headers"])
