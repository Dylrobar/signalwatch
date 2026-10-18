import copy
import hashlib
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

from signalwatch.cve_program import DELTA_URL, RAW_BASE, RELEASE_URL, collect_cve_program, parse_cve5
from signalwatch.store import Store


def cve_record(native_id="CVE-2026-12345", modified="2026-10-18T05:00:00Z", state="PUBLISHED"):
    return {
        "dataType": "CVE_RECORD", "dataVersion": "5.2.0",
        "cveMetadata": {"cveId": native_id, "state": state, "datePublished": "2026-10-18T01:00:00Z", "dateUpdated": modified},
        "containers": {"cna": {"title": "Device vulnerability", "providerMetadata": {"shortName": "Vendor CNA"}, "descriptions": [{"lang": "en", "value": "Native vulnerability description"}], "rejectedReasons": [{"lang": "en", "value": "Duplicate record"}], "metrics": [{"cvssV3_1": {"baseScore": 9.8}}], "references": [{"url": "https://vendor.example/advisory"}], "affected": [{"vendor": "Vendor display name", "product": "Device display name", "cpes": ["cpe:2.3:h:vendor:device:1.0:*:*:*:*:*:*:*"], "defaultStatus": "unaffected", "versions": [{"version": "1.0", "lessThan": "2.0", "versionType": "custom", "status": "affected", "changes": [{"at": "1.5", "status": "unaffected"}]}]}]}, "adp": [{"references": [{"url": "https://cve.example/reference"}]}]},
    }


class MemoryStore:
    def __init__(self, state=None, fail=False):
        self.state = copy.deepcopy(state or {})
        self.batches = []
        self.fail = fail

    def source_state(self, name):
        return copy.deepcopy(self.state)

    def update_source(self, name, **fields):
        self.state.update(fields)

    def ingest(self, batch):
        if self.fail:
            raise RuntimeError("Storage failed")
        self.batches.append(batch)
        return {"advisories": len(batch["advisories"])}


class FixtureHTTP:
    def __init__(self, paths):
        self.paths = paths
        self.errors = set()
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url in self.errors:
            raise RuntimeError("Unavailable")
        path = self.paths[url]
        return SimpleNamespace(path=path, digest=hashlib.sha256(path.read_bytes()).hexdigest(), changed=False, status=304, headers={})


class CVEParserTests(unittest.TestCase):
    def test_namespaced_identity_native_versions_and_cpe_identity(self):
        original = cve_record()
        parsed = parse_cve5(original)
        self.assertEqual(parsed["id"], "CVE5:CVE-2026-12345")
        self.assertEqual(parsed["aliases"], ["CVE-2026-12345"])
        self.assertEqual(parsed["source"], "cve_program")
        affected = parsed["affected"][0]
        self.assertEqual((affected["vendor"], affected["product"], affected["part"]), ("vendor", "device", "h"))
        self.assertEqual(affected["version"], "*")
        self.assertTrue(affected["version_unverified"])
        self.assertEqual(affected["cve_versions"], original["containers"]["cna"]["affected"][0]["versions"])
        self.assertEqual(affected["cve_default_status"], "unaffected")
        self.assertEqual(parsed["references"], ["https://vendor.example/advisory", "https://cve.example/reference"])
        self.assertEqual(parsed["severity"], 9.8)

    def test_free_text_product_is_retained_without_fabricated_cpe_match(self):
        original = cve_record()
        product = original["containers"]["cna"]["affected"][0]
        product.pop("cpes")
        parsed = parse_cve5(original)
        self.assertEqual(parsed["affected"], [])
        self.assertEqual(parsed["configurations"]["unverified_products"], [product])

    def test_unaffected_only_product_is_not_an_active_affected_row(self):
        original = cve_record()
        original["containers"]["cna"]["affected"][0]["versions"][0]["status"] = "unaffected"
        parsed = parse_cve5(original)
        self.assertEqual(parsed["affected"], [])
        self.assertEqual(parsed["configurations"]["containers"], original["containers"])

    def test_authoritative_rejected_record_keeps_reason_and_no_active_products(self):
        parsed = parse_cve5(cve_record(state="REJECTED"))
        self.assertTrue(parsed["rejected"])
        self.assertEqual(parsed["summary"], "Duplicate record")
        self.assertEqual(parsed["affected"], [])
        self.assertEqual(parsed["configurations"]["cve_state"], "REJECTED")

    def test_unsupported_schema_and_nonpublic_status_fail(self):
        for field, value in (("dataVersion", "4.0"), ("dataType", "unknown")):
            original = cve_record()
            original[field] = value
            with self.assertRaises(ValueError):
                parse_cve5(original)
        with self.assertRaises(ValueError):
            parse_cve5(cve_record(state="RESERVED"))

    def test_nvd_and_cve_program_provenance_coexist(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.db")
            store.ingest({"advisories": [{"id": "CVE-2026-12345", "source": "NVD", "title": "NVD row"}]})
            store.ingest({"advisories": [parse_cve5(cve_record())]})
            with store.connection() as connection:
                rows = connection.execute("SELECT id,canonical_id,source FROM advisories ORDER BY id").fetchall()
            self.assertEqual([tuple(row) for row in rows], [("CVE-2026-12345", "CVE-2026-12345", "NVD"), ("CVE5:CVE-2026-12345", "CVE-2026-12345", "cve_program")])


class CVECollectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.paths = {}
        self.asset_url = "https://github.com/CVEProject/cvelistV5/releases/download/cve_2026-10-18_0600Z/2026-10-18_delta_CVEs_at_0600Z.zip"

    def tearDown(self):
        self.temp.cleanup()

    def fixture(self, archive_records=(), raw_records=(), day="2026-10-18"):
        archive = self.folder / "delta.zip"
        with zipfile.ZipFile(archive, "w") as target:
            target.writestr("delta.json", json.dumps({"numberOfChanges": len(archive_records)}))
            for record in archive_records:
                native_id = record["cveMetadata"]["cveId"]
                target.writestr(f"cves/2026/12xxx/{native_id}.json", json.dumps(record))
        self.paths[self.asset_url] = archive
        manifest = {"tag_name": f"cve_{day}_0600Z", "assets": [{"name": f"{day}_all_CVEs_at_midnight.zip.zip", "size": 634802733, "browser_download_url": "https://github.com/baseline.zip.zip"}, {"name": f"{day}_delta_CVEs_at_0600Z.zip", "size": archive.stat().st_size, "browser_download_url": self.asset_url}]}
        manifest_path = self.folder / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        self.paths[RELEASE_URL] = manifest_path
        delta = {"fetchTime": f"{day}T06:44:00Z", "new": [], "updated": [], "error": []}
        for record in raw_records:
            native_id = record["cveMetadata"]["cveId"]
            delta["new"].append({"cveId": native_id, "dateUpdated": record["cveMetadata"]["dateUpdated"]})
            year, serial = native_id.split("-")[1:]
            path = self.folder / f"{native_id}.json"
            path.write_text(json.dumps(record))
            self.paths[f"{RAW_BASE}{year}/{serial[:-3]}xxx/{native_id}.json"] = path
        delta_path = self.folder / "latest-delta.json"
        delta_path.write_text(json.dumps(delta))
        self.paths[DELTA_URL] = delta_path
        return FixtureHTTP(self.paths)

    async def test_unchanged_archive_digest_with_pending_drains_without_loss(self):
        http = self.fixture([cve_record(f"CVE-2026-{number}") for number in (12345, 12346, 12347)])
        store = MemoryStore()
        first = await collect_cve_program({"cve_max_records": 1}, store, http)
        self.assertTrue(first["pending"])
        self.assertEqual(first["coverage_floor"], "2026-10-18T00:00:00+00:00")
        self.assertIsNone(first["coverage_through"])
        await collect_cve_program({"cve_max_records": 1}, store, http)
        third = await collect_cve_program({"cve_max_records": 1}, store, http)
        self.assertFalse(third["pending"])
        self.assertEqual(third["coverage_through"], "2026-10-18T06:00:00+00:00")
        self.assertFalse(third["history_complete"])
        ids = [row["id"] for batch in store.batches for row in batch["advisories"]]
        self.assertEqual(ids, ["CVE5:CVE-2026-12345", "CVE5:CVE-2026-12346", "CVE5:CVE-2026-12347"])
        self.assertFalse(any(url.endswith("baseline.zip.zip") for url, _ in http.calls))

    async def test_raw_latest_batch_priority_and_duplicate_archive_record(self):
        raw = cve_record("CVE-2026-12345", "2026-10-18T06:40:00Z")
        http = self.fixture([cve_record("CVE-2026-12345"), cve_record("CVE-2026-12346")], [raw])
        store = MemoryStore()
        first = await collect_cve_program({"cve_max_records": 1}, store, http)
        self.assertTrue(first["pending"])
        self.assertEqual(store.batches[0]["advisories"][0]["modified"], raw["cveMetadata"]["dateUpdated"])
        second = await collect_cve_program({"cve_max_records": 1}, store, http)
        self.assertFalse(second["pending"])
        self.assertEqual(store.batches[1]["advisories"][0]["id"], "CVE5:CVE-2026-12346")

    async def test_manifest_failure_returns_raw_batch_and_explicit_gap(self):
        http = self.fixture(raw_records=[cve_record()])
        http.errors.add(RELEASE_URL)
        store = MemoryStore()
        result = await collect_cve_program({}, store, http)
        self.assertEqual(result["records"], 1)
        self.assertIn("Release manifest unavailable", result["gap"])
        self.assertIsNone(result["coverage_through"])
        self.assertEqual(result["coverage_floor"], "2026-10-18T06:44:00Z")

    async def test_oversize_archive_is_not_downloaded(self):
        http = self.fixture(raw_records=[cve_record()])
        manifest = json.loads(self.paths[RELEASE_URL].read_text())
        manifest["assets"][1]["size"] = 20 * 1024 * 1024
        self.paths[RELEASE_URL].write_text(json.dumps(manifest))
        result = await collect_cve_program({}, MemoryStore(), http)
        self.assertIn("archive size limit", result["gap"])
        self.assertNotIn(self.asset_url, [url for url, _ in http.calls])

    async def test_ingestion_failure_does_not_advance_state(self):
        http = self.fixture([cve_record()])
        state = {"seen_day": "2026-10-18", "seen_records": {}}
        store = MemoryStore(state, fail=True)
        with self.assertRaisesRegex(RuntimeError, "Storage failed"):
            await collect_cve_program({}, store, http)
        self.assertEqual(store.state, state)

    async def test_daily_rollover_records_unfilled_history_interval(self):
        http = self.fixture([cve_record()], day="2026-10-18")
        store = MemoryStore({"seen_day": "2026-10-17", "coverage_floor": "2026-10-17T00:00:00Z", "coverage_through": "2026-10-17T23:00:00Z", "seen_records": {}})
        result = await collect_cve_program({}, store, http)
        self.assertIn("Unverified rollover interval", result["gap"])
        self.assertIn("2026-10-17T23:00:00Z", result["gap"])

    async def test_changed_release_reuses_seen_record_hashes(self):
        original = cve_record()
        http = self.fixture([original])
        store = MemoryStore()
        await collect_cve_program({}, store, http)
        http = self.fixture([original, cve_record("CVE-2026-12346")])
        result = await collect_cve_program({}, store, http)
        self.assertEqual(result["records"], 1)
        self.assertEqual(store.batches[-1]["advisories"][0]["id"], "CVE5:CVE-2026-12346")
