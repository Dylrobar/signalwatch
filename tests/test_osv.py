import copy
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

from signalwatch.osv import DATA_URL, INDEX_URL, collect_osv, parse_osv, select_changes
from signalwatch.store import Store


def record(record_id="OSV-2026-1", modified="2026-10-17T00:00:00Z"):
    return {
        "id": record_id, "modified": modified, "published": "2026-10-01T00:00:00Z",
        "aliases": ["CVE-2026-12345", "GHSA-aaaa-bbbb-cccc"], "summary": "Package vulnerability",
        "details": "Affected package details", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "references": [{"type": "ADVISORY", "url": "https://vendor.example/advisory"}],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "example-package", "purl": "pkg:pypi/example-package"}, "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}, {"type": "GIT", "repo": "https://github.com/example/project", "events": [{"introduced": "a" * 40}, {"fixed": "b" * 40}]}], "versions": ["1.1.0", "1.2.0"]}],
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
    def __init__(self, paths, failures=()):
        self.paths = paths
        self.failures = set(failures)
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(url)
        if url in self.failures:
            raise RuntimeError("Download failed")
        return SimpleNamespace(path=self.paths[url], changed=False, status=304, headers={})


class RangedFixtureHTTP(FixtureHTTP):
    def __init__(self, paths, folder, max_chunk=95):
        super().__init__(paths)
        self.folder = folder
        self.max_chunk = max_chunk
        self.etag = '"snapshot-1"'
        self.ranges = []
        self.bytes_received = 0

    async def get(self, url, **kwargs):
        if url != INDEX_URL:
            return await super().get(url, **kwargs)
        self.calls.append(url)
        headers = kwargs["headers"]
        if headers.get("If-Match", self.etag) != self.etag:
            raise RuntimeError("Index snapshot changed")
        start = int(headers["Range"].split("=", 1)[1].split("-", 1)[0])
        requested_end = int(headers["Range"].rsplit("-", 1)[1]) + 1
        data = self.paths[url].read_bytes()
        end = min(len(data), start + self.max_chunk, requested_end)
        self.ranges.append(start)
        self.bytes_received += end - start
        path = self.folder / f"range-{len(self.ranges)}"
        path.write_bytes(data[start:end])
        return SimpleNamespace(path=path, changed=True, status=206, headers={"ETag": self.etag, "Content-Range": f"bytes {start}-{end - 1}/{len(data)}"})


class OSVParsingTests(unittest.TestCase):
    def test_preserves_package_identity_aliases_ranges_and_evidence(self):
        original = record()
        batch = parse_osv(original)
        advisory = batch["advisories"][0]
        affected = advisory["affected"][0]
        self.assertEqual(affected["ecosystem"], "PyPI")
        self.assertEqual(affected["package"], "example-package")
        self.assertEqual(affected["purl"], "pkg:pypi/example-package")
        self.assertEqual(affected["ranges"], original["affected"][0]["ranges"])
        self.assertEqual(advisory["configurations"]["osv_affected"], original["affected"])
        self.assertEqual(advisory["id"], "OSV:" + original["id"])
        self.assertEqual(advisory["aliases"], [original["id"], *original["aliases"]])
        self.assertNotIn("vendor", affected)
        self.assertNotIn("criteria", affected)
        self.assertEqual(advisory["references"], ["https://vendor.example/advisory"])
        self.assertIsNone(advisory["severity"])

    def test_withdrawal_clears_active_affected_and_retains_original(self):
        original = record()
        original["withdrawn"] = "2026-10-18T00:00:00Z"
        batch = parse_osv(original)
        advisory = batch["advisories"][0]
        self.assertEqual(advisory["status"], "withdrawn")
        self.assertTrue(advisory["rejected"])
        self.assertEqual(advisory["affected"], [])
        self.assertEqual(advisory["configurations"]["osv_affected"], original["affected"])
        self.assertEqual(batch["edges"], [])

    def test_numeric_cvss_is_bounded_and_vectors_are_not_numbers(self):
        original = record()
        original["severity"].extend([{"type": "CVSS_V3", "score": "9.8"}, {"type": "CVSS_V3", "score": 100}, {"type": "CVSS_V3", "score": "NaN"}, {"type": "CVSS_V4", "score": True}])
        self.assertEqual(parse_osv(original)["advisories"][0]["severity"], 9.8)

    def test_unsorted_change_index_does_not_appear_complete(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "changes.csv"
            path.write_text("2026-10-16T00:00:00Z,PyPI/OSV-1\n2026-10-17T00:00:00Z,PyPI/OSV-2\n")
            cursor = {"upper": "2026-10-18T00:00:00Z", "lower": "2026-10-01T00:00:00Z", "before": "2026-10-18T00:00:00Z", "seen": []}
            with self.assertRaisesRegex(ValueError, "reverse chronological"):
                select_changes(path, cursor, 10)

    def test_store_creates_package_evidence_and_preserves_source_rows(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "signalwatch.db")
            store.ingest({"advisories": [{"id": "CVE-2026-12345", "source": "nvd", "title": "NVD", "affected": [{"vendor": "example-vendor", "product": "example-product"}]}]})
            store.ingest(parse_osv(record("CVE-2026-12345")))
            with store.connection() as connection:
                rows = connection.execute("SELECT id,source FROM advisories ORDER BY id").fetchall()
                package = connection.execute("SELECT id,metadata FROM entities WHERE kind='package'").fetchone()
                edge = connection.execute("SELECT relation FROM edges WHERE from_id=? AND to_id=?", (package["id"], "CVE-2026-12345")).fetchone()
            self.assertEqual([tuple(row) for row in rows], [("CVE-2026-12345", "nvd"), ("OSV:CVE-2026-12345", "osv")])
            self.assertEqual(json.loads(package["metadata"])["purl"], "pkg:pypi/example-package")
            self.assertEqual(edge["relation"], "affected_by")


class OSVCollectionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.cursor = {"upper": "2026-10-18T00:00:00Z", "lower": "2026-10-15T00:00:00Z", "before": "2026-10-18T00:00:00Z", "seen": []}
        self.paths = {}

    def tearDown(self):
        self.temp.cleanup()

    def fixtures(self, rows):
        path = self.folder / "index.csv"
        path.write_text("".join(f"{modified},PyPI/{record_id}\n" for modified, record_id in rows))
        self.paths[INDEX_URL] = path
        for modified, record_id in rows:
            target = self.folder / f"{record_id}.json"
            target.write_text(json.dumps(record(record_id, modified)))
            self.paths[DATA_URL + f"PyPI/{record_id}.json"] = target
        return FixtureHTTP(self.paths)

    async def test_capped_equal_timestamps_resume_without_losing_records(self):
        http = self.fixtures([("2026-10-17T00:00:00Z", "OSV-A"), ("2026-10-17T00:00:00Z", "OSV-B"), ("2026-10-17T00:00:00Z", "OSV-C"), ("2026-10-16T00:00:00Z", "OSV-D")])
        store = MemoryStore({"watermark": "2026-10-15T00:00:00Z", "cursor": self.cursor})
        config = {"osv_max_records": 2, "concurrency": 2}
        first = await collect_osv(config, store, http)
        self.assertTrue(first["pending"])
        self.assertEqual(store.state["watermark"], "2026-10-15T00:00:00Z")
        self.assertEqual(store.state["cursor"]["seen"], ["PyPI/OSV-A", "PyPI/OSV-B"])
        second = await collect_osv(config, store, http)
        self.assertFalse(second["pending"])
        self.assertIsNone(store.state["cursor"])
        self.assertEqual(store.state["watermark"], self.cursor["upper"])
        self.assertEqual([item["id"] for batch in store.batches for item in batch["advisories"]], ["OSV:OSV-A", "OSV:OSV-B", "OSV:OSV-C", "OSV:OSV-D"])

    async def test_new_arrivals_wait_for_next_cycle_without_dropping_backlog(self):
        http = self.fixtures([("2026-10-17T00:00:00Z", "OSV-A"), ("2026-10-16T00:00:00Z", "OSV-B")])
        store = MemoryStore({"cursor": self.cursor})
        config = {"osv_max_records": 1, "concurrency": 2}
        await collect_osv(config, store, http)
        http = self.fixtures([("2026-10-18T01:00:00Z", "OSV-NEW"), ("2026-10-17T00:00:00Z", "OSV-A"), ("2026-10-16T00:00:00Z", "OSV-B")])
        await collect_osv(config, store, http)
        self.assertEqual([batch["advisories"][0]["id"] for batch in store.batches], ["OSV:OSV-A", "OSV:OSV-B"])
        result = await collect_osv({**config, "osv_max_records": 10}, store, http)
        self.assertFalse(result["pending"])
        self.assertEqual(store.batches[-1]["advisories"][0]["id"], "OSV:OSV-NEW")

    async def test_download_or_ingestion_failure_does_not_advance_checkpoint(self):
        http = self.fixtures([("2026-10-17T00:00:00Z", "OSV-A")])
        state = {"watermark": "2026-10-15T00:00:00Z", "cursor": self.cursor}
        store = MemoryStore(state)
        http.failures.add(DATA_URL + "PyPI/OSV-A.json")
        with self.assertRaisesRegex(RuntimeError, "Download failed"):
            await collect_osv({}, store, http)
        self.assertEqual(store.state, state)
        self.assertEqual(store.batches, [])
        http.failures.clear()
        store.fail = True
        with self.assertRaisesRegex(RuntimeError, "Storage failed"):
            await collect_osv({}, store, http)
        self.assertEqual(store.state, state)

    async def test_bootstrap_window_skips_old_records_and_records_304_payload(self):
        current = datetime.now(timezone.utc)
        recent = (current - timedelta(days=1)).isoformat()
        old = (current - timedelta(days=60)).isoformat()
        http = self.fixtures([(recent, "OSV-RECENT"), (old, "OSV-OLD")])
        store = MemoryStore()
        result = await collect_osv({"bootstrap_days": 30}, store, http)
        self.assertEqual(result["records"], 1)
        self.assertEqual(store.batches[0]["advisories"][0]["id"], "OSV:OSV-RECENT")
        self.assertNotIn(DATA_URL + "PyPI/OSV-OLD.json", http.calls)

    async def test_index_id_mismatch_does_not_advance_checkpoint(self):
        http = self.fixtures([("2026-10-17T00:00:00Z", "OSV-A")])
        self.paths[DATA_URL + "PyPI/OSV-A.json"].write_text(json.dumps(record("OSV-WRONG")))
        store = MemoryStore({"cursor": self.cursor})
        state = copy.deepcopy(store.state)
        with self.assertRaisesRegex(ValueError, "id differs"):
            await collect_osv({}, store, http)
        self.assertEqual(store.state, state)

    async def test_partial_range_eof_and_split_line_resume_at_byte_boundary(self):
        self.fixtures([("2026-10-17T00:00:00Z", "OSV-A"), ("2026-10-17T00:00:00Z", "OSV-B"), ("2026-10-16T00:00:00Z", "OSV-C"), ("2026-10-16T00:00:00Z", "OSV-D")])
        http = RangedFixtureHTTP(self.paths, self.folder)
        store = MemoryStore({"cursor": self.cursor, "watermark": "2026-10-15T00:00:00Z"})
        config = {"osv_max_records": 10, "osv_index_chunks": 1}
        first = await collect_osv(config, store, http)
        self.assertTrue(first["pending"])
        self.assertEqual(store.state["watermark"], "2026-10-15T00:00:00Z")
        self.assertEqual(store.state["cursor"]["index_etag"], '"snapshot-1"')
        self.assertGreater(store.state["cursor"]["index_offset"], 0)
        for _ in range(5):
            result = await collect_osv(config, store, http)
            if not result["pending"]:
                break
        self.assertFalse(result["pending"])
        ids = [item["id"] for batch in store.batches for item in batch["advisories"]]
        self.assertEqual(ids, ["OSV:OSV-A", "OSV:OSV-B", "OSV:OSV-C", "OSV:OSV-D"])
        self.assertTrue(any(offset > 0 for offset in http.ranges))

    async def test_changed_index_etag_rescans_timestamp_cursor(self):
        self.fixtures([("2026-10-17T00:00:00Z", "OSV-A"), ("2026-10-16T00:00:00Z", "OSV-B")])
        http = RangedFixtureHTTP(self.paths, self.folder, max_chunk=300)
        store = MemoryStore({"cursor": self.cursor})
        config = {"osv_max_records": 1}
        await collect_osv(config, store, http)
        self.fixtures([("2026-10-18T01:00:00Z", "OSV-NEW"), ("2026-10-17T00:00:00Z", "OSV-A"), ("2026-10-16T00:00:00Z", "OSV-B")])
        http.etag = '"snapshot-2"'
        result = await collect_osv(config, store, http)
        self.assertFalse(result["pending"])
        ids = [item["id"] for batch in store.batches for item in batch["advisories"]]
        self.assertEqual(ids, ["OSV:OSV-A", "OSV:OSV-B"])

    async def test_changing_index_revision_seeks_past_prefix_larger_than_scan_budget(self):
        self.fixtures([("2026-10-09T00:00:00Z", "OSV-A"), ("2026-10-09T00:00:00Z", "OSV-B"), ("2026-10-08T00:00:00Z", "OSV-C")])
        http = RangedFixtureHTTP(self.paths, self.folder, max_chunk=1024 * 1024)
        cursor = {**self.cursor, "lower": "2026-10-01T00:00:00Z", "before": "2026-10-10T00:00:00Z"}
        store = MemoryStore({"cursor": cursor})
        suffix = self.paths[INDEX_URL].read_text()
        for cycle in range(3):
            prefix = "2026-10-18T01:00:00Z,PyPI/NEW-RECORD-1234567890\n" * (30000 + cycle * 1000)
            self.paths[INDEX_URL].write_text(prefix + suffix)
            http.etag = f'"snapshot-{cycle + 1}"'
            result = await collect_osv({"osv_max_records": 1, "osv_index_chunks": 1}, store, http)
            self.assertEqual(result["records"], 1)
        ids = [item["id"] for batch in store.batches for item in batch["advisories"]]
        self.assertEqual(ids, ["OSV:OSV-A", "OSV:OSV-B", "OSV:OSV-C"])
        self.assertLess(http.bytes_received, 7 * 1024 * 1024)

    async def test_index_newer_than_pending_window_completes_without_requesting_past_eof(self):
        self.fixtures([("2026-10-19T00:00:00Z", "OSV-NEW")])
        http = RangedFixtureHTTP(self.paths, self.folder)
        store = MemoryStore({"cursor": self.cursor})
        result = await collect_osv({"osv_index_chunks": 1}, store, http)
        self.assertFalse(result["pending"])
        self.assertEqual(result["records"], 0)
        self.assertIsNone(store.state["cursor"])
        self.assertEqual(http.ranges, [0])

    async def test_revision_change_during_timestamp_seek_keeps_checkpoint(self):
        self.fixtures([("2026-10-09T00:00:00Z", "OSV-A")])
        prefix = "2026-10-18T01:00:00Z,PyPI/NEW-RECORD-1234567890\n" * 30000
        self.paths[INDEX_URL].write_text(prefix + self.paths[INDEX_URL].read_text())
        http = RangedFixtureHTTP(self.paths, self.folder, max_chunk=1024 * 1024)
        original_get = http.get

        async def changing_get(url, **kwargs):
            if http.ranges:
                http.etag = '"snapshot-2"'
            return await original_get(url, **kwargs)

        http.get = changing_get
        store = MemoryStore({"cursor": {**self.cursor, "lower": "2026-10-01T00:00:00Z", "before": "2026-10-10T00:00:00Z"}})
        original_state = copy.deepcopy(store.state)
        with self.assertRaisesRegex(RuntimeError, "snapshot changed"):
            await collect_osv({"osv_index_chunks": 1}, store, http)
        self.assertEqual(store.state, original_state)
        self.assertEqual(store.batches, [])

    async def test_equal_timestamp_replay_expands_bounded_scan_and_recovers(self):
        modified = "2026-10-17T00:00:00Z"
        self.fixtures([(modified, "OSV-A")])
        self.paths[INDEX_URL].write_text(f"{modified},PyPI/OSV-SEEN\n" * 40000 + self.paths[INDEX_URL].read_text())
        http = RangedFixtureHTTP(self.paths, self.folder, max_chunk=1024 * 1024)
        store = MemoryStore({"cursor": {**self.cursor, "before": modified, "seen": ["PyPI/OSV-SEEN"]}})
        config = {"osv_index_chunks": 1, "osv_index_max_chunks": 2}
        first = await collect_osv(config, store, http)
        self.assertEqual(first["no_progress_runs"], 1)
        self.assertEqual(first["records"], 0)
        self.assertEqual(first["index_chunks"], 1)
        http.etag = '"snapshot-2"'
        second = await collect_osv(config, store, http)
        self.assertEqual(second["records"], 1)
        self.assertEqual(second["index_chunks"], 2)
        self.assertFalse(second["pending"])
        self.assertEqual(second["no_progress_runs"], 0)
        self.assertEqual(store.state["no_progress_runs"], 0)

    async def test_equal_timestamp_replay_at_cap_reports_actionable_partial_error(self):
        modified = "2026-10-17T00:00:00Z"
        self.fixtures([(modified, "OSV-A")])
        self.paths[INDEX_URL].write_text(f"{modified},PyPI/OSV-SEEN\n" * 40000 + self.paths[INDEX_URL].read_text())
        http = RangedFixtureHTTP(self.paths, self.folder, max_chunk=1024 * 1024)
        store = MemoryStore({"cursor": {**self.cursor, "before": modified, "seen": ["PyPI/OSV-SEEN"]}, "watermark": "2026-10-15T00:00:00Z"})
        config = {"osv_index_chunks": 1, "osv_index_max_chunks": 1}
        for cycle in range(3):
            http.etag = f'"snapshot-{cycle + 1}"'
            result = await collect_osv(config, store, http)
        self.assertEqual(result["no_progress_runs"], 3)
        self.assertEqual(result["index_chunks"], 1)
        self.assertTrue(result["pending"])
        self.assertEqual(result["records"], 0)
        self.assertTrue(result["index_revision_changed"])
        self.assertIn("increase osv_index_max_chunks", result["errors"][0])
        self.assertEqual(store.state["watermark"], "2026-10-15T00:00:00Z")
