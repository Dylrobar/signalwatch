import tempfile
import unittest
from pathlib import Path

from signalwatch.store import Store, digest, encode


class ObservationPartIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "inventory.sqlite3"
        self.store = Store(self.path)

    def observation(self, **changes):
        return {
            "asset_id": "asset:gateway", "vendor": "acme", "product": "gateway",
            "part": "a", "version": "1.0", "origin": "imported",
            "source_url": "https://inventory.example.test/gateway",
            "observed_at": "2026-10-01T00:00:00Z", **changes,
        }

    def rows(self):
        with self.store.connection() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM observations ORDER BY part")]

    def install_legacy_id(self, observation):
        self.store.ingest({"observations": [observation]})
        legacy = digest(encode([observation[key] for key in
                                ("asset_id", "vendor", "product", "source_url", "origin")]))
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE observations SET id=? WHERE part=?", (legacy, observation["part"]))
        return legacy

    def test_parts_coexist_for_imported_web_and_nmap_evidence(self):
        for origin in ("imported", "web", "nmap"):
            with self.subTest(origin=origin):
                records = [self.observation(origin=origin, part=part) for part in ("a", "h", "o")]
                self.store.ingest({"observations": records})
                self.store.ingest({"observations": records})
                selected = [row for row in self.rows() if row["origin"] == origin]
                self.assertEqual([row["part"] for row in selected], ["a", "h", "o"])
        self.assertEqual(len(self.rows()), 9)

    def test_hardware_refresh_does_not_remove_software_exposure(self):
        self.store.ingest({
            "observations": [self.observation()],
            "advisories": [{"id": "CVE-2026-12345", "affected": [
                {"vendor": "acme", "product": "gateway", "part": "a", "version": "1.0"},
            ]}],
        })
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        self.store.ingest({"observations": [self.observation(part="h", version="2.0")]})
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        self.assertEqual(self.store.alerts()["items"][0]["version"], "1.0")
        self.assertEqual(len(self.rows()), 2)

    def test_legacy_part_survives_other_part_then_migrates_on_its_own_refresh(self):
        for legacy_part, incoming_part in (("h", "a"), ("a", "h")):
            with self.subTest(legacy_part=legacy_part):
                self.store = Store(Path(self.temp.name) / (legacy_part + ".sqlite3"))
                original = self.observation(part=legacy_part)
                legacy = self.install_legacy_id(original)
                self.store = Store(self.store.path)
                other = self.observation(part=incoming_part, version="2.0")
                self.store.ingest({"observations": [other]})
                self.assertEqual(len(self.rows()), 2)
                self.assertIn(legacy, {row["id"] for row in self.rows()})
                refreshed = {**original, "version": "3.0"}
                self.store.ingest({"observations": [refreshed]})
                self.assertEqual(len(self.rows()), 2)
                self.assertNotIn(legacy, {row["id"] for row in self.rows()})
                self.assertEqual({row["part"]: row["version"] for row in self.rows()},
                                 {legacy_part: "3.0", incoming_part: "2.0"})
                self.store = Store(self.store.path)
                self.store.ingest({"observations": [other, refreshed]})
                self.assertEqual(len(self.rows()), 2)

    def test_matching_legacy_and_new_rows_collapse_to_the_refresh(self):
        original = self.observation()
        legacy = self.install_legacy_id(original)
        with self.store.connection(write=True) as conn:
            columns = [row[1] for row in conn.execute("PRAGMA table_info(observations)")]
            old = dict(conn.execute("SELECT * FROM observations").fetchone())
            old["id"] = digest(encode([original[key] for key in
                                       ("asset_id", "vendor", "product", "source_url", "origin", "part")]))
            conn.execute("INSERT INTO observations(" + ",".join(columns) + ") VALUES(" +
                         ",".join("?" for _ in columns) + ")", [old[key] for key in columns])
        self.assertEqual(len(self.rows()), 2)
        self.store.ingest({"observations": [self.observation(version="3.0")]})
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertNotEqual(rows[0]["id"], legacy)
        self.assertEqual(rows[0]["version"], "3.0")

    def test_legacy_migration_rolls_back_with_failed_ingest(self):
        legacy = self.install_legacy_id(self.observation())
        with self.assertRaises(KeyError):
            self.store.ingest({"observations": [self.observation(version="2.0")], "articles": [{}]})
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], legacy)
        self.assertEqual(rows[0]["version"], "1.0")

    def test_sbom_identity_and_multiple_versions_remain_unchanged(self):
        record = self.observation(origin="sbom:gateway", part="h")
        expected = digest(encode([record[key] for key in
                                  ("asset_id", "vendor", "product", "source_url", "origin", "part", "version")]))
        self.store.ingest({"observations": [record, {**record, "version": "2.0"}]})
        self.store.ingest({"observations": [record]})
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertIn(expected, {row["id"] for row in rows})


if __name__ == "__main__":
    unittest.main()
