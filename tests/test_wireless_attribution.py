import asyncio
import csv
import io
import json
import sqlite3
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from signalwatch.store import Store
from signalwatch.wireless import device_id, normalize_wigle
from signalwatch.wireless_api import _sqlite_write
from signalwatch.wireless_attribution import company_wireless_summary, delete_facility, dense_scan_cells, device_company_links, enrich_manufacturers, fetch_business_facilities, import_device_enrichment, import_manufacturer_registry, import_osm_facilities, list_facilities, match_facilities, set_device_company, upsert_facility


class WirelessAttributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "wireless.db")
        self.company = self.store.save_company_profile(name="Company A", legal_name="Company A Holdings LLC")["id"]

    def observations(self, rows):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["MAC", "SSID", "Type", "CurrentLatitude", "CurrentLongitude", "AccuracyMeters", "MfgrId", "FirstSeen", "RSSI"])
        writer.writerows(rows)
        self.store.ingest(normalize_wigle({"payload": output.getvalue().encode(), "source": "private-export",
                                          "source_url": "https://user.example/export"}))

    def registry(self, prefix, name="Manufacturer", registry="MA-L"):
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Registry", "Assignment", "Organization Name", "Organization Address"])
        writer.writerow([registry, prefix, name, "Address"])
        return import_manufacturer_registry(self.store, output.getvalue(), registry, "https://standards-oui.ieee.org/registry.csv", "test-version")

    def links(self, identifier, radio_type="WIFI"):
        with self.store.connection() as conn:
            return device_company_links(conn, device_id(radio_type, identifier))

    def test_longest_ieee_prefix_only_wifi_no_random_mac_model_or_operator(self):
        self.observations([["00:11:22:33:44:55", "Office", "WIFI", 44, -73, 5, "", "", -50],
                           ["02:11:22:33:44:55", "Random", "WIFI", 44, -73, 5, "", "", -50],
                           ["00:11:22:33:44:55", "BLE", "BLE", 44, -73, 5, "", "", -50],
                           ["00:11:22:33:44:55", "BT", "BT", 44, -73, 5, "", "", -50],
                           ["00:11:22:33:44:ZZ", "Invalid", "WIFI", 44, -73, 5, "", "", -50]])
        self.registry("001122", "Broad assignee")
        self.registry("0011223", "Medium assignee", "MA-M")
        self.registry("001122334", "Specific assignee", "MA-S")
        self.registry("021122", "Must not infer")
        result = enrich_manufacturers(self.store)
        self.assertEqual(result["manufacturer_links"], 1)
        items = self.links("00:11:22:33:44:55")["items"]
        self.assertEqual([(row["company_name"], row["role"], row["status"]) for row in items], [("Specific assignee", "manufacturer", "assigned")])
        self.assertEqual(items[0]["evidence"]["prefix_bits"], 36)
        self.assertFalse(self.links("00:11:22:33:44:55")["operator_confirmed"])
        self.assertEqual(self.links("02:11:22:33:44:55")["items"], [])
        self.assertEqual(self.links("00:11:22:33:44:55", "BLE")["items"], [])
        self.assertEqual(self.links("00:11:22:33:44:55", "BT")["items"], [])

    def test_bluetooth_ids_are_observed_claims_and_conflicts_not_wifi_manufacturers(self):
        self.observations([["C2:11:22:33:44:55", "BLE", "BLE", 44, -73, 5, "0x004c", "", -50],
                           ["C2:11:22:33:44:55", "BLE", "BLE", 44, -73, 5, "6", "", -50],
                           ["00:11:22:33:44:55", "WiFi", "WIFI", 44, -73, 5, "76", "", -50]])
        result = import_manufacturer_registry(self.store, "company_identifiers:\n  - value: 0x004C\n    name: 'Apple, Inc.'\n  - value: 6\n    name: 'Microsoft'\n", "Bluetooth SIG", "https://www.bluetooth.com/assigned", "version")
        self.assertEqual(result["assignments"], 2)
        self.assertEqual(enrich_manufacturers(self.store)["advertised_provider_links"], 2)
        links = self.links("C2:11:22:33:44:55", "BLE")
        self.assertTrue(links["advertised_provider_conflict"])
        self.assertEqual({row["role"] for row in links["items"]}, {"advertised_provider"})
        self.assertFalse(links["operator_confirmed"])
        self.assertEqual(self.links("00:11:22:33:44:55")["items"], [])

    def test_registry_refresh_replaces_stale_automatic_links_but_keeps_manual(self):
        identifier = "00:11:22:33:44:55"
        self.observations([[identifier, "Office", "WIFI", 44, -73, 5, "", "", -50]])
        self.registry("001122", "Former assignee")
        enrich_manufacturers(self.store)
        set_device_company(self.store, device_id("WIFI", identifier), self.company, "confirmed", "Asset inventory", "https://user.example/inventory")
        self.registry("112233", "Other assignee")
        enrich_manufacturers(self.store)
        links = self.links(identifier)
        self.assertEqual([row["role"] for row in links["items"]], ["confirmed_operator"])
        self.assertTrue(links["operator_confirmed"])

    def test_multiple_ieee_assignees_for_same_prefix_remain_ambiguous(self):
        identifier = "08:00:30:33:44:55"
        self.observations([[identifier, "Legacy", "WIFI", 44, -73, 5, "", "", -50]])
        result = import_manufacturer_registry(self.store, "Assignment,Organization Name\n080030,First historical assignee\n080030,Second historical assignee\n", "MA-L", "https://standards-oui.ieee.org/oui/oui.csv")
        self.assertEqual(result["assignments"], 2)
        self.assertEqual(enrich_manufacturers(self.store)["manufacturer_links"], 2)
        links = self.links(identifier)
        self.assertTrue(links["manufacturer_assignment_conflict"])
        self.assertEqual({row["company_name"] for row in links["items"]}, {"First historical assignee", "Second historical assignee"})
        self.assertFalse(links["operator_confirmed"])

    def test_manufacturer_rebuild_scans_input_once_and_indexes_each_prefix_lookup(self):
        self.observations([["00:11:22:33:44:55", "WiFi", "WIFI", 44, -73, 5, "", "", -50],
                           ["C2:11:22:33:44:55", "BLE", "BLE", 44, -73, 5, "0x004c", "", -50]])
        self.registry("001122")
        import_manufacturer_registry(self.store, '[{"value":76,"name":"Assigned provider"}]', "Bluetooth SIG", "https://bluetooth.example/")
        statements = []
        original = self.store.connection
        @contextmanager
        def traced_connection(write=False):
            with original(write=write) as conn:
                conn.set_trace_callback(statements.append)
                yield conn
        with patch.object(self.store, "connection", traced_connection):
            enrich_manufacturers(self.store)
        inserts = [statement for statement in statements if "INSERT OR IGNORE INTO wireless_company_links" in statement]
        self.assertEqual(len(inserts), 5)
        with original() as conn:
            for statement in inserts:
                details = [row[3] for row in conn.execute("EXPLAIN QUERY PLAN " + statement)]
                input_alias = "d" if "FROM wireless_devices" in statement else "o"
                self.assertEqual(details[0], "SCAN " + input_alias)
                registry = next(detail for detail in details if detail.startswith("SEARCH r "))
                self.assertIn("wireless_manufacturer_assignment", registry)
                self.assertIn("bits=? AND prefix=?", registry)

    def test_scan_points_match_multiple_candidates_and_all_observed_locations(self):
        identifier = "00:11:22:33:44:55"
        self.observations([[identifier, "Office", "WIFI", 44, -73, 5, "", "2026-01-01 00:00:00", -50],
                           [identifier, "Office", "WIFI", 45, -74, 5, "", "2026-02-01 00:00:00", -50]])
        other = self.store.save_company_profile(name="Company B")["id"]
        first = upsert_facility(self.store, "Branch A", 44, -73, self.company, source_url="https://company.example/locations")
        upsert_facility(self.store, "Neighbor", 44.0001, -73, other, source_url="https://neighbor.example/")
        upsert_facility(self.store, "Branch B", 45, -74, self.company, source_url="https://company.example/locations")
        self.assertEqual(match_facilities(self.store)["candidate_links"], 3)
        links = self.links(identifier)
        self.assertEqual(len(links["items"]), 3)
        self.assertFalse(links["operator_confirmed"])
        self.assertEqual({row["status"] for row in links["items"]}, {"candidate"})
        self.assertEqual({row["role"] for row in links["items"]}, {"candidate_business"})
        self.assertTrue(all("device location and operator unverified" in row["evidence"]["basis"] for row in links["items"]))
        with self.store.connection() as conn:
            summary = company_wireless_summary(conn, self.company)
        self.assertEqual(summary["distinct_device_count"], 1)
        self.assertEqual(summary["counts_by_role"]["candidate_business"], 1)
        match_facilities(self.store)
        self.assertEqual(len(self.links(identifier)["items"]), 3)
        delete_facility(self.store, first["id"])
        self.assertEqual(len(self.links(identifier)["items"]), 2)

    def test_poor_accuracy_and_invalid_coordinates_never_become_facility_candidates(self):
        self.observations([["00:11:22:33:44:55", "Poor GPS", "WIFI", 44, -73, 7000, "", "", -50],
                           ["00:11:22:33:44:56", "Invalid GPS", "WIFI", "nan", -73, 5, "", "", -50],
                           ["00:11:22:33:44:57", "Near", "WIFI", 44.0011, -73, 30, "", "", -50]])
        upsert_facility(self.store, "Branch", 44, -73, self.company, source_url="https://company.example/")
        self.assertEqual(match_facilities(self.store, radius_meters=100)["candidate_links"], 1)
        self.assertEqual(self.links("00:11:22:33:44:55")["items"], [])
        self.assertEqual(self.links("00:11:22:33:44:56")["items"], [])
        self.assertEqual(self.links("00:11:22:33:44:57")["items"][0]["evidence"]["effective_radius_meters"], 130)

    def test_manual_rejection_preserved_after_match_and_excluded_from_company_rollup(self):
        identifier = "00:11:22:33:44:55"
        self.observations([[identifier, "Office", "WIFI", 44, -73, 5, "", "", -50]])
        upsert_facility(self.store, "Branch", 44, -73, self.company, source_url="https://company.example/")
        set_device_company(self.store, device_id("WIFI", identifier), self.company, "rejected", "Unrelated visitor hotspot", "https://user.example/review")
        match_facilities(self.store)
        match_facilities(self.store)
        items = self.links(identifier)["items"]
        self.assertEqual(len(items), 2)
        self.assertTrue(all(row["rejected_by_user"] for row in items))
        with self.store.connection() as conn:
            summary = company_wireless_summary(conn, self.company)
        self.assertEqual(summary["devices"], [])
        self.assertEqual(summary["counts_by_role"], {})
        self.assertEqual(summary["distinct_device_count"], 0)
        self.assertEqual(self.store.detail(self.company)["company_profile"]["legal_name"], "Company A Holdings LLC")

    def test_facility_update_invalidates_old_automatic_candidates_and_rtree(self):
        identifier = "00:11:22:33:44:55"
        self.observations([[identifier, "Office", "WIFI", 44, -73, 5, "", "", -50]])
        facility = upsert_facility(self.store, "Branch", 44, -73, self.company, source_url="https://company.example/")
        match_facilities(self.store)
        upsert_facility(self.store, "Moved", 46, -75, self.company, source_url="https://company.example/", facility_id=facility["id"])
        self.assertEqual(self.links(identifier)["items"], [])
        self.assertEqual(match_facilities(self.store)["candidate_links"], 0)
        self.assertEqual(list_facilities(self.store)["items"][0]["name"], "Moved")

    def test_osm_company_evidence_uses_brand_identity_without_altering_manual_profile(self):
        existing = "company:wikidata:Q123"
        self.store.ingest({"entities": [{"id": existing, "kind": "company", "name": "Source name"}]})
        self.store.save_company_profile(existing, "Reviewed brand", legal_name="Reviewed legal name", notes="Keep")
        data = {"elements": [{"type": "way", "id": 42, "center": {"lat": 44, "lon": -73},
                              "tags": {"name": "Branch", "shop": "supermarket", "brand": "Brand", "brand:wikidata": "Q123", "website": "https://brand.example/"}}]}
        self.assertEqual(import_osm_facilities(self.store, data)["imported"], 1)
        facility = list_facilities(self.store)["items"][0]
        self.assertEqual(facility["company_id"], existing)
        self.assertEqual(facility["location_basis"], "osm_feature_bbox_center")
        self.assertEqual(facility["evidence"]["attribution"], "OpenStreetMap contributors")
        profile = self.store.detail(existing)["company_profile"]
        self.assertEqual((profile["name"], profile["legal_name"], profile["notes"]), ("Reviewed brand", "Reviewed legal name", "Keep"))

    def test_osm_named_business_can_create_company_but_never_legal_name(self):
        result = import_osm_facilities(self.store, {"elements": [{"type": "node", "id": 12, "lat": 44, "lon": -73,
            "tags": {"name": "Coffee place", "amenity": "cafe", "wikidata": "Q999"}},
            {"type": "node", "id": 13, "lat": 44, "lon": -73, "tags": {"name": "House", "building": "house"}}]})
        self.assertEqual(result["imported"], 1)
        facility = list_facilities(self.store)["items"][0]
        self.assertEqual(facility["company_id"], "company:osm:node:12")
        self.assertEqual(self.store.detail(facility["company_id"])["company_profile"]["legal_name"], "")

    def test_imported_atlas_labels_are_claims_and_never_operator_or_model_confirmation(self):
        identifier = "02:11:22:33:44:55"
        self.observations([[identifier, "Claimed hotspot", "WIFI", 44, -73, 5, "", "", -50]])
        result = import_device_enrichment(self.store, [{"identifier": identifier, "radio_type": "WIFI",
            "labels": {"vendor": "Old vendor", "model_hint": "Name-derived hint", "provider": "Advertised ISP"},
            "evidence": {"model": "SSID text"}}], "https://previous-site.example/", "original-version")
        self.assertEqual(result["matched_devices"], 1)
        links = self.links(identifier)
        self.assertEqual([(row["role"], row["status"]) for row in links["items"]], [("advertised_provider", "claimed")])
        self.assertFalse(links["operator_confirmed"])
        with self.store.connection() as conn:
            metadata = json.loads(conn.execute("SELECT metadata FROM wireless_devices").fetchone()[0])
        self.assertEqual(metadata["imported_enrichment"]["labels"]["model_hint"], "Name-derived hint")
        self.assertEqual(metadata["location_basis"], "scan_observation")

    def test_reimported_labels_replace_removed_provider_and_stale_fields(self):
        identifier = "02:11:22:33:44:55"
        self.observations([[identifier, "Claimed hotspot", "WIFI", 44, -73, 5, "", "", -50]])
        import_device_enrichment(self.store, [{"identifier": identifier, "radio_type": "WIFI",
            "labels": {"provider": "Old provider", "model_hint": "Old hint"}}], "https://previous-site.example/", "old")
        import_device_enrichment(self.store, [{"identifier": identifier, "radio_type": "WIFI",
            "labels": {"category": "Unknown"}}], "https://previous-site.example/", "new")
        self.assertEqual(self.links(identifier)["items"], [])
        with self.store.connection() as conn:
            metadata = json.loads(conn.execute("SELECT metadata FROM wireless_devices").fetchone()[0])
        self.assertEqual(metadata["imported_enrichment"]["labels"], {"category": "Unknown"})

    def test_dense_cells_and_match_cursor_are_bounded(self):
        self.observations([["00:11:22:33:44:55", "A", "WIFI", 44, -73, 5, "", "", -50],
                           ["00:11:22:33:44:56", "B", "WIFI", 44, -73, 5, "", "", -50]])
        cells = dense_scan_cells(self.store, min_devices=2, limit=1)
        self.assertEqual(len(cells), 1)
        self.assertEqual(cells[0]["devices"], 2)
        upsert_facility(self.store, "One", 44, -73, self.company, source_url="https://company.example/", facility_id="facility:1")
        upsert_facility(self.store, "Two", 44, -73, self.company, source_url="https://company.example/", facility_id="facility:2")
        first = match_facilities(self.store, facility_limit=1)
        self.assertTrue(first["has_more"])
        self.assertEqual(first["next_cursor"], "facility:1")
        self.assertFalse(match_facilities(self.store, facility_limit=1, after_facility_id=first["next_cursor"])["has_more"])

    def test_read_side_candidates_are_nearest_first_and_report_full_count(self):
        identifier = "00:11:22:33:44:55"
        self.observations([[identifier, "Office", "WIFI", 44, -73, 5, "", "", -50]])
        upsert_facility(self.store, "Far", 44.0005, -73, self.company, source_url="https://company.example/", facility_id="facility:a")
        upsert_facility(self.store, "Near", 44.0001, -73, self.company, source_url="https://company.example/", facility_id="facility:z")
        match_facilities(self.store)
        with self.store.connection() as conn:
            result = device_company_links(conn, device_id("WIFI", identifier), limit=1)
        self.assertEqual(result["items"][0]["facility_name"], "Near")
        self.assertEqual(result["items"][0]["distance_m"], result["items"][0]["evidence"]["distance_meters"])
        self.assertEqual(result["total"], 2)
        self.assertTrue(result["truncated"])

    def test_wal_reader_does_not_block_matching_and_facility_delete_is_indexed(self):
        identifier = "00:11:22:33:44:55"
        self.observations([[identifier, "Office", "WIFI", 44, -73, 5, "", "", -50]])
        upsert_facility(self.store, "Branch", 44, -73, self.company, source_url="https://company.example/")
        set_device_company(self.store, device_id("WIFI", identifier), self.company, "confirmed", "Inventory", "https://company.example/inventory")
        with self.store.connection() as reader:
            reader.execute("BEGIN")
            reader.execute("SELECT count(*) FROM wireless_company_links").fetchone()
            self.assertEqual(match_facilities(self.store)["candidate_links"], 1)
            plan = [row[3] for row in reader.execute("EXPLAIN QUERY PLAN DELETE FROM wireless_company_links WHERE facility_id=? AND origin='facility_proximity'", ("facility",))]
            self.assertTrue(any("wireless_facility_proximity" in detail for detail in plan))
        self.assertEqual({item["role"] for item in self.links(identifier)["items"]}, {"confirmed_operator", "candidate_business"})

    def test_sqlite_retry_recovers_from_a_real_competing_writer(self):
        attempts = []
        def write():
            attempts.append(1)
            conn = sqlite3.connect(self.store.path, timeout=0.001)
            try:
                conn.execute("BEGIN IMMEDIATE")
                conn.execute("UPDATE company_profiles SET notes='retried' WHERE company_id=?", (self.company,))
                conn.commit()
                return "committed"
            finally:
                conn.close()
        with self.store.connection(write=True) as writer:
            writer.execute("UPDATE company_profiles SET notes='held' WHERE company_id=?", (self.company,))
            async def release(delay):
                writer.commit()
            with patch("signalwatch.wireless_api.asyncio.sleep", side_effect=release) as sleep:
                self.assertEqual(asyncio.run(_sqlite_write(write)), "committed")
                sleep.assert_awaited_once_with(1)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(self.store.detail(self.company)["company_profile"]["notes"], "retried")

    def test_sqlite_retry_is_bounded_and_does_not_retry_other_operational_errors(self):
        busy = sqlite3.OperationalError("database is locked")
        busy.sqlite_errorcode = sqlite3.SQLITE_BUSY | (2 << 8)
        operation = Mock(side_effect=busy)
        with patch("signalwatch.wireless_api.asyncio.sleep", new_callable=AsyncMock) as sleep:
            with self.assertRaises(sqlite3.OperationalError):
                asyncio.run(_sqlite_write(operation))
            self.assertEqual(operation.call_count, 3)
            self.assertEqual([call.args[0] for call in sleep.await_args_list], [1, 2])
        invalid = Mock(side_effect=sqlite3.OperationalError("no such table: invalid"))
        with patch("signalwatch.wireless_api.asyncio.sleep", new_callable=AsyncMock) as sleep:
            with self.assertRaises(sqlite3.OperationalError):
                asyncio.run(_sqlite_write(invalid))
            self.assertEqual(invalid.call_count, 1)
            sleep.assert_not_awaited()

    def test_overpass_request_contains_only_bbox_and_business_tags(self):
        path = Path(self.temp.name) / "overpass.json"
        path.write_text('{"elements":[]}')
        calls = []
        class HTTP:
            async def post(self, url, **kwargs):
                calls.append((url, kwargs))
                return SimpleNamespace(path=path)
        result = asyncio.run(fetch_business_facilities(HTTP(), self.store, [44, -73, 44.02, -72.98]))
        self.assertEqual(result["imported"], 0)
        query = calls[0][1]["data"]["data"]
        self.assertIn("44.0,-73.0,44.02,-72.98", query)
        self.assertNotIn("MAC", query)
        self.assertNotIn("SSID", query)
        self.assertEqual(calls[0][1]["max_attempts"], 1)

    def test_validation_rejects_nonfinite_and_unbounded_spatial_work(self):
        for lat, lon in [(float("nan"), 0), (91, 0), (0, 181)]:
            with self.assertRaises(ValueError):
                upsert_facility(self.store, "Bad", lat, lon, source_url="https://example.com")
        for radius in [float("inf"), 0, 1001]:
            with self.assertRaises(ValueError):
                match_facilities(self.store, radius_meters=radius)
        with self.assertRaises(ValueError):
            asyncio.run(fetch_business_facilities(None, self.store, [-90, -180, 90, 180]))
        with self.assertRaises(ValueError):
            import_manufacturer_registry(self.store, "no assignments", "MA-L", "https://ieee.example/")
        with self.assertRaises(ValueError):
            import_manufacturer_registry(self.store, "Assignment,Organization Name\n00005E\n", "MA-L", "https://ieee.example/")
        with self.assertRaises(ValueError):
            import_manufacturer_registry(self.store, "[{}]", "Bluetooth SIG", "https://bluetooth.example/")
