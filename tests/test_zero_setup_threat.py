import copy
import hashlib
import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from signalwatch.config import DEFAULTS
from signalwatch.extension_threat import MISP_ROOT, collect_threat_sources, normalize_threat
from signalwatch.http import HTTPError
from signalwatch.ingestion import StagingWorker
from signalwatch.normalization import NormalizationError
from signalwatch.staging import StagingQueue
from signalwatch.store import Store


FIXTURES = Path(__file__).parent / "fixtures" / "threat_zero_setup"
STAMP = "2026-10-19T06:00:00+00:00"
EVENT = json.loads((FIXTURES / "event.json").read_text())
UUID = EVENT["Event"]["uuid"]


def staged(provider, value, **metadata):
    payload = value if isinstance(value, bytes) else json.dumps(value).encode()
    return {"id": 1, "source": "public:" + provider, "source_url": MISP_ROOT + UUID + ".json", "stream_key": provider,
            "adapter": "public_source", "content_type": "application/json", "payload": payload,
            "payload_hash": hashlib.sha256(payload).hexdigest(), "received_at": STAMP, "observed_at": STAMP,
            "metadata": {"provider": provider, "watch_products": ["nginx"], "exploit_keywords": ["patch", "exploit"], **metadata}}


class ZeroSetupThreatNormalizationTests(unittest.TestCase):
    def test_misp_manifest_validates_without_becoming_news_or_indicators(self):
        batch = normalize_threat(staged("circl_misp", (FIXTURES / "manifest.json").read_bytes(), format="misp_manifest"))
        self.assertFalse(any(batch.values()))
        for payload in (b"<html>Authentication required</html>", b'{"error":"denied"}', b'{"../escape":{"timestamp":1}}'):
            with self.subTest(payload=payload), self.assertRaises(NormalizationError):
                normalize_threat(staged("circl_misp", payload, format="misp_manifest"))

    def test_misp_retains_attributed_report_tags_dates_and_literal_cves(self):
        batch = normalize_threat(staged("circl_misp", EVENT, format="misp_event", event_uuid=UUID))
        report = batch["entities"][0]
        self.assertEqual(report["metadata"]["organization"]["name"], "Public Researcher")
        self.assertEqual(report["metadata"]["tlp"], ["tlp:clear"])
        self.assertEqual(report["metadata"]["published"], "2026-10-16")
        self.assertTrue(report["metadata"]["modified"].startswith("2026-10-16"))
        self.assertIn("Exploit status unverified", report["metadata"]["reports"][0]["content"])
        self.assertEqual(batch["articles"][0]["cves"], ["CVE-2026-12345"])
        self.assertTrue(batch["articles"][0]["_signal"]["qualified"])
        self.assertEqual(report["metadata"]["staging"]["raw_reference"], "staging:1")
        self.assertFalse(report["metadata"]["ownership_verified"])
        self.assertFalse(report["metadata"]["exploit_verified"])
        self.assertFalse(batch.get("advisories"))
        self.assertFalse(batch.get("observations"))
        self.assertFalse(batch.get("kev"))

    def test_encoded_attachments_never_enter_evidence_projection(self):
        batch = normalize_threat(staged("circl_misp", EVENT, format="misp_event"))
        encoded = json.dumps(batch)
        self.assertNotIn("ATTACHMENT_BODY_MUST_NOT_PROJECT", encoded)
        self.assertNotIn("sample.bin", encoded)
        self.assertNotIn("analysis.zip", encoded)
        indicators = [row for row in batch["entities"] if row["kind"] == "threat_indicator"]
        self.assertEqual(len(indicators), 4)
        self.assertEqual({row["value"] for row in indicators}, {"8.8.8.8", "https://indicator.example/payload", "a" * 64, "example.net"})
        dns = next(row for row in indicators if row["value"] == "8.8.8.8")
        self.assertFalse(dns["metadata"]["to_ids"])
        self.assertEqual(dns["metadata"]["record_type"], "reported_observable")
        self.assertNotIn("classification", dns["metadata"])
        self.assertTrue(batch["entities"][0]["metadata"]["raw_feed_may_contain_encoded_attachments"])

    def test_misp_budgets_count_articles_entities_and_edges(self):
        for maximum in (1, 2, 3, 5, 10):
            with self.subTest(maximum=maximum):
                batch = normalize_threat(staged("circl_misp", EVENT), max_records=maximum)
                self.assertLessEqual(sum(len(rows) for rows in batch.values()), maximum)
        batch = normalize_threat(staged("circl_misp", EVENT, record_limit=1))
        self.assertEqual(sum(row["kind"] == "threat_indicator" for row in batch["entities"]), 1)
        self.assertTrue(batch["entities"][0]["metadata"]["projection_clipped"])

    def test_misp_rejects_wrong_uuid_unpublished_and_invalid_arrays(self):
        for change in ({"uuid": "../../bad"}, {"published": False}, {"Attribute": {"data": "bad"}}, {"info": ""}):
            value = copy.deepcopy(EVENT)
            value["Event"].update(change)
            with self.subTest(change=change), self.assertRaises(NormalizationError):
                normalize_threat(staged("circl_misp", value))
        with self.assertRaises(NormalizationError):
            normalize_threat(staged("circl_misp", EVENT, event_uuid="00000000-0000-0000-0000-000000000000"))

    def test_invalid_deleted_and_unsupported_indicators_are_not_invented(self):
        value = copy.deepcopy(EVENT)
        value["Event"]["Object"] = []
        value["Event"]["Attribute"] = [
            {"type": "ip-dst", "value": "not-an-ip"}, {"type": "domain", "value": "bad/name"},
            {"type": "url", "value": "http://[invalid"}, {"type": "url", "value": "file:///etc/passwd"},
            {"type": "url", "value": "https://user:secret@example.net/"}, {"type": "sha256", "value": "a" * 63},
            {"type": "text", "value": "CVE-2026-99999"}, {"type": "domain", "value": "deleted.example", "deleted": "1"},
            {"type": "domain", "value": "valid.example"}, {"type": "domain", "value": "valid.example"}]
        batch = normalize_threat(staged("circl_misp", value))
        indicators = [row for row in batch["entities"] if row["kind"] == "threat_indicator"]
        self.assertEqual([row["value"] for row in indicators], ["valid.example"])
        self.assertNotIn("CVE-2026-99999", json.dumps(batch))

    def test_deleted_parent_objects_exclude_observables_and_cves_but_preserve_siblings(self):
        for deleted in (True, 1, "1"):
            with self.subTest(deleted=deleted):
                value = copy.deepcopy(EVENT)
                value["Event"]["Attribute"] = []
                value["Event"]["Object"] = [
                    {"deleted": deleted, "Attribute": [
                        {"type": "domain", "value": "deleted.example", "deleted": False},
                        {"type": "vulnerability", "value": "CVE-2026-99999", "deleted": False}]},
                    {"Attribute": [{"type": "domain", "value": "active.example"}]},
                    {"deleted": False, "Attribute": [{"type": "domain", "value": "false.example"}]},
                    {"deleted": 0, "Attribute": [{"type": "domain", "value": "zero.example"}]},
                    {"deleted": "0", "Attribute": [{"type": "domain", "value": "string-zero.example"}]}]
                batch = normalize_threat(staged("circl_misp", value))
                indicators = [row for row in batch["entities"] if row["kind"] == "threat_indicator"]
                self.assertEqual({row["value"] for row in indicators},
                                 {"active.example", "false.example", "zero.example", "string-zero.example"})
                edges = [row for row in batch["edges"] if row["relation"] == "reports_observable"]
                self.assertEqual({row["to_id"] for row in edges}, {row["id"] for row in indicators})
                self.assertNotIn("deleted.example", json.dumps(batch))
                self.assertNotIn("CVE-2026-99999", json.dumps(batch))
                self.assertEqual(batch["entities"][0]["metadata"]["attributes_seen"], 4)

    def test_cve_reference_does_not_overwrite_canonical_vulnerability(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(str(Path(folder) / "db.sqlite"))
            store.ingest({"entities": [{"id": "CVE-2026-12345", "kind": "vulnerability", "name": "Official title",
                                        "metadata": {"official": True}}]})
            store.ingest(normalize_threat(staged("circl_misp", EVENT)))
            with store.connection() as conn:
                record = conn.execute("SELECT name,metadata FROM entities WHERE id='CVE-2026-12345'").fetchone()
                self.assertEqual(record["name"], "Official title")
                self.assertTrue(json.loads(record["metadata"])["official"])
                self.assertEqual(conn.execute("SELECT count(*) FROM edges e LEFT JOIN entities n ON n.id=e.to_id WHERE n.id IS NULL").fetchone()[0], 0)
                for table in ("advisories", "observations", "alerts", "kev"):
                    self.assertEqual(conn.execute("SELECT count(*) FROM " + table).fetchone()[0], 0)

    def test_public_greynoise_keeps_reported_context_and_checks_requested_ip(self):
        value = {"ip": "8.8.8.8", "noise": False, "riot": True, "classification": "benign"}
        batch = normalize_threat(staged("greynoise_public", value, ip="8.8.8.8"))
        self.assertEqual(batch["entities"][0]["metadata"]["record"]["classification"], "benign")
        self.assertFalse(batch.get("observations"))
        self.assertFalse(batch.get("advisories"))
        for payload in ({**value, "ip": "1.1.1.1"}, {"error": "denied"}, b"<html>Access denied</html>"):
            with self.subTest(payload=payload), self.assertRaises(NormalizationError):
                normalize_threat(staged("greynoise_public", payload, ip="8.8.8.8"))


class ZeroSetupThreatCollectionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.store = Store(str(self.root / "db.sqlite"))
        self.config = {**DEFAULTS, "db": self.store.path, "provider_settings": {}, "provider_credentials": {},
                       "watch_products": ["nginx"], "exploit_keywords": ["patch", "exploit"], "threat_source_batch": 3}
        self.http = SimpleNamespace(get=AsyncMock(side_effect=self.fetch))
        self.responses = {}
        self.clock = patch("signalwatch.extension_threat.utcnow", return_value=STAMP)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def respond(self, url, value):
        path = self.root / (hashlib.sha256(url.encode()).hexdigest() + ".json")
        path.write_bytes(value if isinstance(value, bytes) else json.dumps(value).encode())
        self.responses[url] = SimpleNamespace(path=path, status=200, changed=True, url=url)

    async def fetch(self, url, **kwargs):
        value = self.responses[url]
        if isinstance(value, Exception):
            raise value
        return value

    def seed_ips(self):
        self.store.ingest({"entities": [{"id": "ip:" + address, "kind": "ip", "value": address} for address in
                                        ("8.8.8.8", "1.1.1.1", "10.0.0.1", "127.0.0.1", "2001:4860:4860::8888")]})

    async def test_misp_seven_day_window_two_document_cap_and_delta_skip(self):
        self.config["provider_settings"] = {"circl_misp": {"enabled": True}}
        timestamp = int(datetime.fromisoformat(STAMP).timestamp())
        manifest = {}
        for index, age in enumerate((100, 200, 300, 8 * 86400)):
            uuid = f"00000000-0000-0000-0000-{index:012d}"
            manifest[uuid] = {"timestamp": timestamp - age}
            event = copy.deepcopy(EVENT)
            event["Event"]["uuid"] = uuid
            self.respond(MISP_ROOT + uuid + ".json", event)
        self.respond(MISP_ROOT + "manifest.json", manifest)
        first = await collect_threat_sources(self.config, self.store, self.http)
        health = first["provider_health"]["circl_misp"]
        self.assertEqual(health["eligible_events"], 3)
        self.assertEqual(health["records"], 2)
        self.assertEqual(len(health["event_hashes"]), 2)
        self.assertEqual(health["pending_events"], 1)
        self.assertEqual(first["staged"], 3)
        self.assertEqual(len(self.http.get.call_args_list), 3)
        self.assertEqual(self.http.get.call_args_list[0].kwargs["max_bytes"], 2 * 1024 * 1024)
        self.assertEqual(self.http.get.call_args_list[1].kwargs["max_bytes"], 4 * 1024 * 1024)
        second = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(second["records"], 1)
        before = self.http.get.call_count
        third = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(third["records"], 0)
        self.assertEqual(self.http.get.call_count - before, 1)
        self.assertEqual(third["provider_health"]["circl_misp"]["status"], "unchanged")
        self.assertFalse(any("000000000003.json" in call.args[0] for call in self.http.get.call_args_list))
        outcome = StagingWorker(self.store, self.config).drain(limit=20)
        self.assertEqual(outcome["processed"], 4)
        self.assertEqual(outcome["dead"], 0)
        queue = StagingQueue(self.store)
        item = next(row for row in queue.list()["items"] if row["metadata"]["format"] == "misp_event")
        raw = queue.get(item["id"], include_payload=True)["payload"]
        self.assertIn(b"ATTACHMENT_BODY_MUST_NOT_PROJECT", raw)
        with self.store.connection() as conn:
            self.assertNotIn("ATTACHMENT_BODY_MUST_NOT_PROJECT", " ".join(row[0] for row in conn.execute("SELECT metadata FROM entities")))

    async def test_misp_event_failure_does_not_block_sibling_and_has_cooldown(self):
        self.config["provider_settings"] = {"circl_misp": {"enabled": True}}
        timestamp = int(datetime.fromisoformat(STAMP).timestamp())
        other = "00000000-0000-0000-0000-000000000000"
        self.respond(MISP_ROOT + "manifest.json", {UUID: {"timestamp": timestamp - 1}, other: {"timestamp": timestamp - 2}})
        self.respond(MISP_ROOT + UUID + ".json", b"<html>Rate limit</html>")
        value = copy.deepcopy(EVENT)
        value["Event"]["uuid"] = other
        self.respond(MISP_ROOT + other + ".json", value)
        result = await collect_threat_sources(self.config, self.store, self.http)
        health = result["provider_health"]["circl_misp"]
        self.assertEqual(health["status"], "partial")
        self.assertEqual(health["records"], 1)
        self.assertNotIn(UUID, health["event_versions"])
        self.assertIn(UUID, health["event_retry_at"])
        before = self.http.get.call_count
        repeated = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(self.http.get.call_count - before, 1)
        self.assertEqual(repeated["provider_health"]["circl_misp"]["status"], "partial")
        self.assertEqual(repeated["provider_health"]["circl_misp"]["pending_events"], 1)
        self.assertEqual(repeated["provider_health"]["circl_misp"]["deferred_events"], 1)

    async def test_misp_failed_event_cooldown_preserves_failure_and_last_real_success(self):
        self.config["provider_settings"] = {"circl_misp": {"enabled": True}}
        timestamp = int(datetime.fromisoformat(STAMP).timestamp())
        previous_success = "2026-10-18T05:00:00+00:00"
        self.store.update_source("provider:circl_misp", last_success=previous_success)
        self.respond(MISP_ROOT + "manifest.json", {UUID: {"timestamp": timestamp - 1}})
        self.respond(MISP_ROOT + UUID + ".json", b"<html>Unavailable</html>")
        first = (await collect_threat_sources(self.config, self.store, self.http))["provider_health"]["circl_misp"]
        self.assertEqual(first["status"], "partial")
        self.assertEqual(first["pending_events"], 1)
        self.assertEqual(first["last_success"], previous_success)
        self.assertTrue(first["error"])
        before = self.http.get.call_count
        with patch("signalwatch.extension_threat.utcnow", return_value="2026-10-19T06:05:00+00:00"):
            repeated = (await collect_threat_sources(self.config, self.store, self.http))["provider_health"]["circl_misp"]
        self.assertEqual(self.http.get.call_count - before, 1)
        self.assertEqual(repeated["status"], "partial")
        self.assertEqual(repeated["records"], 0)
        self.assertEqual(repeated["pending_events"], 1)
        self.assertEqual(repeated["deferred_events"], 1)
        self.assertTrue(repeated["deferred"])
        self.assertEqual(repeated["error"], first["error"])
        self.assertEqual(repeated["last_success"], previous_success)
        self.respond(MISP_ROOT + UUID + ".json", EVENT)
        with patch("signalwatch.extension_threat.utcnow", return_value="2026-10-19T06:31:00+00:00"):
            recovered = (await collect_threat_sources(self.config, self.store, self.http))["provider_health"]["circl_misp"]
        self.assertEqual(recovered["status"], "ok")
        self.assertEqual(recovered["pending_events"], 0)
        self.assertEqual(recovered["deferred_events"], 0)
        self.assertEqual(recovered["error"], "")
        self.assertEqual(recovered["last_success"], "2026-10-19T06:31:00+00:00")

    async def test_misp_malformed_manifest_is_provider_error_not_healthy_news(self):
        self.config["provider_settings"] = {"circl_misp": {"enabled": True}}
        self.respond(MISP_ROOT + "manifest.json", b"<html>Sign in</html>")
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["circl_misp"]["status"], "error")
        self.assertEqual(result["records"], 0)

    async def test_public_greynoise_no_inventory_or_disabled_provider_does_no_requests(self):
        self.config["provider_settings"] = {"greynoise_public": {"enabled": True}}
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["greynoise_public"]["reason"], "No public IPv4 inventory to enrich")
        self.seed_ips()
        self.config["provider_settings"]["greynoise_public"]["enabled"] = False
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["greynoise_public"]["status"], "disabled")
        self.http.get.assert_not_called()

    async def test_public_greynoise_uses_existing_global_ipv4_and_404_has_unknown_verdict(self):
        self.seed_ips()
        self.config["provider_settings"] = {"greynoise_public": {"enabled": True}}
        url = "https://api.greynoise.io/v3/community/1.1.1.1"
        self.responses[url] = HTTPError(404, url)
        result = await collect_threat_sources(self.config, self.store, self.http)
        health = result["provider_health"]["greynoise_public"]
        self.assertEqual(health["status"], "ok")
        self.assertEqual(health["lookup_status"], "no_observation")
        self.assertEqual(health["verdict"], "unknown")
        self.assertEqual(result["staged"], 0)
        call = self.http.get.call_args
        self.assertEqual(call.args[0], url)
        self.assertEqual(call.kwargs["max_attempts"], 1)
        self.assertFalse(call.kwargs["allow_redirects"])
        self.assertFalse(call.kwargs["cache"])
        self.assertNotIn("key", call.kwargs["headers"])
        self.assertEqual(self.store.source_state("provider:greynoise_public")["daily_requests"], 1)
        again = await collect_threat_sources(self.config, self.store, self.http)
        self.assertTrue(again["provider_health"]["greynoise_public"]["deferred"])
        self.assertEqual(self.http.get.call_count, 1)

    async def test_public_greynoise_200_is_staged_and_error_response_does_not_create_indicators(self):
        self.seed_ips()
        self.config["provider_settings"] = {"greynoise_public": {"enabled": True}}
        url = "https://api.greynoise.io/v3/community/1.1.1.1"
        self.respond(url, {"ip": "1.1.1.1", "noise": True, "riot": False, "classification": "malicious"})
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["staged"], 1)
        self.assertEqual(StagingWorker(self.store, self.config).drain()["processed"], 1)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM entities WHERE kind='threat_indicator'").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM observations").fetchone()[0], 0)
        self.store.update_source("provider:greynoise_public", retry_at="", ip_cursor="")
        self.respond(url, b"<html>Access denied</html>")
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["greynoise_public"]["status"], "error")
        self.assertEqual(result["staged"], 0)

    async def test_public_greynoise_daily_budget_is_shared_and_persists_across_runs(self):
        self.seed_ips()
        self.config["provider_settings"] = {"greynoise_public": {"enabled": True}}
        self.store.update_source("provider:greynoise_public", request_day="2026-10-19", daily_requests=8)
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertTrue(result["provider_health"]["greynoise_public"]["deferred"])
        self.http.get.assert_not_called()
        self.store.update_source("provider:greynoise_public", request_day="2026-10-18", daily_requests=8, retry_at="")
        url = "https://api.greynoise.io/v3/community/1.1.1.1"
        self.responses[url] = HTTPError(404, url)
        await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(self.store.source_state("provider:greynoise_public")["daily_requests"], 1)

    async def test_public_greynoise_concurrent_runs_share_atomic_reservation(self):
        import asyncio
        self.seed_ips()
        self.config["provider_settings"] = {"greynoise_public": {"enabled": True}}
        url = "https://api.greynoise.io/v3/community/1.1.1.1"
        self.responses[url] = HTTPError(404, url)
        await asyncio.gather(*(collect_threat_sources(self.config, self.store, self.http) for _ in range(4)))
        self.assertEqual(self.http.get.call_count, 1)
        self.assertEqual(self.store.source_state("provider:greynoise_public")["daily_requests"], 1)

    async def test_public_greynoise_429_stops_for_at_least_a_day(self):
        self.seed_ips()
        self.config["provider_settings"] = {"greynoise_public": {"enabled": True}}
        url = "https://api.greynoise.io/v3/community/1.1.1.1"
        self.responses[url] = HTTPError(429, url, retry_after=3600)
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["greynoise_public"]["status"], "error")
        state = self.store.source_state("provider:greynoise_public")
        self.assertGreaterEqual(datetime.fromisoformat(state["retry_at"]).timestamp() - datetime.fromisoformat(STAMP).timestamp(), 86400)
        await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(self.http.get.call_count, 1)
