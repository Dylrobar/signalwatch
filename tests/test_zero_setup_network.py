import hashlib
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from signalwatch.extension_network import SOURCE_DEFINITIONS, collect_network_sources, normalize_network
from signalwatch.http import FetchResult, HTTPError
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.normalization import NormalizationError
from signalwatch.store import Store


FIXTURES = Path(__file__).parent / "fixtures" / "network_zero_setup"


class ZeroSetupNetworkTests(unittest.IsolatedAsyncioTestCase):
    def config(self, providers):
        return {"source_targets": [{"domain": "example.com"}], "provider_settings": {row["id"]: {"enabled": row["id"] in providers} for row in SOURCE_DEFINITIONS}}

    def item(self, provider, value):
        raw = json.dumps(value).encode()
        return {"id": 17, "payload": raw, "payload_hash": hashlib.sha256(raw).hexdigest(), "source": "public:" + provider, "source_url": "https://index.example/", "stream_key": provider + ":example.com", "metadata": {"provider": provider, "target_domain": "example.com", "coverage": "bounded public index"}}

    def fetched(self, folder, value, headers=None):
        raw = json.dumps(value).encode()
        path = Path(folder) / hashlib.sha256(raw).hexdigest()
        path.write_bytes(raw)
        return FetchResult(path, 200, headers or {}, "https://index.example/", True, hashlib.sha256(raw).hexdigest())

    def test_official_host_fixture_is_scoped_evidence_without_inventory_or_ownership(self):
        value = json.loads((FIXTURES / "ctlogs-hosts.json").read_text())
        value["hosts"].append({"host": "unrelated.example.net", "certs": 200})
        batch = normalize_network(self.item("ctlogs", value))
        domains = {row["value"] for row in batch["entities"] if row["kind"] == "domain"}
        self.assertTrue(domains)
        self.assertTrue(all(name == "example.com" or name.endswith(".example.com") for name in domains))
        self.assertTrue(all(row["kind"] in {"source_record", "domain"} for row in batch["entities"]))
        self.assertEqual({edge["relation"] for edge in batch["edges"]}, {"reports_on", "certificate_lookup_scope"})
        evidence = next(row for row in batch["entities"] if row["kind"] == "source_record")
        self.assertEqual(evidence["metadata"]["coverage"], "bounded public index")
        self.assertEqual(evidence["metadata"]["attribution"], "provider_report_only")
        self.assertNotIn("observations", batch)

    def test_certspotter_shared_certificate_does_not_attribute_other_sans(self):
        value = json.loads((FIXTURES / "certspotter-issuances.json").read_text())
        batch = normalize_network(self.item("certspotter", value))
        self.assertEqual({row["id"] for row in batch["entities"] if row["kind"] == "domain"}, {"domain:example.com"})
        evidence = next(row for row in batch["entities"] if row["kind"] == "source_record")
        self.assertEqual(evidence["metadata"]["provider_fields"]["dns_names"], value[0]["dns_names"])
        self.assertTrue(evidence["metadata"]["provider_fields"]["revoked"])

    def test_malformed_and_error_documents_fail(self):
        for provider, value in [("ctlogs", {"error": "rate limited"}), ("ctlogs", {"hosts": [], "has_next": True, "next_cursor": ""}), ("ctlogs", {"hosts": [None], "has_next": False, "next_cursor": ""}), ("ctlogs", {"hosts": [{"host": []}], "has_next": False, "next_cursor": ""}), ("certspotter", {"code": "rate_limited"}), ("certspotter", [{"id": "1"}]), ("certspotter", [{"id": "1", "dns_names": [False]}])]:
            with self.subTest(provider=provider, value=value), self.assertRaises(NormalizationError):
                normalize_network(self.item(provider, value))

    async def test_no_key_primary_stages_original_payload_and_crtsh_stays_fallback(self):
        config = self.config({"ctlogs", "crtsh"})
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            value = json.loads((FIXTURES / "ctlogs-hosts.json").read_text())
            result = self.fetched(folder, value)
            http = types.SimpleNamespace(get=AsyncMock(return_value=result))
            counts = await collect_network_sources(config, store, http)
            self.assertEqual(counts["staged"], 1)
            self.assertEqual(counts["provider_health"]["ctlogs"]["status"], "healthy")
            self.assertEqual(counts["provider_health"]["crtsh"]["skipped_targets"], 1)
            self.assertEqual(http.get.await_count, 1)
            self.assertEqual(http.get.await_args.args[0], "https://api.ctlogs.dev/v1/hosts/example.com")
            self.assertEqual(http.get.await_args.kwargs["headers"], {})
            self.assertNotIn("key", http.get.await_args.kwargs["params"])
            self.assertEqual(staging_queue(store, config).get(1, include_payload=True)["payload"], result.path.read_bytes())
            self.assertEqual(StagingWorker(store, config).drain()["processed"], 1)
            with store.connection() as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM observations").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT count(*) FROM entities WHERE kind='company'").fetchone()[0], 0)

    async def test_provider_failure_falls_back_and_persists_retry_after(self):
        config = self.config({"ctlogs", "crtsh"})
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            result = self.fetched(folder, [{"id": 1, "name_value": "vpn.example.com"}])
            async def fetch(url, **kwargs):
                if "ctlogs" in url:
                    raise HTTPError(429, url, retry_after=7200)
                return result
            http = types.SimpleNamespace(get=AsyncMock(side_effect=fetch))
            with patch("signalwatch.extension_network.time.time", return_value=1_800_000_000):
                counts = await collect_network_sources(config, store, http)
                second = await collect_network_sources(config, store, http)
            self.assertEqual(counts["provider_health"]["ctlogs"]["status"], "error")
            self.assertEqual(counts["provider_health"]["crtsh"]["status"], "healthy")
            self.assertEqual(second["provider_health"]["ctlogs"]["status"], "deferred")
            self.assertEqual(store.source_state("exposure_ct")["ctlogs"]["retry_at"], 1_800_007_200)
            self.assertEqual(len([call for call in http.get.await_args_list if "ctlogs" in call.args[0]]), 1)
            self.assertEqual(staging_queue(store, config).stats()["total"], 1)

    async def test_cursor_advance_only_after_valid_page_is_staged(self):
        config = self.config({"ctlogs"})
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            first = self.fetched(folder, {"hosts": [{"host": "first.example.com"}], "has_next": True, "next_cursor": "opaque-one"})
            final = self.fetched(folder, {"hosts": [{"host": "last.example.com"}], "has_next": False, "next_cursor": ""})
            http = types.SimpleNamespace(get=AsyncMock(side_effect=[first, final]))
            with patch("signalwatch.extension_network.time.time", return_value=1_800_000_000):
                await collect_network_sources(config, store, http)
                deferred = await collect_network_sources(config, store, http)
            self.assertEqual(deferred["provider_health"]["ctlogs"]["deferred_targets"], 1)
            self.assertEqual(http.get.await_count, 1)
            with patch("signalwatch.extension_network.time.time", return_value=1_800_003_601):
                await collect_network_sources(config, store, http)
            self.assertEqual(http.get.await_args.kwargs["params"], {"after": "opaque-one"})
            self.assertEqual(store.source_state("exposure_ct")["ctlogs"]["targets"]["example.com"]["after"], "")
            self.assertEqual(staging_queue(store, config).stats()["total"], 2)
            with patch("signalwatch.extension_network.time.time", return_value=1_800_003_602):
                self.assertEqual(StagingWorker(store, config).drain()["processed"], 2)

    async def test_failed_staging_keeps_cursor_for_replay(self):
        config = self.config({"ctlogs"})
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            result = self.fetched(folder, {"hosts": [{"host": "vpn.example.com"}], "has_next": True, "next_cursor": "next"})
            http = types.SimpleNamespace(get=AsyncMock(return_value=result))
            with patch("signalwatch.sourcehub.stage_payload", new=AsyncMock(side_effect=RuntimeError("disk failure"))):
                counts = await collect_network_sources(config, store, http)
            self.assertEqual(counts["staged"], 0)
            self.assertEqual(store.source_state("exposure_ct")["ctlogs"]["targets"], {})
            self.assertEqual(staging_queue(store, config).stats()["total"], 0)

    async def test_no_key_certspotter_cursor_and_retry_after(self):
        config = self.config({"certspotter", "ctlogs", "crtsh"})
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            first = self.fetched(folder, [{"id": "issuer-one", "dns_names": ["vpn.example.com"]}])
            final = self.fetched(folder, [], {"retry-after": "8000"})
            http = types.SimpleNamespace(get=AsyncMock(side_effect=[first, final]))
            with patch("signalwatch.extension_network.time.time", return_value=1_800_000_000):
                await collect_network_sources(config, store, http)
            with patch("signalwatch.extension_network.time.time", return_value=1_800_003_601):
                await collect_network_sources(config, store, http)
            self.assertEqual(http.get.await_count, 2)
            self.assertEqual(http.get.await_args.kwargs["params"]["after"], "issuer-one")
            self.assertEqual(http.get.await_args.kwargs["params"]["expand"], "dns_names")
            self.assertEqual(http.get.await_args.kwargs["headers"], {})
            state = store.source_state("exposure_ct")["certspotter"]["targets"]["example.com"]
            self.assertEqual(state["after"], "issuer-one")
            self.assertEqual(state["retry_at"], 1_800_011_601)

    async def test_ctlogs_anonymous_tenth_page_resets_without_requesting_paid_depth(self):
        config = self.config({"ctlogs"})
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            store.update_source("exposure_ct", ctlogs={"targets": {"example.com": {"after": "page-nine", "pages": 9}}})
            result = self.fetched(folder, {"hosts": [{"host": "ten.example.com"}], "has_next": True, "next_cursor": "page-ten"})
            http = types.SimpleNamespace(get=AsyncMock(return_value=result))
            counts = await collect_network_sources(config, store, http)
            self.assertTrue(counts["provider_health"]["ctlogs"]["history_truncated"])
            self.assertEqual(store.source_state("exposure_ct")["ctlogs"]["targets"]["example.com"]["after"], "")
            self.assertEqual(http.get.await_count, 1)

    async def test_anonymous_hourly_budget_is_persisted_across_collection_runs(self):
        config = self.config({"ctlogs"})
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            store.update_source("exposure_ct", ctlogs={"request_times": [1_800_000_000] * 30})
            http = types.SimpleNamespace(get=AsyncMock())
            with patch("signalwatch.extension_network.time.time", return_value=1_800_000_001):
                counts = await collect_network_sources(config, store, http)
            self.assertEqual(counts["provider_health"]["ctlogs"]["deferred_targets"], 1)
            http.get.assert_not_awaited()

    async def test_hourly_budget_does_not_advance_past_unvisited_targets(self):
        config = self.config({"ctlogs"})
        config["source_targets"] = [{"domain": domain} for domain in ("a.example.com", "b.example.com", "c.example.com")]
        config["public_source_batch"] = 3
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            store.update_source("exposure_ct", ctlogs={"request_times": [1_800_000_000] * 29})
            result = self.fetched(folder, {"hosts": [], "has_next": False, "next_cursor": ""})
            http = types.SimpleNamespace(get=AsyncMock(return_value=result))
            with patch("signalwatch.extension_network.time.time", return_value=1_800_000_001):
                counts = await collect_network_sources(config, store, http)
            self.assertEqual(counts["provider_health"]["ctlogs"]["requests"], 1)
            self.assertEqual(counts["provider_health"]["ctlogs"]["pending_targets"], 2)
            self.assertEqual(store.source_state("exposure_cursors")["ctlogs"], 1)
            with patch("signalwatch.extension_network.time.time", return_value=1_800_003_602):
                await collect_network_sources(config, store, http)
            self.assertIn("/b.example.com", http.get.await_args_list[1].args[0])

    async def test_unchanged_page_is_idempotent_after_cooldown(self):
        config = self.config({"ctlogs"})
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            result = self.fetched(folder, {"hosts": [{"host": "vpn.example.com"}], "has_next": False, "next_cursor": ""})
            http = types.SimpleNamespace(get=AsyncMock(return_value=result))
            with patch("signalwatch.extension_network.time.time", return_value=1_800_000_000):
                first = await collect_network_sources(config, store, http)
            with patch("signalwatch.extension_network.time.time", return_value=1_800_003_601):
                second = await collect_network_sources(config, store, http)
            self.assertEqual(first["staged"], 1)
            self.assertEqual(second["unchanged"], 1)
            self.assertEqual(staging_queue(store, config).stats()["total"], 1)
            with patch("signalwatch.extension_network.time.time", return_value=1_800_003_602):
                self.assertEqual(StagingWorker(store, config).drain()["processed"], 1)

    async def test_explicit_disable_is_preserved_during_provider_failure(self):
        config = self.config({"ctlogs"})
        http = types.SimpleNamespace(get=AsyncMock(side_effect=HTTPError(503, "https://api.ctlogs.dev/")))
        counts = await collect_network_sources(config, None, http)
        self.assertEqual(counts["provider_health"]["crtsh"]["status"], "disabled")
        self.assertEqual(counts["provider_health"]["certspotter"]["status"], "disabled")
        self.assertEqual(http.get.await_count, 1)

    async def test_repeated_cursor_and_malformed_primary_trigger_crtsh_fallback(self):
        for value in [{"error": "busy"}, {"hosts": [{"host": "vpn.example.com"}], "has_next": True, "next_cursor": "same"}]:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as folder:
                config = self.config({"ctlogs", "crtsh"})
                store = Store(Path(folder) / "store.sqlite")
                store.update_source("exposure_ct", ctlogs={"targets": {"example.com": {"after": "same", "pages": 1}}})
                primary = self.fetched(folder, value)
                fallback = self.fetched(folder, [{"name_value": "vpn.example.com"}])
                http = types.SimpleNamespace(get=AsyncMock(side_effect=[primary, fallback]))
                counts = await collect_network_sources(config, store, http)
                self.assertEqual(counts["provider_health"]["ctlogs"]["status"], "error")
                self.assertEqual(counts["provider_health"]["crtsh"]["status"], "healthy")
                self.assertEqual(store.source_state("exposure_ct")["ctlogs"]["targets"]["example.com"]["after"], "same")
                self.assertEqual(staging_queue(store, config).stats()["total"], 1)

    async def test_bounded_page_keeps_all_rows_when_generic_record_limit_is_smaller(self):
        config = self.config({"ctlogs"})
        config["public_source_records"] = 1
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            value = {"hosts": [{"host": "one.example.com"}, {"host": "two.example.com"}], "has_next": True, "next_cursor": "next"}
            http = types.SimpleNamespace(get=AsyncMock(return_value=self.fetched(folder, value)))
            counts = await collect_network_sources(config, store, http)
            self.assertEqual(counts["records"], 2)
            self.assertEqual(StagingWorker(store, config).drain()["processed"], 1)
            with store.connection() as conn:
                self.assertEqual({row[0] for row in conn.execute("SELECT value FROM entities WHERE kind='domain'")}, {"example.com", "one.example.com", "two.example.com"})
