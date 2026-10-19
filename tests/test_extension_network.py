import hashlib
import json
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from signalwatch.extension_network import FOFA_FIELDS, SOURCE_DEFINITIONS, collect_network_sources, normalize_network
from signalwatch.http import FetchResult
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.normalization import NormalizationError
from signalwatch.store import Store


class NetworkSourceTests(unittest.IsolatedAsyncioTestCase):
    def item(self, provider, value, **metadata):
        payload = value.encode() if isinstance(value, str) else json.dumps(value).encode()
        return {"id": 42, "source": provider, "source_url": "https://index.example/", "stream_key": "stream", "payload": payload, "payload_hash": hashlib.sha256(payload).hexdigest(), "observed_at": "2026-10-19T00:00:00+00:00", "metadata": {"provider": provider, "target_domain": "example.com", **metadata}}

    def config(self, providers):
        return {"source_targets": [{"domain": "example.com"}], "provider_settings": {definition["id"]: {"enabled": definition["id"] in providers} for definition in SOURCE_DEFINITIONS}}

    def test_certificate_scope_wildcards_and_expiry_remain_provider_evidence(self):
        item = self.item("crtsh", [{"id": 1, "name_value": "*.example.com\nvpn.example.com\nother.example.net", "not_after": "2020-01-01"}])
        batch = normalize_network(item)
        self.assertEqual({row["value"] for row in batch["entities"] if row["kind"] == "domain"}, {"example.com", "vpn.example.com"})
        evidence = next(row for row in batch["entities"] if row["kind"] == "source_record")
        self.assertEqual(evidence["metadata"]["provider_fields"]["not_after"], "2020-01-01")
        self.assertEqual(evidence["metadata"]["provider_fields"]["name_value"].splitlines()[0], "*.example.com")
        self.assertEqual({row["relation"] for row in batch["edges"]}, {"reports_on"})
        self.assertNotIn("observations", batch)
        self.assertEqual(evidence["metadata"]["staging"]["raw_reference"], "staging:42")

    def test_passive_dns_csv_retains_ip_relationships_without_attribution(self):
        batch = normalize_network(self.item("passive_dns", "www.example.com,192.0.2.10\nvpn.example.com,2001:db8::1\n"))
        self.assertEqual({row["kind"] for row in batch["entities"]}, {"source_record", "domain", "ip"})
        self.assertEqual(len([row for row in batch["entities"] if row["kind"] == "source_record"]), 2)
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "db.sqlite")
            store.ingest(batch)
            with store.connection() as conn:
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 0)
                self.assertEqual(conn.execute("SELECT COUNT(*) FROM entities WHERE kind='company'").fetchone()[0], 0)

    def test_dns_txt_preserves_quotes_and_does_not_infer_service_deployment(self):
        value = '"v=spf1 include:example.net -all"'
        batch = normalize_network(self.item("dns_txt", {"Status": 0, "Answer": [{"name": "example.com.", "type": 16, "TTL": 300, "data": value}, {"name": "example.com.", "type": 5, "data": "other.example.net."}]}))
        evidence = next(row for row in batch["entities"] if row["kind"] == "source_record")
        self.assertEqual(evidence["metadata"]["provider_fields"]["data"], value)
        self.assertEqual(evidence["metadata"]["provider_fields"]["TTL"], 300)
        self.assertNotIn("observations", batch)
        self.assertEqual(normalize_network(self.item("dns_txt", {"Status": 3})), {"entities": [], "edges": []})

    def test_current_indexer_schemas_preserve_banners_and_link_only_reported_entities(self):
        providers = {
            "shodan": {"matches": [{"ip_str": "192.0.2.1", "port": 443, "data": "Server: nginx", "hostnames": ["edge.example.com"], "product": "nginx", "version": "1.2"}]},
            "censys": {"result": {"total_hits": 1, "hits": [{"host_v1": {"resource": {"ip": "192.0.2.1", "services": [{"port": 443, "protocol": "HTTP"}]}, "matched_services": []}, "webproperty_v1": None}]}},
            "fofa": {"error": False, "results": [["192.0.2.1", "443", "https://edge.example.com", "https", "Edge", "edge.example.com", "nginx", "Linux"]]},
            "zoomeye": {"code": 60000, "data": [{"ip": "192.0.2.1", "port": 443, "domain": "edge.example.com", "product": "nginx"}]},
            "netlas": {"items": [{"data": {"ip": "192.0.2.1", "port": 443, "hostnames": ["edge.example.com"]}}]},
        }
        for provider, value in providers.items():
            with self.subTest(provider=provider):
                batch = normalize_network(self.item(provider, value))
                self.assertEqual(len([row for row in batch["entities"] if row["kind"] == "source_record"]), 1)
                self.assertIn("ip:192.0.2.1", {row["id"] for row in batch["entities"]})
                self.assertNotIn("observations", batch)
                self.assertTrue(all(row["relation"] == "reports_on" for row in batch["edges"]))

    def test_invalid_and_provider_error_responses_fail_instead_of_inventing_records(self):
        for provider, payload in [("crtsh", {}), ("dns_txt", {"Status": 2}), ("shodan", {"error": "Invalid key"}), ("fofa", {"error": True}), ("censys", {"result": {"total_hits": 1}}), ("zoomeye", {"code": 50001}), ("netlas", {"items": [None]}), ("passive_dns", "API count exceeded"), ("passive_dns", [{"domain": "example.com"}])]:
            with self.subTest(provider=provider), self.assertRaises((NormalizationError, ValueError)):
                normalize_network(self.item(provider, payload))

    def test_configured_export_is_evidence_and_output_budget_is_total_rows(self):
        batch = normalize_network(self.item("arin", {"handle": "NET-192-0-2-0", "name": "NETWORK"}))
        self.assertEqual(len(batch["entities"]), 1)
        self.assertEqual(batch["entities"][0]["metadata"]["provider_fields"]["handle"], "NET-192-0-2-0")
        names = "\n".join(str(index) + ".example.com" for index in range(200))
        batch = normalize_network(self.item("crtsh", [{"name_value": names}] * 10), max_records=12)
        self.assertLessEqual(sum(map(len, batch.values())), 12)

    async def test_missing_keys_are_unconfigured_and_do_not_request(self):
        config = self.config({"shodan", "censys", "fofa", "zoomeye", "netlas", "dnsdumpster"})
        http = types.SimpleNamespace(get=AsyncMock(), post=AsyncMock())
        stage = AsyncMock()
        with patch.dict("sys.modules", {"signalwatch.sourcehub": types.SimpleNamespace(stage_payload=stage)}):
            counts = await collect_network_sources(config, None, http)
        self.assertEqual(counts["errors"], [])
        self.assertEqual(counts["provider_health"]["shodan"]["status"], "unconfigured")
        self.assertEqual(counts["provider_health"]["dnsdumpster"]["requirements"], ["url"])
        http.get.assert_not_awaited()
        http.post.assert_not_awaited()
        stage.assert_not_awaited()

    async def test_raw_payload_exact_and_auth_query_removed_from_staging_provenance(self):
        config = self.config({"shodan"})
        config["provider_credentials"] = {"shodan": "secret-value"}
        raw = b'{ "matches": [{"ip_str": "192.0.2.1", "port": 443}] }\n'
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "body"
            path.write_bytes(raw)
            http = types.SimpleNamespace(get=AsyncMock(return_value=FetchResult(path, 200, {"Content-Type": "application/json; charset=utf-8"}, "https://api.shodan.io/?key=secret-value", True, "hash")))
            stage = AsyncMock()
            with patch.dict("sys.modules", {"signalwatch.sourcehub": types.SimpleNamespace(stage_payload=stage)}):
                counts = await collect_network_sources(config, None, http)
        self.assertEqual(counts["staged"], 1)
        self.assertEqual(stage.await_args.args[2], raw)
        self.assertNotIn("secret-value", json.dumps(stage.await_args.kwargs))
        self.assertEqual(http.get.await_args.kwargs["params"]["key"], "secret-value")
        self.assertFalse(http.get.await_args.kwargs["cache"])
        self.assertFalse(http.get.await_args.kwargs["allow_redirects"])

    async def test_censys_and_zoomeye_use_current_post_apis(self):
        for provider, payload in [("censys", {"result": {"hits": [], "total_hits": 0}}), ("zoomeye", {"code": 60000, "data": []})]:
            with self.subTest(provider=provider), tempfile.TemporaryDirectory() as folder:
                config = self.config({provider})
                config["provider_credentials"] = {provider: {"api_key": "key"}}
                config["provider_settings"][provider]["query"] = "host.ip:192.0.2.1"
                path = Path(folder) / "body"
                path.write_text(json.dumps(payload))
                http = types.SimpleNamespace(get=AsyncMock(), post=AsyncMock(return_value=FetchResult(path, 200, {}, "https://api.example/", True, "hash")))
                stage = AsyncMock()
                with patch.dict("sys.modules", {"signalwatch.sourcehub": types.SimpleNamespace(stage_payload=stage)}):
                    counts = await collect_network_sources(config, None, http)
                self.assertEqual(counts["provider_health"][provider]["status"], "healthy")
                http.get.assert_not_awaited()
                self.assertIn("/v3/global/search/query" if provider == "censys" else "/v2/search", http.post.await_args.args[0])
                self.assertEqual(http.post.await_args.kwargs["json"]["page_size" if provider == "censys" else "pagesize"], 100)

    async def test_target_budget_dkim_selector_limit_and_failures_are_reported(self):
        config = self.config({"dns_txt", "shodan"})
        config["public_source_batch"] = 1
        config["source_targets"] = [{"domain": "example.com", "dkim_selectors": ["mail"]}, {"domain": "example.net"}]
        config["provider_credentials"] = {"shodan": "secret"}
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "body"
            path.write_text('{"Status":0}')
            async def fetch(url, **kwargs):
                if "shodan" in url:
                    raise RuntimeError("key=secret upstream failure")
                return FetchResult(path, 200, {}, url, True, "hash")
            http = types.SimpleNamespace(get=AsyncMock(side_effect=fetch))
            stage = AsyncMock()
            with patch.dict("sys.modules", {"signalwatch.sourcehub": types.SimpleNamespace(stage_payload=stage)}):
                counts = await collect_network_sources(config, None, http)
        self.assertEqual(counts["staged"], 3)
        self.assertEqual(counts["provider_health"]["shodan"]["status"], "error")
        self.assertNotIn("secret", json.dumps(counts))
        names = {call.kwargs["params"].get("name") for call in http.get.await_args_list if "dns.google" in call.args[0]}
        self.assertEqual(names, {"example.com", "_dmarc.example.com", "mail._domainkey.example.com"})

    async def test_rotating_targets_and_actual_queue_duplicates_have_honest_counts(self):
        config = self.config({"crtsh"})
        config["source_targets"] = [{"domain": name} for name in ("a.test", "b.test", "c.test", "d.test")]
        config["public_source_batch"] = 3
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "store.sqlite")
            bodies = {}
            async def fetch(url, **kwargs):
                name = kwargs["params"]["q"].removeprefix("%.")
                path = bodies.setdefault(name, Path(folder) / name)
                raw = ('[ { "id": 1, "name_value": "vpn.' + name + '" } ]\n').encode()
                path.write_bytes(raw)
                return FetchResult(path, 200, {}, url, True, hashlib.sha256(raw).hexdigest())
            http = types.SimpleNamespace(get=AsyncMock(side_effect=fetch))
            first = await collect_network_sources(config, store, http)
            second = await collect_network_sources(config, store, http)
            self.assertEqual(first["staged"], 3)
            self.assertEqual(second["staged"], 1)
            self.assertEqual(second["unchanged"], 2)
            self.assertEqual(first["pending_targets"], 1)
            self.assertEqual([call.kwargs["params"]["q"] for call in http.get.await_args_list], ["%.a.test", "%.b.test", "%.c.test", "%.d.test", "%.a.test", "%.b.test"])
            self.assertEqual(staging_queue(store, config).stats()["total"], 4)
            raw = staging_queue(store, config).get(1, include_payload=True)["payload"]
            self.assertEqual(raw, bodies["a.test"].read_bytes())
            self.assertEqual(StagingWorker(store, config).drain()["processed"], 4)
