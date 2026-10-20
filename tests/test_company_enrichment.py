import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from signalwatch.config import load_config
from signalwatch.engine import Engine, EXTENSION_ADAPTERS
from signalwatch.extension_network import normalize_network
from signalwatch.store import Store


class CompanyEnrichmentTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = load_config(Path(self.directory.name) / "config.json")
        self.store = Store(self.config["db"])
        self.engine = Engine(self.config, self.store)
        self.engine.collector = SimpleNamespace(http=None)

    def add_company(self, name, domain, relation="official_website"):
        company_id = "company:" + name
        domain_id = "domain:" + domain
        self.store.ingest({"entities": [
            {"id": company_id, "kind": "company", "name": name, "value": name},
            {"id": domain_id, "kind": "domain", "name": domain, "value": domain}],
            "edges": [{"from_id": company_id, "to_id": domain_id, "relation": relation}]})

    def test_targets_use_official_company_domains_and_skip_ambiguous_shared_domains(self):
        self.add_company("Acme", "acme.test")
        self.add_company("Parent", "shared.test")
        self.add_company("Subsidiary", "shared.test")
        self.add_company("Candidate", "candidate.test", "candidate_asset")
        self.store.ingest({"entities": [{"id": "domain:orphan.test", "kind": "domain", "name": "orphan.test", "value": "orphan.test"}]})
        targets = self.store.company_enrichment_targets()
        self.assertEqual(targets, [{"domain": "acme.test", "name": "Acme", "company_id": "company:Acme"}])
        self.assertEqual(len(self.store.company_enrichment_targets(limit=1)), 1)

    def test_target_limit_counts_accepted_owners_after_earlier_ambiguous_domains(self):
        for index, domain in enumerate(("a-shared.test", "b-shared.test", "n-shared.test")):
            self.add_company(f"Shared{index}One", domain)
            self.add_company(f"Shared{index}Two", domain)
        self.add_company("Later", "z-valid.test")
        self.add_company("Earlier", "m-valid.test")
        accepted = [
            {"domain": "m-valid.test", "name": "Earlier", "company_id": "company:Earlier"},
            {"domain": "z-valid.test", "name": "Later", "company_id": "company:Later"},
        ]
        for limit in (1, 2, 3):
            with self.subTest(limit=limit):
                self.assertEqual(self.store.company_enrichment_targets(limit=limit), accepted[:limit])

    def test_target_limit_retains_primary_owner_despite_ambiguous_legacy_associations(self):
        self.add_company("SharedOne", "a-shared.test")
        self.add_company("SharedTwo", "a-shared.test")
        self.add_company("Legacy", "owned.example.com")
        self.add_company("Primary", "owned.example.com")
        self.store.save_company_profile(
            "company:Primary", "Reviewed primary name", primary_domain="owned.example.com",
            primary_domain_evidence="Verified company website", primary_domain_source_url="https://owned.example.com/about")
        self.add_company("Later", "z-valid.test")
        self.assertEqual(self.store.company_enrichment_targets(limit=1), [
            {"domain": "owned.example.com", "name": "Reviewed primary name", "company_id": "company:Primary"},
        ])

    async def test_discovered_companies_reach_all_three_enrichment_families(self):
        self.add_company("Acme", "acme.test")
        before = copy.deepcopy(self.config)
        for family in ("exposure", "corporate", "developer"):
            module, function = EXTENSION_ADAPTERS[family]
            adapter = AsyncMock(return_value={"records": 1})
            with patch(f"signalwatch.{module}.{function}", new=adapter):
                result = await self.engine._collect_source(family)
            targets = adapter.await_args.args[0]["source_targets"]
            self.assertIn({"domain": "acme.test", "name": "Acme", "company_id": "company:Acme"}, targets)
            self.assertEqual(result["discovered_company_targets"], 1)
            self.assertEqual(result["company_targets"], len(self.config["source_targets"]) + 1)
        self.assertEqual(self.config, before)

    async def test_explicit_target_configuration_wins_without_duplicates(self):
        self.add_company("Discovered", "acme.test")
        self.config["source_targets"] = [{"name": "Operator label", "domain": "ACME.TEST.", "github_org": "configured-org", "document_urls": ["https://acme.test/report.pdf"]}]
        adapter = AsyncMock(return_value={})
        with patch("signalwatch.extension_corporate.collect_corporate_sources", new=adapter):
            result = await self.engine._collect_source("corporate")
        self.assertEqual(adapter.await_args.args[0]["source_targets"], self.config["source_targets"])
        self.assertEqual(result["company_targets"], 1)

    async def test_new_company_is_picked_up_on_next_run_without_restart_or_saved_target_edits(self):
        adapter = AsyncMock(side_effect=lambda *args: {})
        with patch("signalwatch.extension_network.collect_network_sources", new=adapter):
            await self.engine._collect_source("exposure")
            self.add_company("New", "new.test")
            await self.engine._collect_source("exposure")
        first, second = [call.args[0]["source_targets"] for call in adapter.await_args_list]
        self.assertFalse(any(target["domain"] == "new.test" for target in first))
        self.assertTrue(any(target["domain"] == "new.test" for target in second))

    async def test_company_discovery_does_not_populate_active_scan_targets(self):
        self.add_company("Acme", "acme.test")
        adapter = AsyncMock(return_value={})
        with patch("signalwatch.engine.collect_nmap", new=adapter):
            await self.engine._collect_source("nmap")
        self.assertEqual(adapter.await_args.args[0]["provider_settings"]["nmap"]["targets"], [])

    def test_default_cadence_prioritizes_company_mapping(self):
        self.assertEqual({key: self.config["source_intervals"][key] for key in ("web", "wikidata", "network", "exposure", "corporate", "developer")},
                         {"web": 5, "wikidata": 15, "network": 15, "exposure": 30, "corporate": 15, "developer": 360})

    def test_certificate_subdomain_evidence_connects_to_the_official_company_domain(self):
        self.add_company("Acme", "acme.test")
        raw = json.dumps([{"name_value": "vpn.acme.test"}]).encode()
        item = {"id": 1, "source": "public:crtsh", "payload": raw, "payload_hash": hashlib.sha256(raw).hexdigest(),
                "metadata": {"provider": "crtsh", "target_domain": "acme.test"}, "received_at": "2026-10-19T00:00:00Z"}
        batch = normalize_network(item)
        self.store.ingest(batch)
        evidence = next(row for row in batch["entities"] if row["kind"] == "source_record")["id"]
        links = {(row["from_id"], row["to_id"], row["relation"]) for row in batch["edges"]}
        self.assertIn((evidence, "domain:acme.test", "certificate_lookup_scope"), links)
        self.assertIn((evidence, "domain:vpn.acme.test", "reports_on"), links)
        self.assertNotIn("observations", batch)
