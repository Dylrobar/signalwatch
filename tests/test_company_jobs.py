import asyncio
import copy
import fcntl
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from signalwatch.collectors import Collector
from signalwatch.config import load_config
from signalwatch.engine import Engine
from signalwatch.http import FetchResult
from signalwatch.store import Store


class CompanyJobsTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = load_config(Path(self.directory.name) / "config.json")
        self.config.update(seed_urls=[], source_targets=[], crawl_pages=1, crawl_depth=0,
                           web_fingerprint_catalog=False)
        self.store = Store(self.config["db"])
        self.engine = Engine(self.config, self.store)
        self.company()

    def company(self, domain="acme.test", company_id="company:acme"):
        self.store.ingest({"entities": [
            {"id": company_id, "kind": "company", "name": company_id},
            {"id": "domain:" + domain, "kind": "domain", "name": domain, "value": domain}],
            "edges": [{"from_id": company_id, "to_id": "domain:" + domain, "relation": "official_website"}]})

    def certificate(self, domain, scope="acme.test", provider="ctlogs"):
        record_id = "source_record:" + provider + ":" + domain
        self.store.ingest({"entities": [
            {"id": record_id, "kind": "source_record", "name": domain,
             "source_url": "https://certificates.example.test/", "metadata": {"provider": provider, "target_domain": scope}},
            {"id": "domain:" + domain, "kind": "domain", "name": domain, "value": domain}],
            "edges": [{"from_id": record_id, "to_id": "domain:" + domain, "relation": "reports_on"}]})

    def test_scope_includes_only_approved_domains_and_related_certificate_hosts(self):
        self.company("other.test", "company:other")
        self.certificate("api.acme.test")
        self.certificate("acme.test.evil.test")
        self.certificate("api.other.test", "other.test")
        self.certificate("dns.acme.test", provider="dns_txt")
        self.store.enqueue_url("https://api.acme.test/")
        scope = self.engine.company_scope("company:acme")
        self.assertEqual([target["domain"] for target in scope["targets"]], ["acme.test", "api.acme.test"])
        self.assertEqual([target["included"] for target in scope["targets"]], [True, False])

    def test_manual_exclusions_are_not_scanned_and_primary_domain_cannot_widen_scope(self):
        self.certificate("rejected.acme.test")
        self.store.set_company_asset("company:acme", "https://rejected.acme.test/", "rejected", "owned",
                                     "Not our host", "https://acme.test/about")
        self.assertEqual(len(self.engine.company_scope("company:acme")["targets"]), 1)
        for domain in ("unrelated.test", "new.acme.test", "acme.test:8443", "acme.test/path", "acme.test?token=x", "user@acme.test"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                self.engine.company_scope("company:acme", domain)
        self.assertEqual(self.engine.company_scope("company:acme", "ACME.test.")["primary_domain"], "acme.test")
        with self.assertRaises(LookupError):
            self.engine.company_scope("company:missing")
        self.store.set_company_asset("company:acme", "https://acme.test/", "rejected", "owned",
                                     "Not our host", "https://acme.test/about")
        with self.assertRaisesRegex(ValueError, "no included domains"):
            self.engine.company_scope("company:acme")

    def test_scope_limit_and_requested_primary_domain_are_respected(self):
        self.company("second.test")
        for name in ("a", "b", "c"):
            self.certificate(name + ".acme.test")
        self.config["crawl_batch"] = 2
        scoped = self.engine.company_scope("company:acme", "acme.test")
        self.assertEqual([target["domain"] for target in scoped["targets"]], ["acme.test", "a.acme.test"])
        self.assertTrue(scoped["truncated"])

    async def test_explicit_web_targets_do_not_claim_seed_or_finish_global_queue(self):
        self.config["seed_urls"] = ["https://unrelated.test/"]
        self.store.enqueue_url("https://unrelated.test/")
        self.store.enqueue_url("https://acme.test/")
        collector = Collector(self.config, self.store)
        collector._resolve = AsyncMock(return_value=([], []))
        collector._can_fetch = AsyncMock(return_value=True)
        path = Path(self.directory.name) / "page.html"
        path.write_text("<html></html>")
        collector.http.get = AsyncMock(return_value=FetchResult(path, 200, {"Server": "nginx/1.24.0"}, "https://acme.test/", True, "fixture"))
        with patch.object(self.store, "enqueue_url", side_effect=AssertionError("global seed")), \
                patch.object(self.store, "crawl_targets", side_effect=AssertionError("global claim")), \
                patch.object(self.store, "company_crawl_candidates", side_effect=AssertionError("global discovery")), \
                patch.object(self.store, "finish_url", side_effect=AssertionError("global completion")):
            result = await collector.collect_web(targets=self.engine.company_scope("company:acme")["targets"])
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["asset_ids"], ["domain:acme.test"])
        self.assertEqual(collector.http.get.await_args.args[0], "https://acme.test/")
        with self.store.connection() as conn:
            self.assertEqual({row[0] for row in conn.execute("SELECT status FROM crawl_urls")}, {"queued"})

    async def test_company_web_job_preserves_global_watermarks_and_reconciles_only_scope(self):
        previous = self.store.update_source("web", watermark="fixture", last_run="2026-01-01T00:00:00Z")
        collect = AsyncMock(return_value={"pages": 1, "observations": 1, "asset_ids": ["domain:redirect.test"], "errors": []})
        self.engine.collector = SimpleNamespace(collect_web=collect)
        with patch.object(self.store, "reconcile", return_value={"alerts": 0}) as reconcile:
            result = await self.engine.run_company("web_probe", "company:acme")
        self.assertTrue(result["sources"][0]["ok"])
        self.assertEqual([target["domain"] for target in collect.await_args.kwargs["targets"]], ["acme.test"])
        self.assertEqual(reconcile.call_args.kwargs["asset_ids"], ["company:acme", "domain:acme.test", "domain:redirect.test"])
        self.assertEqual(self.store.source_state("web"), previous)
        self.assertFalse(self.engine.busy())

    async def test_passive_job_uses_copied_scope_and_shared_quotas_with_private_rotation(self):
        self.config["source_targets"] = [{"domain": "unrelated.test"}]
        self.config["provider_settings"]["shodan"] = {"enabled": True, "query": "country:US"}
        previous_config = copy.deepcopy(self.config)
        previous = self.store.update_source("exposure", watermark="fixture")
        self.store.update_source("exposure_cursors", ctlogs=12)
        quota = self.store.update_source("exposure_ct", ctlogs={"request_times": [123], "targets": {}})
        self.engine.collector = SimpleNamespace(http=object())
        self.engine._drain_staging = AsyncMock(return_value={"processed": 1})

        async def adapter(config, store, http):
            self.assertEqual([row["domain"] for row in config["source_targets"]], ["acme.test"])
            self.assertFalse(config["provider_settings"]["shodan"]["enabled"])
            self.assertEqual(store.source_state("exposure_ct"), quota)
            self.assertEqual(store.source_state("exposure_cursors"), {})
            store.update_source("exposure_cursors", ctlogs=1)
            store.update_source("exposure_ct", ctlogs={"request_times": [123, 456], "targets": {}})
            return {"provider_health": {"ctlogs": {"status": "healthy", "records": 1}}, "errors": []}

        with patch("signalwatch.extension_network.collect_network_sources", new=AsyncMock(side_effect=adapter)):
            result = await self.engine.run_company("passive_scan", "company:acme")
        self.assertTrue(result["sources"][0]["ok"])
        self.assertEqual(self.config, previous_config)
        self.assertEqual(self.store.source_state("exposure"), previous)
        self.assertEqual(self.store.source_state("exposure_cursors"), {"ctlogs": 12})
        self.assertEqual(self.store.source_state("exposure_ct")["ctlogs"]["request_times"], [123, 456])

    async def test_global_cooldown_and_collection_lock_are_observed(self):
        retry_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        previous = self.store.update_source("web", retry_at=retry_at, error="HTTP 429")
        collect = AsyncMock()
        self.engine.collector = SimpleNamespace(collect_web=collect)
        result = await self.engine.run_company("web_probe", "company:acme")
        self.assertEqual(result["sources"][0]["retry_at"], retry_at)
        self.assertEqual(self.store.source_state("web"), previous)
        collect.assert_not_awaited()
        with Path(self.config["db"] + ".collector.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertTrue((await self.engine.run_company("web_probe", "company:acme"))["busy"])
            self.assertTrue((await self.engine.run([]))["busy"])
        self.assertFalse(self.engine.running)

    async def test_scoped_passive_scan_cannot_reset_shared_daily_budget(self):
        import time
        from signalwatch.extension_network import SOURCE_DEFINITIONS

        for definition in SOURCE_DEFINITIONS:
            self.config["provider_settings"][definition["id"]] = {"enabled": definition["id"] == "passive_dns"}
        self.store.update_source("exposure_passive_dns_budget", request_times=[time.time() - 1] * 20)
        http = SimpleNamespace(get=AsyncMock(side_effect=AssertionError("Exceeded shared quota")))
        self.engine.collector = SimpleNamespace(http=http)
        result = await self.engine.run_company("passive_scan", "company:acme")
        self.assertFalse(result["sources"][0]["ok"])
        health = result["sources"][0]["counts"]["provider_health"]["passive_dns"]
        self.assertEqual(health["status"], "deferred")
        self.assertEqual(health["daily_requests_remaining"], 0)
        self.assertIn("retry_at", health)
        http.get.assert_not_awaited()

    async def test_cancellation_keeps_guard_until_started_matching_thread_finishes(self):
        entered, release = threading.Event(), threading.Event()
        self.engine.collector = SimpleNamespace(collect_web=AsyncMock(return_value={"pages": 1, "errors": []}))

        def match(**kwargs):
            entered.set()
            release.wait(5)
            return {"alerts": 0}

        with patch.object(self.store, "reconcile", side_effect=match):
            task = asyncio.create_task(self.engine.run_company("web_probe", "company:acme"))
            try:
                self.assertTrue(await asyncio.to_thread(entered.wait, 2))
                task.cancel()
                await asyncio.sleep(0.01)
                self.assertTrue(self.engine.busy())
                self.assertFalse(task.done())
            finally:
                release.set()
                with self.assertRaises(asyncio.CancelledError):
                    await task
        self.assertFalse(self.engine.busy())
        self.assertFalse(self.engine.current_sources)
