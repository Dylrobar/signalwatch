import asyncio
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from signalwatch.extension_network import SOURCE_DEFINITIONS, collect_network_sources
from signalwatch.http import FetchResult, HTTPError, PublicRequestError
from signalwatch.store import Store


class PassiveDNSBudgetTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.store = Store(self.folder / "store.sqlite")
        self.config = {
            "source_targets": [{"domain": f"target{index}.example.com"} for index in range(23)],
            "public_source_batch": 100,
            "provider_settings": {row["id"]: {"enabled": row["id"] == "passive_dns"} for row in SOURCE_DEFINITIONS},
        }
        self.clock = 1_800_000_000
        clock = patch("signalwatch.extension_network.time.time", side_effect=lambda: self.clock)
        clock.start()
        self.addCleanup(clock.stop)
        self.stage = AsyncMock(return_value={"duplicate": False})
        stage = patch("signalwatch.sourcehub.stage_payload", new=self.stage)
        stage.start()
        self.addCleanup(stage.stop)
        self.http = SimpleNamespace(get=AsyncMock(return_value=self.fetched(b"www.example.com,192.0.2.10\n")))

    def fetched(self, payload, headers=None):
        digest = hashlib.sha256(payload).hexdigest()
        path = self.folder / digest
        path.write_bytes(payload)
        return FetchResult(path, 200, headers or {}, "https://api.hackertarget.com/hostsearch/", True, digest)

    async def collect(self, store=None, http=None):
        return await collect_network_sources(self.config, store or self.store, http or self.http)

    async def test_twenty_requests_are_shared_across_targets_manual_runs_restarts_and_routes(self):
        first = await self.collect()
        health = first["provider_health"]["passive_dns"]
        self.assertEqual(self.http.get.await_count, 20)
        self.assertEqual((health["status"], health["deferred_targets"], health["pending_targets"]), ("healthy", 3, 3))
        self.assertEqual(self.store.source_state("exposure_cursors")["passive_dns"], 20)
        restarted_store = Store(self.folder / "store.sqlite")
        changed_route = SimpleNamespace(get=AsyncMock(return_value=self.http.get.return_value))
        for _ in range(3):
            next_run = await self.collect(restarted_store, changed_route)
            self.assertEqual(next_run["provider_health"]["passive_dns"]["status"], "deferred")
        changed_route.get.assert_not_awaited()
        self.assertEqual(restarted_store.source_state("exposure_cursors")["passive_dns"], 20)
        self.assertEqual(len(restarted_store.source_state("exposure_passive_dns_budget")["request_times"]), 20)
        self.assertTrue(all(call.kwargs["max_attempts"] == 1 and not call.kwargs["allow_redirects"] and not call.kwargs["cache"]
                            for call in self.http.get.await_args_list))

        self.clock += 86400
        await self.collect(restarted_store, changed_route)
        self.assertEqual(changed_route.get.await_count, 20)
        self.assertEqual(changed_route.get.await_args_list[0].kwargs["params"]["q"], "target20.example.com")

    async def test_sliding_window_keeps_newer_requests_and_preserves_other_state(self):
        self.store.update_source("exposure_passive_dns_budget", request_times=[self.clock - 86400] * 7 + [self.clock - 10] * 19,
                                 marker="keep")
        result = await self.collect()
        self.assertEqual(self.http.get.await_count, 1)
        state = self.store.source_state("exposure_passive_dns_budget")
        self.assertEqual(state["marker"], "keep")
        self.assertEqual(len(state["request_times"]), 20)
        self.assertEqual(result["provider_health"]["passive_dns"]["pending_targets"], 22)
        self.assertEqual(self.store.source_state("exposure_cursors")["passive_dns"], 1)
        self.clock += 86391
        await self.collect()
        self.assertEqual(self.http.get.await_count, 20)
        self.assertEqual(self.http.get.await_args_list[1].kwargs["params"]["q"], "target1.example.com")

    async def test_concurrent_collectors_cannot_reserve_the_last_slot_twice(self):
        self.store.update_source("exposure_passive_dns_budget", request_times=[self.clock - 1] * 19)
        await asyncio.gather(self.collect(), self.collect(Store(self.folder / "store.sqlite")))
        self.assertEqual(self.http.get.await_count, 1)
        self.assertEqual(len(self.store.source_state("exposure_passive_dns_budget")["request_times"]), 20)
        self.assertEqual(self.store.source_state("exposure_cursors")["passive_dns"], 1)

    async def test_invalid_target_advances_without_using_quota_or_starving_valid_target(self):
        self.config["source_targets"] = [{"domain": "bad/url"}, {"domain": "valid.example"}]
        self.config["public_source_batch"] = 1
        first = await self.collect()
        self.http.get.assert_not_awaited()
        self.assertEqual(first["provider_health"]["passive_dns"]["status"], "error")
        self.assertEqual(first["provider_health"]["passive_dns"]["pending_targets"], 1)
        self.assertEqual(self.store.source_state("exposure_cursors")["passive_dns"], 1)
        self.assertFalse(self.store.source_state("exposure_passive_dns_budget"))
        await self.collect(Store(self.folder / "store.sqlite"))
        self.http.get.assert_awaited_once()
        self.assertEqual(self.http.get.await_args.kwargs["params"]["q"], "valid.example")
        self.assertEqual(len(self.store.source_state("exposure_passive_dns_budget")["request_times"]), 1)

    async def test_budget_deferred_target_is_not_skipped_when_later_target_is_invalid(self):
        self.config["source_targets"] = [{"domain": "valid.example"}, {"domain": "bad/url"}]
        self.store.update_source("exposure_passive_dns_budget", request_times=[self.clock] * 20)
        self.store.update_source("exposure_cursors", passive_dns=0)
        result = await self.collect()
        self.http.get.assert_not_awaited()
        self.assertEqual(self.store.source_state("exposure_cursors")["passive_dns"], 0)
        self.assertEqual(result["provider_health"]["passive_dns"]["deferred_targets"], 2)
        self.assertEqual(result["errors"], [])
        self.clock += 86400
        await self.collect()
        self.http.get.assert_awaited_once()
        self.assertEqual(self.http.get.await_args.kwargs["params"]["q"], "valid.example")

    async def test_http_200_quota_text_is_deferred_without_staging_or_trying_other_targets(self):
        self.http.get.return_value = self.fetched(b"API count exceeded - Increase Quota with Membership", {"retry-after": "172800"})
        result = await self.collect()
        self.assertEqual(self.http.get.await_count, 1)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["provider_health"]["passive_dns"]["status"], "deferred")
        self.stage.assert_not_awaited()
        self.assertEqual(self.store.source_state("exposure_passive_dns_budget")["retry_at"], self.clock + 172800)
        self.clock += 86401
        await self.collect(Store(self.folder / "store.sqlite"))
        self.assertEqual(self.http.get.await_count, 1)

    async def test_http_429_provider_cooldown_survives_new_http_client(self):
        self.http.get.side_effect = HTTPError(429, "https://api.hackertarget.com/hostsearch/", retry_after=3600)
        result = await self.collect()
        self.assertEqual(self.http.get.await_count, 1)
        self.assertEqual(result["provider_health"]["passive_dns"]["status"], "deferred")
        self.assertEqual(result["errors"], [])
        self.clock += 3599
        replacement = SimpleNamespace(get=AsyncMock(return_value=self.fetched(b"no records found")))
        await self.collect(Store(self.folder / "store.sqlite"), replacement)
        replacement.get.assert_not_awaited()
        self.clock += 1
        await self.collect(http=replacement)
        self.assertEqual(replacement.get.await_count, 19)

    async def test_failed_transport_consumes_one_reserved_slot_without_retry(self):
        self.config["public_source_batch"] = 1
        self.http.get.side_effect = PublicRequestError("Connection failed", "https://api.hackertarget.com/hostsearch/")
        result = await self.collect()
        self.assertEqual(self.http.get.await_count, 1)
        self.assertEqual(self.http.get.await_args.kwargs["max_attempts"], 1)
        self.assertEqual(len(self.store.source_state("exposure_passive_dns_budget")["request_times"]), 1)
        self.assertEqual(result["provider_health"]["passive_dns"]["status"], "error")

    async def test_missing_persistent_store_does_not_issue_unbudgeted_requests(self):
        result = await collect_network_sources(self.config, None, self.http)
        health = result["provider_health"]["passive_dns"]
        self.assertEqual((health["status"], health["requirements"]), ("unconfigured", ["persistent_store"]))
        self.http.get.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
