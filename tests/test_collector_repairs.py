import asyncio
import hashlib
import json
import socket
import ssl
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import aiohttp

from signalwatch.collectors import Collector
from signalwatch.config import DEFAULTS
from signalwatch.extension_developer import SOURCE_DEFINITIONS as DEVELOPERS, collect_developer_sources
from signalwatch.extension_network import SOURCE_DEFINITIONS as EXPOSURE, collect_network_sources
from signalwatch.http import FetchResult, HTTPError, PublicHTTP, PublicRequestError
from signalwatch.store import Store
from test_collectors import CaptureStore
import test_http


class TransientRepairTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = test_http.HTTPRetryTests.asyncSetUp

    async def test_gateway_statuses_retry_with_retry_after_and_bound_attempts(self):
        for status in (502, 504):
            with self.subTest(status=status):
                self.http.host_wait.clear()
                self.waits.clear()
                self.http.session.get.reset_mock()
                self.http.session.get.side_effect = [test_http.Response(status, headers={"Retry-After": "3"}), test_http.Response(200)]
                await self.http.get("https://example.test/index", max_attempts=2)
                self.assertEqual(self.waits, [3])
                self.assertEqual(self.http.session.get.call_count, 2)
                self.http.host_wait.clear()
                self.http.session.get.side_effect = [test_http.Response(status), test_http.Response(status)]
                with self.assertRaises(HTTPError) as error:
                    await self.http.get("https://example.test/index", max_attempts=2)
                self.assertEqual(error.exception.status, status)
                self.assertGreaterEqual(error.exception.retry_after, 1)

    async def test_long_gateway_retry_after_preserves_cooldown_without_sleep(self):
        for status in (502, 504):
            self.http.host_wait.clear()
            self.http.session.get.side_effect = None
            self.http.session.get.return_value = test_http.Response(status, headers={"Retry-After": "120"})
            with self.assertRaises(HTTPError) as error:
                await self.http.get("https://example.test/index", max_attempts=2)
            self.assertEqual(error.exception.retry_after, 120)
        self.assertEqual(self.waits, [])

    async def test_no_cache_lock_is_held_during_retry_sleep(self):
        self.http.session.get.side_effect = [test_http.Response(503, headers={"Retry-After": "2"}), test_http.Response(200)]

        async def sleep(delay):
            self.assertTrue(self.http.locks)
            self.assertTrue(all(not lock.locked() for lock in self.http.locks.values()))
            self.clock += delay

        with patch("signalwatch.http.asyncio.sleep", side_effect=sleep):
            await self.http.get("https://example.test/feed", max_attempts=2)

    async def test_queued_same_key_request_respects_new_host_cooldown(self):
        entered = asyncio.Event()
        release = asyncio.Event()

        class DelayedResponse(test_http.Response):
            async def __aenter__(response):
                entered.set()
                await release.wait()
                return response

        self.http.session.get.return_value = DelayedResponse(503, headers={"Retry-After": "120"})
        first = asyncio.create_task(self.http.get("https://example.test/feed", max_attempts=1))
        await entered.wait()
        second = asyncio.create_task(self.http.get("https://example.test/feed", max_attempts=1))
        # Let the second request reach the held cache lock before releasing it.
        await asyncio.get_running_loop().run_in_executor(None, lambda: None)
        release.set()
        errors = await asyncio.gather(first, second, return_exceptions=True)
        self.assertTrue(all(isinstance(error, HTTPError) for error in errors))
        self.assertEqual([error.retry_after for error in errors], [120, 120])
        self.assertEqual(self.http.session.get.call_count, 1)
        self.assertEqual(self.waits, [])

    async def test_permanent_tls_dns_and_redirect_errors_do_not_repeat(self):
        key = SimpleNamespace(host="example.test", port=443, ssl=True)
        cases = [
            (aiohttp.ClientConnectorCertificateError(key, ssl.SSLCertVerificationError("expired")), "TLS certificate verification failed"),
            (aiohttp.ClientConnectorError(key, socket.gaierror(socket.EAI_NONAME, "not found")), "DNS lookup failed"),
            (aiohttp.TooManyRedirects(SimpleNamespace(real_url="https://example.test/"), ()), "Too many HTTP redirects"),
        ]
        for exception, reason in cases:
            with self.subTest(reason=reason):
                self.http.session.get.reset_mock()
                self.http.session.get.side_effect = exception
                with self.assertRaises(PublicRequestError) as error:
                    await self.http.get("https://example.test/?private=value", max_attempts=4)
                self.assertEqual(str(error.exception), reason + ": https://example.test/")
                self.assertEqual(self.http.session.get.call_count, 1)
        self.assertEqual(self.waits, [])


    async def test_temporary_dns_retries_and_preserves_network_attempt_bound(self):
        key = SimpleNamespace(host="example.test", port=443, ssl=True)
        temporary = aiohttp.ClientConnectorError(key, socket.gaierror(socket.EAI_AGAIN, "temporary secret resolver text"))
        self.http.session.get.side_effect = [temporary, test_http.Response(200)]
        await self.http.get("https://example.test/feed", max_attempts=2)
        self.assertEqual(self.http.session.get.call_count, 2)
        self.assertEqual(len(self.waits), 1)
        self.http.session.get.reset_mock()
        self.waits.clear()
        self.http.session.get.side_effect = temporary
        with self.assertRaises(PublicRequestError) as raised:
            await self.http.get("https://example.test/feed?private=value", max_attempts=3)
        self.assertEqual(str(raised.exception), "DNS lookup failed: https://example.test/feed")
        self.assertEqual(self.http.session.get.call_count, 3)
        self.assertEqual(len(self.waits), 2)

    async def test_permanent_dns_codes_fast_fail(self):
        key = SimpleNamespace(host="example.test", port=443, ssl=True)
        for code in {socket.EAI_NONAME, getattr(socket, "EAI_NODATA", socket.EAI_NONAME)}:
            self.http.session.get.reset_mock()
            self.http.session.get.side_effect = aiohttp.ClientConnectorError(key, socket.gaierror(code, "not found"))
            with self.assertRaises(PublicRequestError):
                await self.http.get("https://example.test/feed", max_attempts=4)
            self.assertEqual(self.http.session.get.call_count, 1)
        self.assertEqual(self.waits, [])

    async def test_queued_same_key_short_cooldown_waits_without_consuming_attempt(self):
        # Both a single-attempt reader and a reader needing its full retry budget
        # must succeed after a request ahead of it establishes a short cooldown.
        for budget in (1, 2):
            with self.subTest(budget=budget):
                self.http.host_wait.clear()
                self.http.locks.clear()
                self.waits.clear()
                self.http.session.get.reset_mock()
                entered, release, queued = asyncio.Event(), asyncio.Event(), asyncio.Event()

                class QueueObservedLock(asyncio.Lock):
                    async def acquire(lock):
                        if lock.locked():
                            queued.set()
                        return await super().acquire()

                class DelayedResponse(test_http.Response):
                    async def __aenter__(response):
                        entered.set()
                        await release.wait()
                        return response

                url = "https://example.test/feed"
                key = hashlib.sha256((url + "\n").encode()).hexdigest()
                self.http.locks[key] = QueueObservedLock()
                responses = [DelayedResponse(503, headers={"Retry-After": "3"})]
                if budget == 2:
                    responses.append(test_http.Response(502, headers={"Retry-After": "2"}))
                responses.append(test_http.Response(200))
                self.http.session.get.side_effect = responses

                async def sleep(delay):
                    self.assertTrue(all(not lock.locked() for lock in self.http.locks.values()))
                    self.waits.append(delay)
                    self.clock += delay

                with patch("signalwatch.http.asyncio.sleep", side_effect=sleep):
                    first = asyncio.create_task(self.http.get(url, max_attempts=1))
                    await entered.wait()
                    second = asyncio.create_task(self.http.get(url, max_attempts=budget))
                    await queued.wait()
                    release.set()
                    results = await asyncio.gather(first, second, return_exceptions=True)
                self.assertIsInstance(results[0], HTTPError)
                self.assertIsInstance(results[1], FetchResult)
                self.assertEqual(results[1].status, 200)
                self.assertEqual(self.http.session.get.call_count, 1 + budget)
                self.assertEqual(self.waits, [3] if budget == 1 else [3, 2])

    async def test_temporary_dns_does_not_implicitly_retry_post(self):
        key = SimpleNamespace(host="example.test", port=443, ssl=True)
        self.http.session.post.side_effect = aiohttp.ClientConnectorError(key, socket.gaierror(socket.EAI_AGAIN, "temporary"))
        with self.assertRaises(PublicRequestError):
            await self.http.post("https://example.test/search", json={"q": "synthetic"})
        self.assertEqual(self.http.session.post.call_count, 1)
        self.assertEqual(self.waits, [])


class ProviderRepairTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "test.db")
        self.staged = AsyncMock(return_value={"duplicate": False})
        self.stage_patch = patch("signalwatch.sourcehub.stage_payload", self.staged)
        self.stage_patch.start()
        self.addCleanup(self.stage_patch.stop)

    def response(self, url, payload=b"[]"):
        path = Path(self.temp.name) / hashlib.sha256(payload).hexdigest()
        path.write_bytes(payload)
        return FetchResult(path, 200, {"Content-Type": "application/json"}, url, True, "digest")

    def config(self, definitions, provider):
        return {"source_targets": [{"domain": name} for name in ("a.test", "b.test", "c.test", "d.test")],
                "public_source_batch": 3,
                "provider_settings": {row["id"]: {"enabled": row["id"] == provider} for row in definitions}}

    async def test_crtsh_rotates_fairly_after_partial_failure_then_revisits(self):
        config = self.config(EXPOSURE, "crtsh")
        recovered = False
        requested = []

        async def fetch(url, **kwargs):
            name = kwargs["params"]["q"]
            requested.append(name)
            self.assertEqual(kwargs["max_attempts"], 2)
            if name == "%.b.test" and not recovered:
                raise HTTPError(502, url + "?private=value", retry_after=120)
            return self.response(url)

        http = SimpleNamespace(get=AsyncMock(side_effect=fetch))
        first = await collect_network_sources(config, self.store, http)
        self.assertEqual(first["provider_health"]["crtsh"]["status"], "partial")
        self.assertEqual(self.store.source_state("exposure_cursors")["crtsh"], 3)
        self.assertEqual(first["pending_targets"], 1)
        self.assertIn("HTTP 502 Bad Gateway", first["errors"][0])
        self.assertNotIn("private", first["errors"][0])
        recovered = True
        await collect_network_sources(config, Store(self.store.path), http)
        self.assertEqual(requested, ["%.a.test", "%.b.test", "%.c.test", "%.d.test", "%.a.test", "%.b.test"])

    async def test_crtsh_all_failed_still_rotates(self):
        config = self.config(EXPOSURE, "crtsh")
        self.store.update_source("exposure_cursors", crtsh=1)
        http = SimpleNamespace(get=AsyncMock(side_effect=HTTPError(504, "https://crt.sh/")))
        result = await collect_network_sources(config, self.store, http)
        self.assertEqual(result["provider_health"]["crtsh"]["status"], "error")
        self.assertEqual(self.store.source_state("exposure_cursors")["crtsh"], 0)
        self.assertEqual(result["records"], 0)

    async def test_wayback_failure_keeps_safe_reason_and_fair_rotation(self):
        config = self.config(DEVELOPERS, "wayback_cdx")
        config["public_source_batch"] = 2
        self.store.update_source("developer_sources", cursors={"targets:wayback_cdx": 1})
        http = SimpleNamespace(get=AsyncMock(side_effect=PublicRequestError("Connection timed out", "https://web.archive.org/cdx/search/cdx?private=value")))
        result = await collect_developer_sources(config, self.store, http)
        self.assertEqual(result["provider_health"]["wayback_cdx"]["status"], "error")
        self.assertIn("Connection timed out: https://web.archive.org/cdx/search/cdx", result["errors"][0])
        self.assertNotIn("private", json.dumps(result))
        self.assertEqual(self.store.source_state("developer_sources")["cursors"]["targets:wayback_cdx"], 3)
        recovered = SimpleNamespace(get=AsyncMock(side_effect=lambda url, **kwargs: self.response(url)))
        await collect_developer_sources(config, Store(self.store.path), recovered)
        self.assertEqual([call.kwargs["params"]["url"] for call in recovered.get.await_args_list], ["d.test/*", "a.test/*"])
        self.assertEqual(self.store.source_state("developer_sources")["cursors"]["targets:wayback_cdx"], 1)

    async def test_commoncrawl_catalog_failure_rotates_selected_domains(self):
        config = self.config(DEVELOPERS, "commoncrawl")
        self.store.update_source("developer_sources", cursors={"targets:commoncrawl": 1})
        http = SimpleNamespace(get=AsyncMock(side_effect=HTTPError(504, "https://index.commoncrawl.org/collinfo.json")))
        result = await collect_developer_sources(config, self.store, http)
        self.assertEqual(result["provider_health"]["commoncrawl"]["status"], "error")
        self.assertEqual(self.store.source_state("developer_sources")["cursors"]["targets:commoncrawl"], 0)

    async def test_commoncrawl_partial_index_failure_rotates_batch(self):
        config = self.config(DEVELOPERS, "commoncrawl")
        index = "https://index.commoncrawl.org/CC-MAIN-2026-40-index"
        config["provider_settings"]["commoncrawl"]["index_url"] = index

        async def fetch(url, **kwargs):
            if kwargs["params"]["url"] == "b.test/*":
                raise HTTPError(504, url)
            return self.response(url, b'{"url":"https://a.test/archive"}\n')

        result = await collect_developer_sources(config, self.store, SimpleNamespace(get=AsyncMock(side_effect=fetch)))
        self.assertEqual(result["provider_health"]["commoncrawl"]["status"], "partial")
        self.assertEqual(result["staged"], 2)
        self.assertEqual(self.store.source_state("developer_sources")["cursors"].get("targets:commoncrawl", 0), 3)


class RobotsRepairTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = CaptureStore()
        self.collector = Collector({**DEFAULTS, "cache_dir": self.temp.name, "seed_urls": []}, self.store)
        self.collector._resolve = AsyncMock(return_value=([], []))

    async def test_concurrent_failed_robots_is_cached_without_granting_permission(self):
        error = PublicRequestError("Connection timed out", "https://a.test/robots.txt")
        self.collector.http.get = AsyncMock(side_effect=error)
        results = await asyncio.gather(*(self.collector._crawl({"url": f"https://a.test/{index}"}) for index in range(3)))
        self.assertEqual(self.collector.http.get.await_count, 1)
        self.assertTrue(all(row["pages"] == 0 and "Connection timed out" in row["error"] for row in results))
        self.assertEqual(len(self.store.finished), 3)

    async def test_failed_robots_is_retried_next_collection_run(self):
        self.store.crawl_targets = lambda *args: [{"url": "https://a.test/"}]
        self.collector.http.get = AsyncMock(side_effect=ValueError("Response exceeds robots limit"))
        for _ in range(2):
            with self.assertRaisesRegex(RuntimeError, "All crawl targets failed"):
                await self.collector.collect_web()
        self.assertEqual(self.collector.http.get.await_count, 2)

    async def test_http_robots_policy_is_preserved(self):
        for status, allowed in ((401, False), (403, False), (404, True), (503, None)):
            self.collector.robots.clear()
            self.collector.robot_errors.clear()
            self.collector.http.get = AsyncMock(side_effect=HTTPError(status, "https://a.test/robots.txt"))
            if allowed is None:
                with self.assertRaises(HTTPError):
                    await self.collector._can_fetch("https://a.test/page")
            else:
                self.assertEqual(await self.collector._can_fetch("https://a.test/page"), allowed)
                self.assertEqual(await self.collector._can_fetch("https://a.test/other"), allowed)
            self.assertEqual(self.collector.http.get.await_count, 1)

    async def test_partial_page_errors_remain_visible_and_are_not_all_failed(self):
        self.store.crawl_targets = lambda *args: [{"url": "https://a.test/"}]
        path = Path(self.temp.name) / "html"
        path.write_text('<html><a href="/blocked">next</a></html>')
        self.collector._can_fetch = AsyncMock(side_effect=[True, False])
        self.collector.http.get = AsyncMock(return_value=FetchResult(path, 200, {"Content-Type": "text/html"}, "https://a.test/", True, "digest"))
        result = await self.collector.collect_web()
        self.assertEqual(result["pages"], 1)
        self.assertEqual(result["targets"], 1)
        self.assertIn("robots.txt disallows", result["errors"][0])
        self.assertIn("robots.txt disallows", self.store.finished["https://a.test/"])
        self.assertEqual(self.collector.http.get.await_count, 1)
