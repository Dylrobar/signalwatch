import asyncio
import json
import os
import tempfile
import traceback
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import aiohttp
from multidict import CIMultiDict

from signalwatch.config import DEFAULTS
from signalwatch.http import HTTPError, PublicHTTP, PublicRequestError


class Response:
    def __init__(self, status=200, *, headers=None, url="https://example.test/feed", entered=None, release=None):
        self.status = status
        self.headers = headers or {}
        self.url = url
        self.entered = entered
        self.release = release
        self.content = Mock()
        self.content.read = AsyncMock(side_effect=AssertionError("Error pages must not be read"))

        async def chunks(size):
            yield b'{"ok":true}'

        self.content.iter_chunked = chunks

    async def __aenter__(self):
        if self.entered:
            self.entered.set()
        if self.release:
            await self.release.wait()
        return self

    async def __aexit__(self, *exc):
        pass


class ProxyHTTPTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = 1000.0
        self.waits = []
        self.on_sleep = None
        self.real_sleep = asyncio.sleep
        clock = SimpleNamespace(monotonic=lambda: self.clock, time=lambda: 1700000000 + self.clock)
        env = {
            "SIGNALWATCH_PROXY_LIST_JSON": json.dumps([
                "first.example.test:8080", "second.example.test:8080", "third.example.test:8080",
            ]),
            "SIGNALWATCH_PROXY_LIST_FILE": "",
            "SIGNALWATCH_PROXY_USERNAME": "fixture-user",
            "SIGNALWATCH_PROXY_PASSWORD": "fixture-password",
        }

        async def sleep(delay):
            if delay:
                self.waits.append(delay)
                if self.on_sleep:
                    self.on_sleep()
                self.clock += delay
            await self.real_sleep(0)

        for patcher in (patch.dict(os.environ, env), patch("signalwatch.http.time", clock),
                        patch("signalwatch.proxies.time", clock),
                        patch("signalwatch.http.asyncio.sleep", side_effect=sleep),
                        patch("signalwatch.http.random.random", return_value=0)):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.http = self.client()

    def client(self, **overrides):
        http = PublicHTTP({**DEFAULTS, "cache_dir": self.temp.name, **overrides})
        http.session = Mock()
        return http

    def used_proxies(self, http=None):
        return [call.kwargs.get("proxy") for call in (http or self.http).session.get.call_args_list]

    def proxy_error(self, status, headers=None):
        return aiohttp.ClientHttpProxyError(Mock(), (), status=status,
                                           message="fixture-password must stay private", headers=headers)

    async def test_new_requests_rotate_and_credentials_only_use_proxy_auth(self):
        self.http.session.get.return_value = Response()
        for index in range(4):
            await self.http.get(f"https://example.test/{index}", headers={"Accept": "application/json"})
        self.assertEqual(self.used_proxies(), ["http://first.example.test:8080", "http://second.example.test:8080",
                                              "http://third.example.test:8080", "http://first.example.test:8080"])
        for call in self.http.session.get.call_args_list:
            self.assertEqual(call.kwargs["headers"], {"Accept": "application/json"})
            self.assertEqual(call.kwargs["proxy_auth"].login, "fixture-user")
            self.assertEqual(call.kwargs["proxy_auth"].password, "fixture-password")
            self.assertNotIn("fixture-user", call.kwargs["proxy"])
        for path in Path(self.temp.name).iterdir():
            self.assertNotIn(b"fixture-password", path.read_bytes())

    async def test_transport_failure_uses_another_endpoint_within_attempt_budget(self):
        self.http.session.get.side_effect = [asyncio.TimeoutError("private failure"), Response()]
        await self.http.get("https://example.test/feed", max_attempts=2)
        self.assertEqual(self.used_proxies(), ["http://first.example.test:8080", "http://second.example.test:8080"])
        self.assertEqual(self.waits, [1])

    async def test_transport_failure_stops_at_request_budget(self):
        self.http.session.get.side_effect = asyncio.TimeoutError("private failure")
        with self.assertRaisesRegex(PublicRequestError, "Connection timed out"):
            await self.http.get("https://example.test/feed", max_attempts=2)
        self.assertEqual(len(self.used_proxies()), 2)
        self.assertNotIn(None, self.used_proxies())

    async def test_exhausted_pool_has_no_direct_fallback(self):
        self.http.session.get.side_effect = asyncio.TimeoutError("private failure")
        with self.assertRaises(PublicRequestError) as raised:
            await self.http.get("https://example.test/feed", max_attempts=4)
        self.assertEqual(len(self.used_proxies()), 3)
        self.assertNotIn(None, self.used_proxies())
        self.assertGreater(raised.exception.retry_after, 0)

    async def test_origin_authentication_access_and_missing_paths_fail_without_rotation(self):
        for status in (401, 403, 404):
            with self.subTest(status=status):
                http = self.client()
                response = Response(status)
                http.session.get.return_value = response
                with self.assertRaises(HTTPError) as raised:
                    await http.get("https://example.test/feed")
                self.assertEqual(raised.exception.status, status)
                self.assertEqual(self.used_proxies(http), ["http://first.example.test:8080"])
                response.content.read.assert_not_awaited()

    async def test_origin_429_retries_same_proxy_and_shares_host_cooldown(self):
        self.http.session.get.side_effect = [Response(429, headers={"retry-after": "7"}), Response()]
        await self.http.get("https://example.test/feed")
        self.assertEqual(self.used_proxies(), ["http://first.example.test:8080"] * 2)
        self.assertEqual(self.waits, [7])
        self.http.session.get.side_effect = None
        self.http.session.get.return_value = Response(429, headers={"Retry-After": "120"})
        with self.assertRaises(HTTPError):
            await self.http.get("https://example.test/limited")
        with self.assertRaises(HTTPError) as raised:
            await self.http.get("https://example.test/other")
        self.assertEqual(raised.exception.retry_after, 120)
        self.assertEqual(self.http.session.get.call_count, 3)

    async def test_rate_limited_403_fails_immediately_and_retains_reset_deadline(self):
        self.http.session.get.return_value = Response(403, headers={
            "x-ratelimit-remaining": "0", "x-ratelimit-reset": str(1700000000 + self.clock + 125),
        })
        with self.assertRaises(HTTPError) as raised:
            await self.http.get("https://example.test/feed")
        self.assertEqual(raised.exception.retry_after, 125)
        self.assertEqual(self.http.session.get.call_count, 1)

    async def test_proxy_connect_407_is_redacted_failfast_and_disables_pool(self):
        self.http.session.get.side_effect = self.proxy_error(407)
        try:
            await self.http.get("https://example.test/feed?key=private-query")
        except PublicRequestError as error:
            message = "".join(traceback.format_exception(error))
            self.assertNotIn("fixture-password", message)
            self.assertNotIn("private-query", str(error))
            self.assertIn("Proxy HTTP 407", str(error))
        else:
            self.fail("Proxy authentication rejection did not fail")
        with self.assertRaisesRegex(PublicRequestError, "authentication was rejected"):
            await self.http.get("https://another.test/feed")
        self.assertEqual(self.http.session.get.call_count, 1)

    async def test_proxy_http_407_also_disables_pool(self):
        self.http.session.get.return_value = Response(407)
        with self.assertRaises(HTTPError) as raised:
            await self.http.get("http://example.test/feed")
        self.assertEqual(raised.exception.status, 407)
        with self.assertRaisesRegex(PublicRequestError, "authentication was rejected"):
            await self.http.get("http://another.test/feed")
        self.assertEqual(self.http.session.get.call_count, 1)

    async def test_proxy_connect_403_denial_does_not_rotate(self):
        self.http.session.get.side_effect = self.proxy_error(403)
        with self.assertRaisesRegex(PublicRequestError, "Proxy HTTP 403"):
            await self.http.get("https://example.test/feed")
        self.assertEqual(self.http.session.get.call_count, 1)

    async def test_proxy_429_defers_entire_pool_across_destination_hosts(self):
        self.http.session.get.side_effect = self.proxy_error(429, CIMultiDict({"retry-after": "120"}))
        with self.assertRaises(PublicRequestError) as raised:
            await self.http.get("https://example.test/feed")
        self.assertEqual(raised.exception.retry_after, 120)
        with self.assertRaises(PublicRequestError) as raised:
            await self.http.get("https://another.test/feed")
        self.assertEqual(raised.exception.retry_after, 120)
        self.assertEqual(self.http.session.get.call_count, 1)

    async def test_proxy_503_with_retry_after_defers_pool_without_endpoint_failover(self):
        self.http.session.get.side_effect = self.proxy_error(503, CIMultiDict({"retry-after": "120"}))
        with self.assertRaises(PublicRequestError) as raised:
            await self.http.get("https://example.test/feed")
        self.assertEqual(raised.exception.retry_after, 120)
        self.assertIn("Proxy HTTP 503", str(raised.exception))
        with self.assertRaises(PublicRequestError) as raised:
            await self.http.get("https://another.test/feed")
        self.assertEqual(raised.exception.retry_after, 120)
        self.assertEqual(self.http.session.get.call_count, 1)

    async def test_retained_retry_endpoint_honors_pool_deferral_from_another_request(self):
        self.http.session.get.side_effect = [Response(429, headers={"Retry-After": "2"}), Response()]
        self.on_sleep = lambda: self.http.proxy_pool.defer(120)
        with self.assertRaises(PublicRequestError) as raised:
            await self.http.get("https://example.test/feed")
        self.assertEqual(raised.exception.retry_after, 118)
        self.assertEqual(self.http.session.get.call_count, 1)

    async def test_retained_retry_endpoint_honors_pool_auth_rejection_from_another_request(self):
        self.http.session.get.side_effect = [Response(503, headers={"Retry-After": "2"}), Response()]
        self.on_sleep = self.http.proxy_pool.reject_auth
        with self.assertRaisesRegex(PublicRequestError, "authentication was rejected"):
            await self.http.get("https://example.test/feed")
        self.assertEqual(self.http.session.get.call_count, 1)

    async def test_headers_remain_case_insensitive_through_200_and_304_cache(self):
        self.http.session.get.side_effect = [
            Response(headers={"content-type": "application/json", "etag": '"v1"',
                              "last-modified": "Mon, 19 Oct 2026 00:00:00 GMT", "set-cookie": "private-cookie"}),
            Response(304, headers={"ETAG": '"v2"', "cache-control": "max-age=60"}),
        ]
        initial = await self.http.get("https://example.test/feed")
        self.assertEqual(initial.headers["Content-Type"], "application/json")
        cached = await self.http.get("https://example.test/feed")
        self.assertEqual(cached.status, 304)
        self.assertEqual(cached.headers["Content-Type"], "application/json")
        self.assertEqual(cached.headers["ETag"], '"v2"')
        self.assertEqual(cached.headers["Cache-Control"], "max-age=60")
        self.assertNotIn("Set-Cookie", cached.headers)
        self.assertEqual(self.http.session.get.call_args.kwargs["headers"]["If-None-Match"], '"v1"')
        self.assertIn("If-Modified-Since", self.http.session.get.call_args.kwargs["headers"])

    async def test_long_origin_cooldown_survives_new_public_http_instance(self):
        self.http.session.get.return_value = Response(429, headers={"Retry-After": "120"})
        with self.assertRaises(HTTPError):
            await self.http.get("https://example.test/feed")
        self.clock += 15
        replacement = self.client()
        with self.assertRaises(HTTPError) as raised:
            await replacement.get("https://example.test/different")
        self.assertEqual(raised.exception.retry_after, 105)
        replacement.session.get.assert_not_called()
        files = list(Path(self.temp.name).glob("cooldown-*.json"))
        self.assertEqual(len(files), 1)
        self.assertEqual(set(json.loads(files[0].read_text())), {"until", "status"})

    async def test_origin_concurrency_limit_is_shared_across_proxies(self):
        self.http = self.client(per_host=2)
        active = 0
        maximum = 0
        occupied = asyncio.Event()
        release = asyncio.Event()

        class TrackingResponse(Response):
            async def __aenter__(response):
                nonlocal active, maximum
                active += 1
                maximum = max(maximum, active)
                if active == 2:
                    occupied.set()
                await release.wait()
                return response

            async def __aexit__(response, *exc):
                nonlocal active
                active -= 1

        self.http.session.get.side_effect = lambda *args, **kwargs: TrackingResponse()
        tasks = [asyncio.create_task(self.http.get(f"https://example.test/{index}")) for index in range(4)]
        try:
            await asyncio.wait_for(occupied.wait(), timeout=1)
            await self.real_sleep(0)
            self.assertEqual(self.http.session.get.call_count, 2)
        finally:
            release.set()
            await asyncio.gather(*tasks)
        self.assertEqual(maximum, 2)
        self.assertEqual(self.http.session.get.call_count, 4)
        self.assertGreater(len(set(self.used_proxies())), 1)

    async def test_queued_request_rechecks_429_cooldown_after_acquiring_origin_slot(self):
        self.http = self.client(per_host=1)
        entered = asyncio.Event()
        release = asyncio.Event()
        self.http.session.get.side_effect = [Response(429, headers={"Retry-After": "120"},
                                                      entered=entered, release=release), Response()]
        first = asyncio.create_task(self.http.get("https://example.test/first", max_attempts=1))
        await asyncio.wait_for(entered.wait(), timeout=1)
        second = asyncio.create_task(self.http.get("https://example.test/second", max_attempts=1))
        await self.real_sleep(0)
        release.set()
        errors = await asyncio.gather(first, second, return_exceptions=True)
        self.assertTrue(all(isinstance(error, HTTPError) and error.status == 429 for error in errors), errors)
        self.assertEqual(self.http.session.get.call_count, 1)
        self.assertEqual(self.waits, [])


if __name__ == "__main__":
    unittest.main()
