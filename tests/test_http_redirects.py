import asyncio
import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import aiohttp
from multidict import CIMultiDict

from signalwatch.config import DEFAULTS
from signalwatch.http import HTTPError, PublicHTTP, PublicRequestError
from signalwatch.proxies import ProxyPool


class Response:
    def __init__(self, status, url, headers=None, enter=None, body=b'{"ok":true}'):
        self.status, self.url, self.headers = status, url, headers or {}
        self.content = self
        self.enter = enter
        self.body = body

    async def __aenter__(self):
        if self.enter:
            await self.enter()
        return self

    async def __aexit__(self, *args):
        pass

    async def iter_chunked(self, size):
        yield self.body


class RedirectTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        env = patch.dict(os.environ, {}, clear=True)
        env.start()
        self.addCleanup(env.stop)
        self.http = PublicHTTP({**DEFAULTS, "cache_dir": self.temp.name})
        self.http.session = Mock()

    async def test_new_redirector_cannot_reach_a_cooling_destination(self):
        target = "https://destination.example.test/feed"
        self.http.session.get.side_effect = [
            Response(302, "https://first.example.test/", {"Location": target}),
            Response(429, target, {"Retry-After": "120"}),
            Response(302, "https://second.example.test/", {"Location": target}),
        ]
        for start in ("first", "second"):
            with self.assertRaises(HTTPError) as raised:
                await self.http.get(f"https://{start}.example.test/", max_attempts=1)
            self.assertEqual(raised.exception.status, 429)
            self.assertGreater(raised.exception.retry_after, 119)
        self.assertEqual(self.http.session.get.call_count, 3)
        self.assertEqual([call.args[0] for call in self.http.session.get.call_args_list].count(target), 1)

    async def test_changed_redirect_target_cannot_revalidate_another_resources_body(self):
        start = "https://directory.example.test/company"
        original = "https://acme.example.test/"
        # ETags are scoped to a resource, so two destinations may legitimately
        # use the same value for entirely different company pages.
        for replacement in ("https://nebula.example.test/", "https://acme.example.test/new-company"):
            with self.subTest(replacement=replacement):
                self.http.session.get.side_effect = [
                    Response(302, start, {"Location": original}),
                    Response(200, original, {"ETag": '"1"', "Server": "acme-server"}, body=b"Acme technology"),
                ]
                await self.http.get(start, force=True)

                def changed_destination(url, *, headers, **options):
                    if url == start:
                        return Response(302, url, {"Location": replacement})
                    if headers.get("If-None-Match") == '"1"':
                        return Response(304, url)
                    return Response(200, url, {"ETag": '"1"', "Server": "nebula-server"}, body=b"Nebula technology")

                self.http.session.get.side_effect = changed_destination
                result = await self.http.get(start)
                self.assertEqual(result.url, replacement)
                self.assertEqual(result.path.read_bytes(), b"Nebula technology")
                self.assertEqual(result.headers["Server"], "nebula-server")
                self.assertTrue(result.changed)

    async def test_stable_redirect_revalidates_only_its_cached_destination(self):
        start, target = "https://directory.example.test/company", "https://acme.example.test/"
        self.http.session.get.side_effect = [
            Response(302, start, {"Location": target}),
            Response(200, target, {"ETag": '"acme"'}, body=b"Acme technology"),
            Response(302, start, {"Location": target}),
            Response(304, target),
        ]
        await self.http.get(start)
        result = await self.http.get(start)
        initial, destination = self.http.session.get.call_args_list[-2:]
        self.assertNotIn("If-None-Match", initial.kwargs["headers"])
        self.assertEqual(destination.kwargs["headers"]["If-None-Match"], '"acme"')
        self.assertEqual(result.status, 304)
        self.assertEqual(result.path.read_bytes(), b"Acme technology")

    async def test_last_modified_is_scoped_to_cached_resource_and_unsolicited_304_is_rejected(self):
        start, target = "https://directory.example.test/company", "https://nebula.example.test/"
        self.http.session.get.side_effect = [
            Response(200, start, {"Last-Modified": "Tue, 20 Oct 2026 00:00:00 GMT"}, body=b"Acme technology"),
            Response(302, start, {"Location": target}),
            Response(304, target),
        ]
        saved = await self.http.get(start)
        with self.assertRaisesRegex(PublicRequestError, "304 without a usable cached response"):
            await self.http.get(start)
        original, destination = self.http.session.get.call_args_list[-2:]
        self.assertIn("If-Modified-Since", original.kwargs["headers"])
        self.assertNotIn("If-Modified-Since", destination.kwargs["headers"])
        self.assertEqual(saved.path.read_bytes(), b"Acme technology")

    async def test_redirect_destination_cooldown_is_restored_from_disk(self):
        self.http._cooldown("destination.example.test", 503, 120)
        replacement = PublicHTTP({**DEFAULTS, "cache_dir": self.temp.name})
        replacement.session = Mock()
        replacement.session.get.return_value = Response(302, "https://first.example.test/", {"Location": "https://destination.example.test/"})
        with self.assertRaises(HTTPError) as raised:
            await replacement.get("https://first.example.test/", max_attempts=1)
        self.assertEqual(raised.exception.status, 503)
        replacement.session.get.assert_called_once()

    async def test_distinct_redirectors_share_destination_concurrency_and_release_old_slots(self):
        self.http.config["per_host"] = 1
        entered, release = asyncio.Event(), asyncio.Event()
        destination_calls = 0

        async def hold_destination():
            entered.set()
            await release.wait()

        def request(url, **kwargs):
            nonlocal destination_calls
            if "destination.example.test" in url:
                destination_calls += 1
                return Response(200, url, enter=hold_destination)
            return Response(302, url, {"Location": "https://destination.example.test/"})

        self.http.session.get.side_effect = request
        tasks = [asyncio.create_task(self.http.get(f"https://{host}.example.test/", max_attempts=1)) for host in ("first", "second")]
        try:
            await asyncio.wait_for(entered.wait(), 1)
            await asyncio.sleep(0)
            self.assertEqual(destination_calls, 1)
            self.assertFalse(self.http.host_slots["first.example.test"].locked())
            self.assertFalse(self.http.host_slots["second.example.test"].locked())
        finally:
            release.set()
            await asyncio.gather(*tasks)
        self.assertEqual(destination_calls, 2)

    async def test_cross_origin_strips_request_and_configured_auth_and_explicit_cookies(self):
        self.http.config["headers"] = {"Authorization": "Bearer configured-fixture", "Cookie": "fixture=value", "X-Public": "public"}
        self.http.session.get.side_effect = [
            Response(302, "https://first.example.test/start", {"Location": "/same"}),
            Response(302, "https://first.example.test/same", {"Location": "https://second.example.test/final"}),
            Response(200, "https://second.example.test/final"),
        ]
        await self.http.get("https://first.example.test/start", headers={"authorization": "Bearer request-fixture"}, max_attempts=1)
        first, same, other = [call.kwargs["headers"] for call in self.http.session.get.call_args_list]
        for headers in (first, same):
            self.assertEqual(headers["Authorization"], "Bearer request-fixture")
            self.assertEqual(headers["Cookie"], "fixture=value")
        self.assertNotIn("Authorization", other)
        self.assertNotIn("Cookie", other)
        self.assertEqual(other["X-Public"], "public")

    async def test_url_auth_is_retained_same_origin_and_removed_cross_origin(self):
        self.http.session.get.side_effect = [
            Response(302, "https://first.example.test/start", {"Location": "/same"}),
            Response(302, "https://first.example.test/same", {"Location": "https://second.example.test/final"}),
            Response(200, "https://second.example.test/final"),
        ]
        await self.http.get("https://fixture:fixture@first.example.test/start", max_attempts=1)
        first, same, other = self.http.session.get.call_args_list
        self.assertEqual(first.kwargs["auth"], same.kwargs["auth"])
        self.assertNotIn("auth", other.kwargs)
        self.assertNotIn("fixture", first.args[0])

    async def test_cross_origin_drops_provider_api_keys_but_same_origin_retains_them(self):
        credentials = {"apiKey": "fixture-nvd", "X-API-Key": "fixture-provider", "Auth-Key": "fixture-urlhaus",
                       "X-Auth-Token": "fixture-token", "API-KEY": "fixture-zoom", "Key": "fixture-greynoise"}
        self.http.config["headers"] = {"apiKey": credentials["apiKey"], "Accept": "application/json"}
        self.http.session.get.side_effect = [
            Response(302, "https://first.example.test/start", {"Location": "/same"}),
            Response(302, "https://first.example.test/same", {"Location": "https://second.example.test/final"}),
            Response(200, "https://second.example.test/final"),
        ]
        await self.http.get("https://first.example.test/start", headers=credentials, max_attempts=1)
        first, same, other = [call.kwargs["headers"] for call in self.http.session.get.call_args_list]
        for headers in (first, same):
            for name, value in credentials.items():
                self.assertEqual(headers[name], value)
        for name in credentials:
            self.assertNotIn(name, other)
        self.assertEqual(other["Accept"], "application/json")

    async def test_session_defaults_do_not_restore_removed_credentials(self):
        self.http.config["headers"] = {"authorization": "Bearer configured-fixture", "Cookie": "fixture=value"}
        with patch("signalwatch.http.aiohttp.TCPConnector"), patch("signalwatch.http.aiohttp.ClientSession") as session:
            await self.http.__aenter__()
        supplied = CIMultiDict(session.call_args.kwargs["headers"])
        self.assertNotIn("Authorization", supplied)
        self.assertNotIn("Cookie", supplied)

    async def test_provider_key_is_dropped_for_port_or_scheme_change(self):
        for target in ("http://origin.example.test/final", "https://origin.example.test:8443/final"):
            with self.subTest(target=target):
                self.http.session.get.reset_mock()
                self.http.session.get.side_effect = [
                    Response(302, "https://origin.example.test/start", {"Location": target}),
                    Response(200, target),
                ]
                await self.http.get("https://origin.example.test/start", headers={"aPi_KeY": "fixture-secret"})
                first, redirected = self.http.session.get.call_args_list
                self.assertEqual(first.kwargs["headers"]["api_key"], "fixture-secret")
                self.assertNotIn("api_key", redirected.kwargs["headers"])

    async def test_relative_location_uri_fallback_and_encoding(self):
        self.http.session.get.side_effect = [
            Response(301, "https://origin.example.test/path/start", {"location": "../next page"}),
            Response(307, "https://origin.example.test/next%20page", {"URI": "?page=2"}),
            Response(200, "https://origin.example.test/next%20page?page=2"),
        ]
        result = await self.http.get("https://origin.example.test/path/start", max_attempts=1)
        self.assertEqual([call.args[0] for call in self.http.session.get.call_args_list], [
            "https://origin.example.test/path/start", "https://origin.example.test/next%20page", "https://origin.example.test/next%20page?page=2",
        ])
        self.assertEqual(result.url, "https://origin.example.test/next%20page?page=2")
        self.assertTrue(all(call.kwargs["allow_redirects"] is False for call in self.http.session.get.call_args_list))

    async def test_redirect_count_is_bounded_without_retry_or_proxy_rotation(self):
        self.http.proxy_pool = ProxyPool.from_env({"SIGNALWATCH_PROXY_LIST_JSON": '["one.example.test:8080", "two.example.test:8080"]'})
        self.http.session.get.side_effect = lambda url, **kwargs: Response(302, url, {"Location": "/again"})
        with self.assertRaisesRegex(PublicRequestError, "Too many HTTP redirects"):
            await self.http.get("https://origin.example.test/")
        self.assertEqual(self.http.session.get.call_count, 10)
        self.assertEqual(len({call.kwargs["proxy"] for call in self.http.session.get.call_args_list}), 1)

    async def test_invalid_redirect_scheme_fails_without_following(self):
        self.http.session.get.return_value = Response(302, "https://origin.example.test/", {"Location": "file:///private"})
        with self.assertRaisesRegex(PublicRequestError, "Invalid HTTP redirect"):
            await self.http.get("https://origin.example.test/")
        self.http.session.get.assert_called_once()

    async def test_disabled_redirects_and_missing_location_return_original_response(self):
        for allow, headers in ((False, {"Location": "/other"}), (True, {})):
            with self.subTest(allow=allow):
                self.http.session.get.reset_mock()
                self.http.session.get.return_value = Response(302, "https://origin.example.test/", headers)
                result = await self.http.get("https://origin.example.test/", allow_redirects=allow)
                self.assertEqual(result.status, 302)
                self.http.session.get.assert_called_once()

    async def test_post_301_302_303_switch_to_get_without_body_or_content_length(self):
        for status in (301, 302, 303):
            with self.subTest(status=status):
                self.http.session.reset_mock()
                self.http.session.post.return_value = Response(status, "https://origin.example.test/start", {"Location": "/result"})
                self.http.session.get.return_value = Response(200, "https://origin.example.test/result")
                await self.http.post("https://origin.example.test/start", json={"q": "fixture"}, headers={"content-length": "15"}, allow_redirects=True)
                self.http.session.post.assert_called_once()
                self.http.session.get.assert_called_once()
                options = self.http.session.get.call_args.kwargs
                self.assertNotIn("json", options)
                self.assertNotIn("data", options)
                self.assertNotIn("Content-Length", options["headers"])

    async def test_post_307_308_replay_json_and_form_data(self):
        for status in (307, 308):
            for body in ({"json": {"q": "fixture"}}, {"data": {"q": "fixture"}}):
                with self.subTest(status=status, body=body):
                    self.http.session.reset_mock()
                    self.http.session.post.side_effect = [Response(status, "https://origin.example.test/start", {"Location": "/result"}), Response(200, "https://origin.example.test/result")]
                    await self.http.post("https://origin.example.test/start", **body, allow_redirects=True)
                    self.assertEqual(self.http.session.post.call_count, 2)
                    self.http.session.get.assert_not_called()
                    for key, value in body.items():
                        self.assertEqual(self.http.session.post.call_args.kwargs[key], value)

    async def test_each_redirect_hop_rechecks_proxy_pool_availability(self):
        self.http.proxy_pool = ProxyPool.from_env({"SIGNALWATCH_PROXY_LIST_JSON": '["one.example.test:8080"]'})

        async def reject_auth():
            self.http.proxy_pool.reject_auth()

        self.http.session.get.return_value = Response(302, "https://origin.example.test/", {"Location": "https://other.example.test/"}, enter=reject_auth)
        with self.assertRaisesRegex(PublicRequestError, "authentication was rejected"):
            await self.http.get("https://origin.example.test/")
        self.http.session.get.assert_called_once()

    async def test_redirects_share_the_network_timeout_budget(self):
        clock = [100.0]

        async def first_hop():
            clock[0] += 4

        self.http.session.get.side_effect = [Response(302, "https://origin.example.test/", {"Location": "/next"}, enter=first_hop), Response(200, "https://origin.example.test/next")]
        with patch("signalwatch.http.time.monotonic", side_effect=lambda: clock[0]):
            await self.http.get("https://origin.example.test/", max_attempts=1)
        self.assertEqual([call.kwargs["timeout"].total for call in self.http.session.get.call_args_list], [30, 26])

    async def test_gateway_retry_after_survives_new_client_and_different_destination(self):
        environment = {"SIGNALWATCH_PROXY_LIST_JSON": '["one.example.test:8080", "two.example.test:8080"]'}
        self.http.proxy_pool = ProxyPool.from_env(environment)
        self.http.session.get.side_effect = aiohttp.ClientHttpProxyError(Mock(), (), status=429, headers={"Retry-After": "120"})
        with self.assertRaises(PublicRequestError):
            await self.http.get("https://first.example.test/")
        replacement = PublicHTTP({**DEFAULTS, "cache_dir": self.temp.name})
        replacement.proxy_pool = ProxyPool.from_env(environment)
        replacement.session = Mock()
        with self.assertRaises(PublicRequestError) as raised:
            await replacement.get("https://second.example.test/")
        self.assertGreater(raised.exception.retry_after, 119)
        replacement.session.get.assert_not_called()
        files = list(replacement.cache.glob("proxy-cooldown-*.json"))
        self.assertEqual(len(files), 1)
        self.assertEqual(set(json.loads(files[0].read_text())), {"until", "status"})

    async def test_gateway_retry_after_created_between_hops_is_honored(self):
        environment = {"SIGNALWATCH_PROXY_LIST_JSON": '["one.example.test:8080"]'}
        self.http.proxy_pool = ProxyPool.from_env(environment)
        other_client = PublicHTTP({**DEFAULTS, "cache_dir": self.temp.name})
        other_client.proxy_pool = ProxyPool.from_env(environment)

        async def defer_gateway():
            other_client._defer_proxy(503, 120)

        self.http.session.get.return_value = Response(302, "https://origin.example.test/", {"Location": "https://other.example.test/"}, enter=defer_gateway)
        with self.assertRaises(PublicRequestError) as raised:
            await self.http.get("https://origin.example.test/")
        self.assertGreater(raised.exception.retry_after, 119)
        self.http.session.get.assert_called_once()


if __name__ == "__main__":
    unittest.main()
