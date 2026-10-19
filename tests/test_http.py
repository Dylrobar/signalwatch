import asyncio
import email.utils
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from signalwatch.config import DEFAULTS
from signalwatch.http import HTTPError, PublicHTTP, retry_delay


class Response:
    def __init__(self, status, *, headers=None, url="https://example.test/feed?query=secret"):
        self.status = status
        self.headers = headers or {}
        self.url = url
        self.content = Mock()
        self.content.read = AsyncMock(side_effect=AssertionError("Error pages must not be read"))

        async def chunks(size):
            yield b'{"ok": true}'

        self.content.iter_chunked = chunks

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        pass


class HTTPRetryTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.http = PublicHTTP({**DEFAULTS, "cache_dir": self.temp.name})
        self.http.session = Mock()
        self.clock = 1000.0
        self.waits = []

        async def sleep(delay):
            self.waits.append(delay)
            self.clock += delay

        self.addCleanup(patch.stopall)
        patch("signalwatch.http.time", SimpleNamespace(monotonic=lambda: self.clock, time=time.time)).start()
        patch("signalwatch.http.asyncio.sleep", side_effect=sleep).start()

    async def test_short_retry_after_waits_once_and_retries(self):
        limited = Response(429, headers={"Retry-After": "7"})
        self.http.session.get.side_effect = [limited, Response(200)]
        result = await self.http.get("https://example.test/feed")
        self.assertEqual(result.path.read_text(), '{"ok": true}')
        self.assertEqual(self.waits, [7.0])
        self.assertEqual(self.http.session.get.call_count, 2)
        limited.content.read.assert_not_awaited()

    async def test_long_retry_after_defers_without_truncating_or_requesting_host(self):
        self.http.session.get.return_value = Response(429, headers={"Retry-After": "120"})
        with self.assertRaises(HTTPError) as raised:
            await self.http.get("https://example.test/feed?query=private")
        self.assertEqual(raised.exception.retry_after, 120)
        self.assertEqual(self.http.host_wait["example.test"], 1120)
        with self.assertRaises(HTTPError) as cooled:
            await self.http.get("https://example.test/other")
        self.assertEqual(cooled.exception.retry_after, 120)
        self.assertEqual(self.http.session.get.call_count, 1)
        self.assertEqual(self.waits, [])
        self.assertNotIn("private", str(raised.exception))

    async def test_last_attempt_retains_host_cooldown_for_next_request(self):
        self.http.session.get.side_effect = [Response(503, headers={"Retry-After": "9"}), Response(200)]
        with self.assertRaises(HTTPError) as raised:
            await self.http.get("https://example.test/feed", max_attempts=1)
        self.assertEqual(raised.exception.status, 503)
        self.assertEqual(self.waits, [])
        await self.http.get("https://example.test/other")
        self.assertEqual(self.waits, [9.0])
        self.assertEqual(self.http.session.get.call_count, 2)

    async def test_zero_retry_after_has_minimum_delay(self):
        self.http.session.get.side_effect = [Response(429, headers={"Retry-After": "0"}), Response(200)]
        await self.http.get("https://example.test/feed")
        self.assertEqual(self.waits, [1.0])

    async def test_error_page_and_encoded_query_are_not_diagnostics(self):
        response = Response(404, url="https://user:password@example.test/sparql?query=" + "%20" * 2000)
        self.http.session.get.return_value = response
        with self.assertRaises(HTTPError) as raised:
            await self.http.get("https://example.test/sparql")
        self.assertEqual(str(raised.exception), "HTTP 404 Not Found: https://example.test/sparql")
        response.content.read.assert_not_awaited()
        self.assertEqual(list(Path(self.temp.name).iterdir()), [])

    async def test_timeout_message_is_concise_without_query(self):
        self.http.session.get.side_effect = asyncio.TimeoutError("long raw request and private query")
        with self.assertRaisesRegex(RuntimeError, r"^Connection timed out: https://example.test/feed$"):
            await self.http.get("https://example.test/feed?query=private", max_attempts=1)

    async def test_post_bounds_response_and_never_persists_request_credentials(self):
        self.http.session.post.return_value = Response(200)
        result = await self.http.post("https://example.test/search", json={"query": "host"}, headers={"Authorization": "Bearer private-value"})
        self.assertEqual(result.path.read_bytes(), b'{"ok": true}')
        self.assertFalse(list(Path(self.temp.name).glob("*.json")))
        self.http.session.post.assert_called_once()
        self.assertFalse(self.http.session.post.call_args.kwargs["allow_redirects"])
        with self.assertRaisesRegex(ValueError, "Response exceeds"):
            await self.http.post("https://example.test/search", data={"token": "private-value"}, max_bytes=1)
        for path in Path(self.temp.name).iterdir():
            self.assertNotIn(b"private-value", path.read_bytes())

    async def test_post_uses_host_cooldown_and_has_no_implicit_retry(self):
        self.http.session.post.return_value = Response(429, headers={"Retry-After": "120"})
        with self.assertRaises(HTTPError) as raised:
            await self.http.post("https://example.test/search", json={"q": "test"})
        self.assertEqual(raised.exception.retry_after, 120)
        self.assertEqual(self.http.session.post.call_count, 1)
        self.assertEqual(self.waits, [])


class HTTPDiagnosticTests(unittest.TestCase):
    def test_retry_after_http_date_and_invalid_numbers(self):
        with patch("signalwatch.http.time.time", return_value=1000):
            self.assertEqual(retry_delay(email.utils.formatdate(1210, usegmt=True), 0), 210)
            self.assertEqual(retry_delay(email.utils.formatdate(900, usegmt=True), 0), 0)
        with patch("signalwatch.http.random.random", return_value=0):
            for value in (None, "invalid", "nan", "inf"):
                self.assertEqual(retry_delay(value, 2), 4)

    def test_direct_http_errors_drop_html_body(self):
        message = str(HTTPError(522, "https://example.test/?secret=x", "<!DOCTYPE html><html>Error</html>"))
        self.assertEqual(message, "HTTP 522 Request failed: https://example.test/")


if __name__ == "__main__":
    unittest.main()
