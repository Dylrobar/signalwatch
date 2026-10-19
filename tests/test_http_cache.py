import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from signalwatch.config import DEFAULTS
from signalwatch.http import PublicHTTP, PublicRequestError


class Response:
    def __init__(self, status, body=b"", etag=None):
        self.status = status
        self.headers = {"ETag": etag} if etag else {}
        self.url = "https://example.test/feed"
        self.content = Mock()

        async def chunks(size):
            yield body

        self.content.iter_chunked = chunks

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        pass


class HTTPCacheTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.http = PublicHTTP({**DEFAULTS, "cache_dir": self.temp.name})
        self.http.session = Mock()
        self.url = "https://example.test/feed?token=synthetic-secret"

    async def test_revalidated_body_obeys_current_size_limit(self):
        self.http.session.get.side_effect = [Response(200, b"large body", "a"), Response(304)]
        original = await self.http.get(self.url)
        with self.assertRaisesRegex(ValueError, "Response exceeds 2 bytes") as raised:
            await self.http.get(self.url, max_bytes=2)
        self.assertNotIn("synthetic-secret", str(raised.exception))
        self.assertEqual(original.path.read_bytes(), b"large body")

    async def test_304_requires_usable_conditional_cache(self):
        for options in ({}, {"cache": False}, {"force": True}):
            with self.subTest(options=options):
                # A cold 304 must never create an empty success/cache entry.
                for path in Path(self.temp.name).iterdir():
                    path.unlink()
                if options:
                    self.http.session.get.return_value = Response(200, b"old body", "a")
                    await self.http.get(self.url)
                self.http.session.get.return_value = Response(304)
                with self.assertRaisesRegex(PublicRequestError, "304 without a usable cached response"):
                    await self.http.get(self.url, **options)
                if not options:
                    self.assertFalse(list(Path(self.temp.name).iterdir()))

    async def test_uncached_refresh_invalidates_old_validator(self):
        self.http.session.get.side_effect = [Response(200, b"A", "a"), Response(200, b"B", "b")]
        await self.http.get(self.url)
        await self.http.get(self.url, cache=False)

        def origin(url, *, headers, **options):
            return Response(304) if headers.get("If-None-Match") == "a" else Response(200, b"A", "a")

        self.http.session.get.side_effect = origin
        result = await self.http.get(self.url)
        self.assertEqual(result.path.read_bytes(), b"A")
        self.assertEqual(result.digest, hashlib.sha256(b"A").hexdigest())
        self.assertNotIn("If-None-Match", self.http.session.get.call_args.kwargs["headers"])


if __name__ == "__main__":
    unittest.main()
