import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from signalwatch.config import DEFAULTS
from signalwatch.extension_threat import ARCHIVES, FEEDS, collect_threat_sources, normalize_threat
from signalwatch.http import HTTPError
from signalwatch.ingestion import StagingWorker
from signalwatch.staging import StagingQueue
from signalwatch.store import Store


class MailingArchiveFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(str(Path(self.temp.name) / "test.db"))
        self.config = {**DEFAULTS, "watch_products": ["nginx"], "exploit_keywords": ["patch"],
                       "provider_credentials": {}, "provider_settings": {}, "public_source_records": 2}
        self.responses = {}
        self.http = SimpleNamespace(get=AsyncMock(side_effect=self.fetch))

    async def fetch(self, url, **kwargs):
        self.assertFalse(kwargs.get("allow_redirects", True) if url not in FEEDS.values() else False)
        result = self.responses[url]
        if isinstance(result, Exception):
            raise result
        path = Path(self.temp.name) / str(len(self.http.get.await_args_list))
        path.write_bytes(result)
        return SimpleNamespace(path=path, url=url, status=200)

    def archive(self, provider):
        root, name = ARCHIVES[provider]
        self.config["provider_settings"] = {provider: {"enabled": True}}
        self.responses[FEEDS[provider]] = HTTPError(502, FEEDS[provider])
        from urllib.parse import urljoin
        self.responses[urljoin(root, "/robots.txt")] = b"User-agent: *\nDisallow: /cgi/\n"
        self.responses[root] = (f'<html><h2>{name} mailing list</h2><ul><li><a href="2026/10/18/6">nginx patch</a></li></ul></html>').encode()
        self.responses[root + "2026/10/18/6"] = (f'''<html><title>{name} - nginx patch</title><pre>
Message-ID: &lt;synthetic-message@example.test&gt;
Date: Sun, 18 Oct 2026 12:00:00 +0200
From: Example &lt;example@example.test&gt;
Subject: nginx patch

An attributed patch report, not evidence of deployment.
</pre></html>''').encode()
        return root

    async def test_both_default_fallbacks_retain_dates_claims_raw_bytes_and_dedup(self):
        for provider in ARCHIVES:
            with self.subTest(provider=provider):
                root = self.archive(provider)
                result = await collect_threat_sources(self.config, self.store, self.http)
                health = result["provider_health"][provider]
                self.assertEqual(health["status"], "partial")
                self.assertTrue(health["fallback_used"])
                self.assertIn("HTTP 502", health["primary_error"])
                self.assertEqual(health["records"], 1)
                self.assertEqual(health["qualified"], 1)
                self.assertEqual(health["fallback_source_url"], root)
                self.assertIn("HTTP 502", health["error"])
                self.assertEqual(health["errors"], [])
                self.assertFalse(health["deferred"])
                queue = StagingQueue(self.store)
                entries = [row for row in queue.list()["items"] if row["source"] == "public:" + provider]
                self.assertEqual(len(entries), 2)
                message = next(queue.get(row["id"], include_payload=True) for row in entries
                               if queue.get(row["id"])["metadata"]["format"] == "mail_archive_message")
                self.assertEqual(message["payload"], self.responses[root + "2026/10/18/6"])
                self.assertEqual(message["source_url"], root + "2026/10/18/6")
                article = normalize_threat(message)["articles"][0]
                self.assertEqual(article["published"], "2026-10-18T10:00:00+00:00")
                self.assertEqual(article["url"], root + "2026/10/18/6")
                self.assertEqual(article["feed_url"], FEEDS[provider])
                self.assertTrue(article["_staging"]["fallback_used"])
                self.assertEqual(article["_staging"]["primary_source_url"], FEEDS[provider])
                self.assertIn("HTTP 502", article["_staging"]["primary_error"])
                self.assertEqual(article["_staging"]["claim_type"], "attributed_mailing_list_claim")
                self.assertEqual(article["_staging"]["source_url"], root + "2026/10/18/6")
                self.assertTrue(article["_signal"]["qualified"])
                second = await collect_threat_sources(self.config, self.store, self.http)
                self.assertEqual(second["provider_health"][provider]["staged"], 0)
                self.assertEqual(second["provider_health"][provider]["duplicates"], 2)
        outcome = StagingWorker(self.store, self.config).drain()
        self.assertEqual(outcome["dead"], 0)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM articles").fetchone()[0], 2)
            self.assertEqual(conn.execute("SELECT count(*) FROM observations").fetchone()[0], 0)

    async def test_primary_feed_recovery_clears_persisted_fallback_error(self):
        provider = "oss_security"
        self.archive(provider)
        await collect_threat_sources(self.config, self.store, self.http)
        self.assertTrue(self.store.source_state("provider:" + provider)["error"])
        self.responses[FEEDS[provider]] = b'''<rss version="2.0"><channel>
<title>OSS-Security</title><link>https://www.openwall.com/</link>
<description>Public security messages</description><item>
<title>nginx patch</title><link>https://www.openwall.com/lists/oss-security/2026/10/18/6</link>
<description>Public patch report</description></item></channel></rss>'''
        self.http.get.reset_mock()
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"][provider]["status"], "ok")
        persisted = self.store.source_state("provider:" + provider)
        self.assertFalse(persisted.get("error"))
        self.assertFalse(persisted["fallback_used"])
        self.assertFalse(persisted["primary_error"])
        self.assertFalse(persisted["fallback_source_url"])
        self.assertEqual(persisted["errors"], [])
        self.assertEqual(self.http.get.await_count, 1)

    async def test_mixed_message_coverage_keeps_primary_and_archive_errors(self):
        root = self.archive("oss_security")
        self.responses[root] = self.responses[root].replace(b"</ul>", b'<li><a href="2026/10/18/5">nginx patch</a></li></ul>')
        self.responses[root + "2026/10/18/5"] = HTTPError(504, root + "2026/10/18/5")
        result = await collect_threat_sources(self.config, self.store, self.http)
        health = result["provider_health"]["oss_security"]
        self.assertEqual(health["status"], "partial")
        self.assertTrue(health["fallback_used"])
        self.assertEqual(health["records"], 1)
        self.assertEqual(health["staged"], 2)
        self.assertEqual(health["fallback_source_url"], root)
        self.assertIn("HTTP 502", health["primary_error"])
        self.assertEqual(len(health["errors"]), 1)
        self.assertIn("HTTP 504 Gateway Timeout: " + root + "2026/10/18/5", health["errors"][0])
        self.assertIn("HTTP 502", health["error"])
        self.assertIn("HTTP 504", health["error"])

    async def test_malformed_archive_is_error_not_empty_success(self):
        root = self.archive("oss_security")
        self.responses[root] = b"<html><h2>Proxy error</h2></html>"
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["oss_security"]["status"], "error")
        self.assertEqual(result["records"], 0)
        self.assertEqual(len(self.http.get.await_args_list), 3)

    async def test_unrelated_links_never_fetched(self):
        root = self.archive("oss_security")
        self.responses[root] = self.responses[root].replace(b"</ul>", b'''<li><a href="https://unrelated.test/lists/oss-security/2026/10/18/2">nginx patch</a></li>
<li><a href="//www.openwall.com/other/2026/10/18/2">other</a></li>
<li><a href="2026/10/">month</a></li><li><a href="2026/10/18/2?redirect=1">query</a></li>
<li><a href="2026/99/18/2">invalid date</a></li></ul>''')
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["records"], 1)
        self.assertEqual(len(self.http.get.await_args_list), 4)

    async def test_no_allowed_message_links_is_error(self):
        root = self.archive("oss_security")
        self.responses[root] = b'<h2>oss-security mailing list</h2><ul><li><a href="https://unrelated.test/one">patch</a></li></ul>'
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["oss_security"]["status"], "error")
        self.assertEqual(len(self.http.get.await_args_list), 3)

    async def test_custom_url_is_never_overridden_even_if_equal_to_default(self):
        for url in ("https://custom.test/security.rss", FEEDS["oss_security"]):
            self.http.get.reset_mock()
            self.config["provider_settings"] = {"oss_security": {"enabled": True, "url": url}}
            self.responses[url] = HTTPError(502, url)
            result = await collect_threat_sources(self.config, self.store, self.http)
            self.assertEqual(result["provider_health"]["oss_security"]["status"], "error")
            self.assertEqual([call.args[0] for call in self.http.get.await_args_list], [url])

    async def test_full_disclosure_robots_disallow_is_honest_blocker(self):
        self.archive("fulldisclosure")
        self.responses["https://lists.openwall.net/robots.txt"] = b"User-agent: *\nDisallow: /\n"
        result = await collect_threat_sources(self.config, self.store, self.http)
        health = result["provider_health"]["fulldisclosure"]
        self.assertEqual(health["status"], "error")
        self.assertFalse(health["fallback_used"])
        self.assertIn("robots.txt disallows", health["error"])
        self.assertIn("HTTP 502", health["primary_error"])
        self.assertEqual(len(self.http.get.await_args_list), 2)

    async def test_message_error_and_bad_date_do_not_produce_records(self):
        root = self.archive("oss_security")
        for payload in (b"<html><title>challenge</title></html>", self.responses[root + "2026/10/18/6"].replace(b"Sun, 18 Oct 2026 12:00:00 +0200", b"not a date")):
            self.responses[root + "2026/10/18/6"] = payload
            result = await collect_threat_sources(self.config, self.store, self.http)
            self.assertEqual(result["provider_health"]["oss_security"]["status"], "error")
            self.assertEqual(result["records"], 0)

    async def test_recent_message_limit_and_bytes_are_bounded(self):
        root = self.archive("oss_security")
        self.config["public_source_records"] = 1000
        self.responses[root] = ('<h2>oss-security mailing list</h2><ul>' + ''.join(
            f'<li><a href="2026/10/18/{index}">nginx patch</a></li>' for index in range(1, 30)) + '</ul>').encode()
        message = self.responses[root + "2026/10/18/6"]
        for index in range(1, 30):
            self.responses[root + f"2026/10/18/{index}"] = message
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["records"], 8)
        calls = self.http.get.await_args_list
        self.assertEqual(len(calls), 11)
        self.assertEqual(calls[3].args[0], root + "2026/10/18/29")
        self.assertTrue(all(call.kwargs["max_bytes"] <= 512 * 1024 for call in calls[3:]))

    async def test_cached_304_archive_responses_remain_valid(self):
        self.archive("oss_security")
        async def cached(url, **kwargs):
            response = await self.fetch(url, **kwargs)
            response.status = 304
            return response
        self.http.get.side_effect = cached
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["records"], 1)
        self.assertTrue(result["provider_health"]["oss_security"]["fallback_used"])
