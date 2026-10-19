import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from signalwatch.config import DEFAULTS
from signalwatch.extension_threat import SOURCE_DEFINITIONS, collect_threat_sources, normalize_threat
from signalwatch.ingestion import StagingWorker
from signalwatch.normalization import NormalizationError
from signalwatch.staging import StagingQueue
from signalwatch.store import Store


RSS = b'''<?xml version="1.0"?><rss version="2.0"><channel><title>Security</title><item><guid>1</guid><title>nginx exploit fixed CVE-2026-12345</title><link>https://news.example/one</link><description>Patch is available</description><pubDate>Sun, 18 Oct 2026 12:00:00 GMT</pubDate></item><item><guid>2</guid><title>Unrelated conference</title><link>https://news.example/two</link><description>Schedule</description></item></channel></rss>'''


def staged(provider, payload, **metadata):
    if not isinstance(payload, bytes):
        payload = json.dumps(payload).encode()
    return {"id": 12, "source": "public:" + provider, "source_url": "https://feeds.example/public", "stream_key": provider,
            "adapter": "public_source", "content_type": "application/json", "payload": payload, "payload_hash": hashlib.sha256(payload).hexdigest(),
            "received_at": "2026-10-19T00:00:00+00:00", "observed_at": "2026-10-19T00:00:00+00:00",
            "metadata": {"provider": provider, "watch_products": ["nginx"], "exploit_keywords": ["exploit", "patch"], **metadata}}


class ThreatNormalizationTests(unittest.TestCase):
    def test_security_rss_preserves_qualified_and_unqualified_news_without_deployment_claims(self):
        batch = normalize_threat(staged("fulldisclosure", RSS))
        self.assertEqual(len(batch["articles"]), 2)
        self.assertTrue(batch["articles"][0]["_signal"]["qualified"])
        self.assertFalse(batch["articles"][1]["_signal"]["qualified"])
        self.assertEqual(batch["articles"][0]["cves"], ["CVE-2026-12345"])
        self.assertEqual(batch["articles"][0]["published"], "2026-10-18T12:00:00+00:00")
        self.assertEqual(batch["articles"][0]["_staging"]["raw_reference"], "staging:12")
        self.assertFalse(batch.get("advisories"))
        self.assertFalse(batch.get("observations"))

    def test_html_error_and_invalid_feed_cannot_be_healthy_news(self):
        for payload in (b"<html><title>Site Unavailable</title></html>", b"<rss><channel><item>"):
            with self.subTest(payload=payload), self.assertRaises(NormalizationError):
                normalize_threat(staged("cisco_psirt", payload))

    def test_apple_index_is_bounded_and_preserves_release_dates(self):
        payload = b'''<html><h1>Apple security releases</h1><table><tr><th>Name</th><th>Available for</th><th>Date</th></tr><tr><td><a href="/en-us/123456">macOS 15.5</a></td><td>Mac</td><td>18 Oct 2026</td></tr><tr><td><a href="/en-us/123457">iOS 26.1</a></td><td>iPhone</td><td>17 Oct 2026</td></tr></table></html>'''
        item = staged("apple_security", payload, record_limit=1)
        item["source_url"] = "https://support.apple.com/en-us/100100"
        batch = normalize_threat(item)
        self.assertEqual(len(batch["articles"]), 1)
        self.assertEqual(batch["articles"][0]["url"], "https://support.apple.com/en-us/123456")
        self.assertEqual(batch["articles"][0]["published"], "2026-10-18")
        self.assertFalse(batch.get("observations"))

    def test_exploit_db_csv_selects_latest_references_without_fetching_exploit_files(self):
        payload = b'''id,file,description,date_published,date_added,codes\n1,exploits/one.py,old flaw,2020-01-01,2020-01-01,CVE-2020-12345\n3,exploits/three.py,nginx exploit,2026-10-18,2026-10-18,CVE-2026-12345\n2,exploits/two.py,other issue,2025-01-01,2025-01-01,\n'''
        batch = normalize_threat(staged("exploit_db", payload, record_limit=1))
        self.assertEqual(batch["articles"][0]["url"], "https://www.exploit-db.com/exploits/3")
        self.assertEqual(batch["articles"][0]["cves"], ["CVE-2026-12345"])
        self.assertFalse(batch.get("advisories"))

    def test_urlhaus_comment_csv_retains_ioc_without_news_or_target_fetch(self):
        payload = b'''# URLhaus CSV\n# id,dateadded,url,url_status,threat,tags,urlhaus_link,reporter\n1,2026-10-18,http://malware.example/payload,online,malware_download,loader,https://urlhaus.abuse.ch/url/1/,reporter\n'''
        batch = normalize_threat(staged("urlhaus", payload, format="csv"))
        self.assertFalse(batch["articles"])
        self.assertEqual(batch["entities"][0]["kind"], "threat_indicator")
        self.assertEqual(batch["entities"][0]["metadata"]["record"]["url_status"], "online")
        self.assertFalse(batch.get("observations"))

    def test_greynoise_matches_requested_ip_and_keeps_sensor_claims_separate(self):
        payload = {"ip": "8.8.8.8", "noise": False, "riot": True, "classification": "benign", "name": "Google Public DNS"}
        batch = normalize_threat(staged("greynoise", payload, ip="8.8.8.8"))
        self.assertEqual(batch["entities"][0]["kind"], "threat_indicator")
        self.assertFalse(batch["entities"][0]["metadata"]["record"]["noise"])
        self.assertFalse(batch.get("advisories"))
        self.assertFalse(batch.get("observations"))
        with self.assertRaises(NormalizationError):
            normalize_threat(staged("greynoise", payload, ip="1.1.1.1"))

    def test_unqualified_social_is_source_evidence_and_qualified_social_is_article(self):
        payload = [{"id": "1", "url": "https://social.example/@someone/1", "content": "nginx patch", "created_at": "2026-10-18T10:00:00Z"},
                   {"id": "2", "url": "https://social.example/@someone/2", "content": "my nginx tutorial"}]
        batch = normalize_threat(staged("mastodon", payload))
        self.assertEqual(len(batch["articles"]), 1)
        self.assertEqual(len(batch["entities"]), 1)
        self.assertEqual(batch["entities"][0]["kind"], "source_record")
        self.assertFalse(batch["entities"][0]["metadata"]["qualification"]["qualified"])

    def test_reddit_listing_uses_permalink_and_source_created_time(self):
        payload = {"data": {"children": [{"data": {"id": "post", "title": "nginx exploit", "selftext": "CVE-2026-12345", "permalink": "/r/netsec/comments/post/title/", "created_utc": 1792324800}}]}}
        batch = normalize_threat(staged("reddit_netsec", payload))
        self.assertEqual(batch["articles"][0]["url"], "https://www.reddit.com/r/netsec/comments/post/title/")
        self.assertEqual(batch["articles"][0]["published"], "2026-10-18T12:00:00+00:00")

    def test_bluesky_did_permalink_and_qualification(self):
        payload = {"posts": [{"uri": "at://did:plc:abc/app.bsky.feed.post/postid", "record": {"text": "nginx patch released", "createdAt": "2026-10-18T12:00:00Z"}}]}
        batch = normalize_threat(staged("bluesky", payload))
        self.assertEqual(batch["articles"][0]["url"], "https://bsky.app/profile/did:plc:abc/post/postid")

    def test_oss_fuzz_public_export_does_not_become_verified_advisory(self):
        batch = normalize_threat(staged("oss_fuzz", {"issues": [{"id": "123", "title": "nginx crash", "url": "https://issues.oss-fuzz.com/issues/123", "public": True}]}))
        self.assertEqual(batch["entities"][0]["kind"], "source_record")
        self.assertFalse(batch.get("advisories"))
        with self.assertRaises(NormalizationError):
            normalize_threat(staged("oss_fuzz", {"id": "private", "public": False}))

    def test_distribution_tracker_preserves_release_context_without_upstream_version_claim(self):
        record = {"description": "nginx flaw", "releases": {"bookworm": {"status": "resolved", "fixed_version": "1.22.1-9+deb12u3"}}}
        batch = normalize_threat(staged("debian_tracker", {"nginx": {"CVE-2026-12345": record}}))
        self.assertEqual(batch["entities"][0]["metadata"]["record"]["releases"], record["releases"])
        self.assertEqual(batch["edges"][0]["to_id"], "CVE-2026-12345")
        self.assertFalse(batch.get("observations"))

    def test_total_output_limit_includes_reference_edges(self):
        batch = normalize_threat(staged("oss_fuzz", [{"id": "1", "title": "CVE-2026-12345 CVE-2026-12346"}, {"id": "2", "title": "another"}]), max_records=2)
        self.assertEqual(sum(len(rows) for rows in batch.values()), 2)

    def test_api_error_objects_are_rejected(self):
        for value in ({"error": "denied"}, {"success": False}, {"status": "failed"}):
            with self.subTest(value=value), self.assertRaises(NormalizationError):
                normalize_threat(staged("vulncheck", value))
        for provider in ("vulncheck", "attackerkb", "mastodon"):
            with self.subTest(provider=provider), self.assertRaises(NormalizationError):
                normalize_threat(staged(provider, {}))

    def test_public_bugzilla_and_launchpad_containers_keep_individual_records(self):
        for provider, key, record in (("redhat_security", "bugs", {"id": 123, "summary": "nginx vulnerability"}),
                                      ("ubuntu_launchpad", "entries", {"id": 456, "title": "nginx patch", "web_link": "https://bugs.launchpad.net/bugs/456"})):
            with self.subTest(provider=provider):
                batch = normalize_threat(staged(provider, {key: [record]}))
                self.assertEqual(len(batch["entities"]), 1)
                self.assertEqual(batch["entities"][0]["metadata"]["record"]["id"], record["id"])
                self.assertIn("nginx", batch["entities"][0]["name"])

    def test_catalog_has_unique_ids_and_no_global_greynoise_feed_claim(self):
        ids = [row["id"] for row in SOURCE_DEFINITIONS]
        self.assertEqual(len(ids), len(set(ids)))
        definition = next(row for row in SOURCE_DEFINITIONS if row["id"] == "greynoise")
        self.assertIn("ips", definition["required"])
        self.assertEqual(definition["access"], "api_key")


class ThreatCollectionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.store = Store(str(Path(self.folder.name) / "signalwatch.db"))
        self.config = {**DEFAULTS, "db": str(Path(self.folder.name) / "signalwatch.db"), "provider_settings": {}, "provider_credentials": {},
                       "watch_products": ["nginx"], "exploit_keywords": ["exploit", "patch"], "public_source_batch": 3, "threat_source_batch": 3, "public_source_records": 100}
        self.path = Path(self.folder.name) / "feed.xml"
        self.path.write_bytes(RSS)
        self.http = SimpleNamespace(get=AsyncMock(return_value=SimpleNamespace(path=self.path, status=200, changed=True)))

    async def test_missing_credentials_and_urls_are_unconfigured_without_network_calls(self):
        self.config["provider_settings"] = {"greynoise": {"enabled": True, "ips": ["8.8.8.8"]}, "oss_fuzz": {"enabled": True}}
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["greynoise"]["status"], "unconfigured")
        self.assertEqual(result["provider_health"]["greynoise"]["requirements"], ["api_key"])
        self.assertEqual(result["provider_health"]["oss_fuzz"]["requirements"], ["url"])
        self.http.get.assert_not_called()

    async def test_public_feed_is_staged_exactly_and_unchanged_payload_deduplicates(self):
        self.config["provider_settings"] = {"fulldisclosure": {"enabled": True}}
        first = await collect_threat_sources(self.config, self.store, self.http)
        second = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(first["staged"], 1)
        self.assertEqual(first["qualified"], 1)
        self.assertEqual(first["filtered"], 1)
        self.assertEqual(second["provider_health"]["fulldisclosure"]["status"], "unchanged")
        queue = StagingQueue(self.store)
        item = queue.get(queue.list()["items"][0]["id"], include_payload=True)
        self.assertEqual(item["payload"], RSS)
        self.assertEqual(item["adapter"], "public_source")
        self.assertEqual(item["metadata"]["provider"], "fulldisclosure")

    async def test_round_robin_budget_does_not_starve_later_providers(self):
        self.config["provider_settings"] = {key: {"enabled": True} for key in ("fulldisclosure", "oss_security", "dark_reading")}
        self.config["threat_source_batch"] = 1
        for _ in range(3):
            result = await collect_threat_sources(self.config, self.store, self.http)
            self.assertEqual(sum(row.get("deferred", False) for row in result["provider_health"].values()), 2)
        urls = [call.args[0] for call in self.http.get.call_args_list]
        self.assertEqual(len(set(urls)), 3)

    async def test_threat_budget_overrides_general_provider_budget(self):
        self.config["provider_settings"] = {key: {"enabled": True} for key in ("fulldisclosure", "oss_security", "dark_reading")}
        self.config["public_source_batch"] = 1
        self.config["threat_source_batch"] = 3
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["targets"], 3)
        self.assertTrue(all(result["provider_health"][key]["status"] == "ok" for key in self.config["provider_settings"]))

    async def test_html_200_is_provider_error_with_raw_retained_and_worker_dead_letter(self):
        self.config["provider_settings"] = {"cisco_psirt": {"enabled": True}}
        payload = b"<html><h1>Site Unavailable</h1></html>"
        self.path.write_bytes(payload)
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["cisco_psirt"]["status"], "error")
        self.assertEqual(result["staged"], 1)
        self.assertEqual(result["provider_health"]["cisco_psirt"]["staged"], 1)
        queue = StagingQueue(self.store)
        item_id = queue.list()["items"][0]["id"]
        self.assertEqual(queue.get(item_id, include_payload=True)["payload"], payload)
        outcome = StagingWorker(self.store, self.config).drain()
        self.assertEqual(outcome["dead"], 1)
        self.assertEqual(outcome["processed"], 0)
        retained = queue.get(item_id, include_payload=True)
        self.assertEqual(retained["status"], "dead")
        self.assertEqual(retained["payload"], payload)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM articles").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM advisories").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM observations").fetchone()[0], 0)
        second = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(second["provider_health"]["cisco_psirt"]["status"], "error")
        self.assertEqual(second["staged"], 0)
        self.assertEqual(queue.list()["total"], 1)

    async def test_authenticated_url_errors_do_not_expose_keys(self):
        self.config["provider_settings"] = {"urlhaus": {"enabled": True}}
        self.config["provider_credentials"] = {"urlhaus": "secret-test-key"}
        self.http.get.side_effect = RuntimeError("Request denied: https://urlhaus-api.abuse.ch/v2/files/exports/secret-test-key/recent.csv")
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertNotIn("secret-test-key", json.dumps(result))
        call = self.http.get.call_args
        self.assertFalse(call.kwargs["cache"])
        self.assertFalse(call.kwargs["allow_redirects"])

    async def test_greynoise_rotates_only_explicit_public_ipv4_targets(self):
        self.config["provider_settings"] = {"greynoise": {"enabled": True, "ips": ["8.8.8.8", "1.1.1.1"]}}
        self.config["provider_credentials"] = {"greynoise": "key"}
        for address in ("8.8.8.8", "1.1.1.1"):
            self.path.write_text(json.dumps({"ip": address, "noise": False, "riot": True}))
            result = await collect_threat_sources(self.config, self.store, self.http)
            self.assertEqual(result["staged"], 1)
        self.assertEqual([call.args[0].rsplit("/", 1)[-1] for call in self.http.get.call_args_list], ["8.8.8.8", "1.1.1.1"])

    async def test_social_collection_requires_product_configuration(self):
        self.config["provider_settings"] = {"bluesky": {"enabled": True, "query": "nginx"}}
        self.config["watch_products"] = []
        result = await collect_threat_sources(self.config, self.store, self.http)
        self.assertEqual(result["provider_health"]["bluesky"]["requirements"], ["watch_products"])
        self.http.get.assert_not_called()
