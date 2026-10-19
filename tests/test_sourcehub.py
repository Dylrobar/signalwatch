import json
import tempfile
import unittest
from pathlib import Path

from signalwatch.config import load_config
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.sourcehub import definitions, public_settings, source_catalog, stage_payload
from signalwatch.store import Store


class SourceHubTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / "config.json")
        self.store = Store(self.config["db"])
        self.queue = staging_queue(self.store, self.config)

    async def test_all_extension_families_route_original_bytes_to_existing_models(self):
        values = [
            ("crtsh", [{"id": 1, "name_value": "vpn.example.com"}], {"target_domain": "example.com"}),
            ("greenhouse", {"jobs": [{"id": 1, "title": "Engineer", "absolute_url": "https://jobs.example/1", "content": "Windows and Jamf"}]}, {}),
            ("github_public", [{"id": 1, "full_name": "example/project", "html_url": "https://github.com/example/project", "default_branch": "main"}], {"artifact_kind": "repositories"}),
            ("wigle", {"success": True, "results": [{"netid": "02:11:22:33:44:55", "ssid": "Office"}]}, {}),
        ]
        saved = []
        for provider, value, metadata in values:
            raw = b"  " + json.dumps(value).encode() + b"\n"
            item = await stage_payload(self.config, self.store, raw, provider=provider, source_url="https://source.example/" + provider, metadata=metadata)
            saved.append((item["id"], raw))
        rss = b'<rss version="2.0"><channel><title>Feed</title><item><title>Patch report</title><link>https://news.example/patch</link></item></channel></rss>'
        item = await stage_payload(self.config, self.store, rss, provider="fulldisclosure", source_url="https://source.example/rss", content_type="application/rss+xml")
        saved.append((item["id"], rss))
        report = StagingWorker(self.store, self.config, self.queue).drain()
        self.assertEqual((report["processed"], report["dead"]), (5, 0), report)
        for item_id, raw in saved:
            self.assertEqual(self.queue.get(item_id, include_payload=True)["payload"], raw)
        self.assertGreater(self.store.search(kind="job_posting")["total"], 0)
        self.assertGreater(self.store.search(kind="wireless")["total"], 0)
        self.assertEqual(self.store.stats()["observations"], 0)
        self.assertEqual(self.store.search(kind="company")["total"], 0)

    async def test_generated_idempotency_covers_mime_time_and_query_provenance(self):
        options = {"provider": "fcc_uls", "source_url": "https://user:password@source.example/data?api_key=private&query=one", "metadata": {"dataset": "records"}}
        one = await stage_payload(self.config, self.store, b"[]", **options)
        again = await stage_payload(self.config, self.store, b"[]", **options)
        mime = await stage_payload(self.config, self.store, b"[]", **options, content_type="text/plain")
        timed = await stage_payload(self.config, self.store, b"[]", **options, observed_at="2026-10-18T12:00:00Z")
        self.assertTrue(again["duplicate"])
        self.assertEqual(one["id"], again["id"])
        self.assertEqual(len({one["id"], mime["id"], timed["id"]}), 3)
        self.assertEqual(one["source_url"], "https://source.example/data?query=one")
        self.assertNotIn("private", json.dumps(self.queue.list()))

    async def test_catalog_has_unique_ids_native_health_and_credential_requirements(self):
        specs = definitions()
        self.assertEqual(len(specs), len({row["id"] for row in specs}))
        self.assertGreaterEqual(len(specs), 75)
        self.store.update_source("nvd", status="ok", last_success="2026-10-18T12:00:00Z", counts={"advisories": 17})
        self.store.update_source("exposure", counts={"provider_health": {"shodan": {"status": "healthy", "records": 5}}})
        rows = {row["id"]: row for row in source_catalog(self.config, self.store)["items"]}
        self.assertEqual(rows["nvd"]["health"]["counts"]["advisories"], 17)
        self.assertEqual(rows["shodan"]["status"], "unconfigured")
        self.assertFalse(rows["shodan"]["credential_configured"])
        self.assertEqual(rows["shodan"]["credential_env"], "SIGNALWATCH_SHODAN_CREDENTIALS")

    async def test_malformed_corporate_raw_goes_directly_to_dead_letter(self):
        item = await stage_payload(self.config, self.store, b"{bad", provider="greenhouse", source_url="https://source.example/jobs")
        report = StagingWorker(self.store, self.config, self.queue).drain()
        self.assertEqual((report["dead"], report["retried"]), (1, 0))
        self.assertEqual(self.queue.get(item["id"], include_payload=True)["payload"], b"{bad")

    def test_public_settings_redacts_legacy_credentials_and_keeps_public_fields(self):
        result = public_settings({"provider_settings": {"sam_gov": {"api_key": "private", "enabled": True, "url": " HTTPS://user:password@source.example/path?%61%70%69%5f%6b%65%79=private&query=public"}}, "watch_products": ["nginx"]})
        self.assertEqual(result["watch_products"], ["nginx"])
        self.assertTrue(result["provider_settings"]["sam_gov"]["enabled"])
        self.assertEqual(result["provider_settings"]["sam_gov"]["url"], "https://source.example/path?query=public")
        self.assertNotIn("private", json.dumps(result))
