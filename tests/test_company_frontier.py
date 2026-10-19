import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from signalwatch.collectors import Collector
from signalwatch.config import load_config
from signalwatch.dns import DNSResult
from signalwatch.http import FetchResult
from signalwatch.store import Store


STAMP = "2026-10-19T07:00:00+00:00"


class CompanyFrontierTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = load_config(Path(self.directory.name) / "config.json")
        self.config.update(seed_urls=[], source_targets=[], crawl_pages=1, crawl_depth=0)
        self.store = Store(self.config["db"])
        self.collector = Collector(self.config, self.store)

    def company(self, domain="acme.test"):
        self.store.ingest({"entities": [
            {"id": "company:acme", "kind": "company", "name": "Acme", "value": "Acme"},
            {"id": "domain:" + domain, "kind": "domain", "name": domain, "value": domain}],
            "edges": [{"from_id": "company:acme", "to_id": "domain:" + domain, "relation": "official_website"}]})

    def evidence(self, host, scope="acme.test", provider="ctlogs", record_id=None, source_url=None, stamp=STAMP):
        record_id = record_id or "source_record:" + provider + ":" + host
        source_url = source_url or "https://api.ctlogs.dev/v1/hosts/" + scope
        self.store.ingest({"entities": [
            {"id": record_id, "kind": "source_record", "name": host, "value": host, "source_url": source_url,
             "observed_at": stamp, "metadata": {"provider": provider, "target_domain": scope}},
            {"id": "domain:" + host, "kind": "domain", "name": host, "value": host}],
            "edges": [{"from_id": record_id, "to_id": "domain:" + host, "relation": "reports_on", "source_url": source_url}]})
        return record_id

    def test_only_scoped_certificate_names_under_company_domains_are_selected(self):
        self.company()
        self.evidence("api.acme.test")
        self.evidence("acme.test")
        self.evidence("api.acme.test.evil.test")
        self.evidence("api.other.test", scope="other.test")
        self.evidence("dns.acme.test", provider="dns_txt")
        candidates = self.store.company_crawl_candidates()
        self.assertEqual([row["domain"] for row in candidates], ["api.acme.test"])
        self.assertEqual(candidates[0]["scope"], "acme.test")

    def test_explicit_targets_work_without_inventing_a_company(self):
        self.evidence("api.acme.test")
        self.assertEqual(self.store.company_crawl_candidates(), [])
        self.assertEqual([row["domain"] for row in self.store.company_crawl_candidates(["ACME.TEST."])], ["api.acme.test"])
        self.assertEqual(self.store.search(kind="company")["total"], 0)

    def test_existing_http_or_https_roots_are_not_queued_again_and_limit_is_bounded(self):
        self.company()
        for host in ("a.acme.test", "b.acme.test", "c.acme.test"):
            self.evidence(host)
        self.store.enqueue_url("http://a.acme.test/")
        self.store.enqueue_url("https://b.acme.test/")
        self.assertEqual([row["domain"] for row in self.store.company_crawl_candidates()], ["c.acme.test"])
        self.evidence("d.acme.test")
        self.assertEqual(len(self.store.company_crawl_candidates(limit=1)), 1)

    def test_latest_candidate_preserves_one_complete_provenance_record(self):
        self.company()
        self.company("app.acme.test")
        self.evidence("api.app.acme.test", record_id="a-old", source_url="https://old.test/evidence", stamp="2026-10-18T00:00:00Z")
        self.evidence("api.app.acme.test", scope="app.acme.test", record_id="z-new", source_url="https://new.test/evidence", stamp=STAMP)
        self.assertEqual(self.store.company_crawl_candidates(), [{"domain": "api.app.acme.test", "record_id": "z-new",
            "source_url": "https://new.test/evidence", "observed_at": STAMP, "scope": "app.acme.test"}])

    async def test_new_hosts_reach_dns_and_technology_mapping_without_becoming_owned_assets(self):
        self.company()
        record_id = self.evidence("api.acme.test")
        path = Path(self.directory.name) / "page.html"
        raw = b'<html><meta name="generator" content="WordPress 6.7.2"></html>'
        path.write_bytes(raw)
        self.collector._can_fetch = AsyncMock(return_value=True)

        async def resolve(host, source_url):
            return DNSResult([{"name": host, "type": "A", "value": "192.0.2.10", "ttl": 60,
                "observed_at": STAMP}], [], {"A": "NOERROR"}, STAMP, "doh").graph(host, source_url)

        self.collector._resolve = resolve
        self.collector.http.get = AsyncMock(return_value=FetchResult(path, 200,
            {"Content-Type": "text/html", "Server": "nginx/1.26.3"}, "https://api.acme.test/", True, hashlib.sha256(raw).hexdigest()))
        result = await self.collector.collect_web()
        self.assertEqual((result["company_hosts_queued"], result["targets"], result["pages"]), (1, 1, 1))
        with self.store.connection() as conn:
            self.assertIsNone(conn.execute("SELECT company_id FROM crawl_urls WHERE url='https://api.acme.test/'").fetchone()[0])
            self.assertEqual(conn.execute("SELECT status FROM crawl_urls WHERE url='https://api.acme.test/'").fetchone()[0], "done")
            self.assertIsNotNone(conn.execute("SELECT 1 FROM edges WHERE from_id=? AND to_id='domain:acme.test' AND relation='certificate_lookup_scope'", (record_id,)).fetchone())
            self.assertIsNotNone(conn.execute("SELECT 1 FROM edges WHERE from_id='domain:api.acme.test' AND to_id='ip:192.0.2.10' AND relation='resolves_to'").fetchone())
            self.assertIsNotNone(conn.execute("SELECT 1 FROM observations WHERE asset_id='domain:api.acme.test' AND product='nginx' AND version='1.26.3'").fetchone())
            self.assertEqual(conn.execute("SELECT count(*) FROM edges WHERE from_id='company:acme' AND to_id='domain:api.acme.test'").fetchone()[0], 0)
        second = await self.collector.collect_web()
        self.assertEqual((second["company_hosts_queued"], second["targets"]), (0, 0))

    async def test_discovery_cap_is_preserved(self):
        self.company()
        self.evidence("a.acme.test")
        self.evidence("b.acme.test")
        self.config["max_discovered_domains"] = 1
        self.collector._crawl = AsyncMock(return_value={"pages": 1, "observations": 0, "error": None})
        result = await self.collector.collect_web()
        self.assertEqual((result["company_hosts_considered"], result["company_hosts_queued"]), (2, 1))
        self.assertEqual(self.store.stats()["crawl_urls"], 1)
