import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from signalwatch.csaf import collect_csaf, cpe_identity, parse_csaf, parse_feed, product_identities, purl_identity
from signalwatch.http import FetchResult
from signalwatch.store import Store


def document(identifier="vendor-2026-01", cves=None):
    return {
        "document": {"csaf_version": "2.0", "title": "Router security advisory", "publisher": {"name": "Vendor", "namespace": "https://vendor.example/csaf"}, "tracking": {"id": identifier, "status": "final", "initial_release_date": "2026-10-01T00:00:00Z", "current_release_date": "2026-10-18T00:00:00Z"}},
        "product_tree": {"branches": [{"category": "vendor", "name": "Vendor", "branches": [
            {"category": "product_version", "name": "Router 1.2.3", "product": {"name": "Router 1.2.3", "product_id": "affected", "product_identification_helper": {"cpe": "cpe:2.3:o:vendor:router_firmware:1.2.3:*:*:*:*:*:*:*"}}},
            {"category": "product_version", "name": "Router 2.0.0", "product": {"name": "Router 2.0.0", "product_id": "fixed", "product_identification_helper": {"cpe": "cpe:2.3:o:vendor:router_firmware:2.0.0:*:*:*:*:*:*:*"}}},
        ]}]},
        "vulnerabilities": [{"cve": cve, "title": "Router authentication defect", "notes": [{"category": "description", "text": "The affected firmware mishandles authentication."}], "scores": [{"cvss_v3": {"baseScore": 9.8}, "products": ["affected"]}], "product_status": {"known_affected": ["affected"], "fixed": ["fixed"]}, "remediations": [{"category": "vendor_fix", "details": "Install 2.0.0", "url": "https://vendor.example/update", "product_ids": ["affected"]}]} for cve in (cves or ["CVE-2026-12345"])],
    }


def feed(entries, next_url=None):
    return {"feed": {"entry": [{"id": url, "updated": updated, "content": {"type": "application/json", "src": url}} for url, updated in entries], "link": [{"rel": "next", "href": next_url}] if next_url else []}}


class FixtureHTTP:
    def __init__(self, directory, fixtures):
        self.directory = Path(directory)
        self.fixtures = fixtures
        self.calls = []

    async def get(self, url, **kwargs):
        self.calls.append(url)
        value = self.fixtures[url]
        if isinstance(value, Exception):
            raise value
        path = self.directory / f"fixture-{len(self.calls)}.json"
        text = json.dumps(value)
        path.write_text(text)
        return FetchResult(path, 200, {}, url, True, hashlib.sha256(text.encode()).hexdigest())


class CSAFParsingTests(unittest.TestCase):
    def test_known_affected_only_preserves_fixed_status_remediation_and_raw(self):
        record = document(cves=["CVE-2026-12345", "CVE-2026-12346"])
        parsed = parse_csaf(record, "https://vendor.example/advisory.json")["advisories"]
        self.assertEqual(len(parsed), 2)
        self.assertNotEqual(parsed[0]["id"], parsed[1]["id"])
        self.assertTrue(parsed[0]["id"].startswith("CSAF:"))
        self.assertEqual(parsed[0]["aliases"], ["CVE-2026-12345"])
        self.assertEqual([item["version"] for item in parsed[0]["affected"]], ["1.2.3"])
        self.assertEqual(parsed[0]["severity"], 9.8)
        self.assertEqual(parsed[0]["configurations"]["product_status"]["fixed"], ["fixed"])
        self.assertEqual(parsed[0]["configurations"]["remediations"][0]["category"], "vendor_fix")
        self.assertEqual(parsed[0]["raw"]["vulnerability"], record["vulnerabilities"][0])

    def test_relationship_without_exact_identifier_remains_unverified(self):
        record = document()
        record["product_tree"]["relationships"] = [{"category": "installed_on", "product_reference": "affected", "relates_to_product_reference": "fixed", "full_product_name": {"product_id": "combination", "name": "Router combined deployment"}}]
        record["vulnerabilities"][0]["product_status"]["known_affected"] = ["combination", "missing"]
        parsed = parse_csaf(record, "https://vendor.example/advisory.json")["advisories"][0]
        self.assertEqual(parsed["affected"], [])
        self.assertEqual(len(parsed["configurations"]["unverified_products"]), 2)
        self.assertEqual(parsed["configurations"]["csaf_product_tree"], record["product_tree"])

    def test_cpe22_and_escaped23_identifiers(self):
        legacy = cpe_identity("cpe:/a:vendor:product%21:1.0")
        self.assertEqual(legacy["product"], "product!")
        self.assertEqual(legacy["version"], "1.0")
        current = cpe_identity(r"cpe:2.3:h:vendor:router\:pro:-:*:*:*:*:*:*:*")
        self.assertEqual(current["product"], "router:pro")
        self.assertIsNone(cpe_identity("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*"))

    def test_purl_identifiers_preserve_namespaces_and_explicit_versions(self):
        npm = purl_identity("pkg:npm/%40scope/parser@1.2.3")
        self.assertEqual(npm["ecosystem"], "npm")
        self.assertEqual(npm["package"], "@scope/parser")
        self.assertEqual(npm["versions"], ["1.2.3"])
        maven = purl_identity("pkg:maven/org.example/parser@2.0.0")
        self.assertEqual(maven["package"], "org.example:parser")
        self.assertIsNone(purl_identity("pkg:deb/debian/parser@1.0?arch=arm64&distro=debian-12"))
        self.assertIsNone(purl_identity("pkg:pypi/parser@1.0?repository_url=https://private.example"))
        self.assertIsNone(purl_identity("pkg:swift/github.com/example/parser@1.0"))

    def test_both_cpe_and_purl_identifiers_are_retained(self):
        product = {"product_identification_helper": {"cpe": "cpe:2.3:a:vendor:parser:1.0.0:*:*:*:*:*:*:*", "purl": "pkg:pypi/parser@1.0.0"}}
        self.assertEqual({item["identity_status"] for item in product_identities(product)}, {"cpe", "purl"})

    def test_rolie_relative_sources_and_next_pages(self):
        records, pages = parse_feed(feed([("advisories/a.json", "2026-10-18T00:00:00Z")], "older.json"), "https://vendor.example/feed.json", "Vendor")
        self.assertEqual(records[0]["url"], "https://vendor.example/advisories/a.json")
        self.assertEqual(pages, ["https://vendor.example/older.json"])
        with self.assertRaises(ValueError):
            parse_feed({}, "https://vendor.example/feed.json", "Vendor")


class CSAFCollectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_budget_resume_and_revision_updates_preserve_nvd(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(str(Path(folder) / "test.db"))
            store.ingest({"advisories": [{"id": "CVE-2026-12345", "title": "NVD original", "source": "NVD", "affected": []}]})
            feed_url = "https://vendor.example/feed.json"
            first, second = "https://vendor.example/first.json", "https://vendor.example/second.json"
            fixtures = {feed_url: feed([(first, "2026-10-18T00:00:00Z"), (second, "2026-10-17T00:00:00Z")]), first: document("first"), second: document("second")}
            http = FixtureHTTP(folder, fixtures)
            config = {"csaf_max_records": 1, "csaf_feeds": [{"name": "Vendor", "url": feed_url}], "concurrency": 2}
            counts = await collect_csaf(config, store, http)
            self.assertEqual((counts["records"], counts["pending"]), (1, 1))
            self.assertNotIn(second, http.calls)
            counts = await collect_csaf(config, store, http)
            self.assertEqual((counts["records"], counts["pending"]), (1, 0))
            fixtures[first] = document("first", ["CVE-2026-12346"])
            fixtures[feed_url] = feed([(first, "2026-10-19T00:00:00Z"), (second, "2026-10-17T00:00:00Z")])
            await collect_csaf(config, store, http)
            with store.connection() as conn:
                self.assertEqual(conn.execute("SELECT title FROM advisories WHERE id='CVE-2026-12345'").fetchone()[0], "NVD original")
                previous = conn.execute("SELECT rejected FROM advisories WHERE source='CSAF' AND id LIKE '%first:CVE-2026-12345'").fetchone()
                self.assertEqual(previous[0], 1)

    async def test_failed_document_does_not_starve_unfetched_history(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(str(Path(folder) / "test.db"))
            feed_url = "https://vendor.example/feed.json"
            first, second = "https://vendor.example/first.json", "https://vendor.example/second.json"
            http = FixtureHTTP(folder, {feed_url: feed([(first, "2026-10-18T00:00:00Z"), (second, "2026-10-17T00:00:00Z")]), first: ValueError("invalid document"), second: document("second")})
            config = {"csaf_max_records": 1, "csaf_feeds": [feed_url]}
            with self.assertRaises(RuntimeError):
                await collect_csaf(config, store, http)
            self.assertEqual(len(store.source_state("csaf")["pending_documents"]), 2)
            http.fixtures[feed_url]["feed"]["updated"] = "2026-10-18T01:00:00Z"
            counts = await collect_csaf(config, store, http)
            self.assertEqual(counts["records"], 1)
            self.assertIn(second, http.calls)
            self.assertEqual(counts["pending"], 1)

    async def test_paginated_feed_progress_with_minimum_page_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(str(Path(folder) / "test.db"))
            root, older, item = "https://vendor.example/feed.json", "https://vendor.example/older.json", "https://vendor.example/a.json"
            http = FixtureHTTP(folder, {root: feed([], older), older: feed([(item, "2026-10-18T00:00:00Z")]), item: document()})
            counts = await collect_csaf({"csaf_max_records": 1, "csaf_feed_pages": 1, "csaf_feeds": [root]}, store, http)
            self.assertEqual(counts["records"], 1)
            self.assertIn(older, http.calls)


    async def test_feed_failure_preserves_last_success(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(str(Path(folder) / "test.db"))
            root = "https://vendor.example/feed.json"
            http = FixtureHTTP(folder, {root: feed([])})
            config = {"csaf_max_records": 1, "csaf_feeds": [root]}
            await collect_csaf(config, store, http)
            previous = store.source_state("csaf")["feed_health"][root]["last_success"]
            http.fixtures[root] = ValueError("invalid feed")
            with self.assertRaises(RuntimeError):
                await collect_csaf(config, store, http)
            health = store.source_state("csaf")["feed_health"][root]
            self.assertEqual(health["last_success"], previous)
            self.assertEqual(health["status"], "error")
