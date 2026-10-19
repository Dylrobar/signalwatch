import json
import unittest
from unittest.mock import patch

from signalwatch.extension_corporate import normalize_corporate
from signalwatch.ingestion import StagingWorker
from signalwatch.staging import StagingQueue
from signalwatch.store import Store
from signalwatch.technographic_store import document_input


def posting(text, key="job:1", company_id="company:acme", url="https://jobs.acme.test/1"):
    return {"id": key, "kind": "job_posting", "name": "Infrastructure engineer", "source_url": "https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true",
            "metadata": {"provider": "greenhouse", "company_context": {"company_id": company_id, "domain": "acme.test"},
                         "fields": {"title": "Infrastructure engineer", "description": text, "url": url, "published_at": "2026-10-01T00:00:00Z"}}}


class TechnographicStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.ingest({"entities": [{"id": "company:acme", "kind": "company", "name": "Acme"}, {"id": "domain:acme.test", "kind": "domain", "value": "acme.test"}],
                           "edges": [{"from_id": "company:acme", "to_id": "domain:acme.test", "relation": "official_website"}]})

    def test_assertion_matches_cve_with_unknown_version_and_kev(self):
        self.store.ingest({"entities": [posting("We use PostgreSQL in production. Experience with Okta is preferred.")],
                           "advisories": [{"id": "CVE-2026-12345", "title": "Postgres issue", "affected": [{"vendor": "postgresql", "product": "postgresql", "version": "*", "part": "a"}]}],
                           "kev": [{"cveID": "CVE-2026-12345"}]})
        self.store.reconcile()
        detail = self.store.detail("company:acme")
        self.assertEqual(detail["technographics"]["documents"], 1)
        self.assertEqual({row["status"] for row in detail["technographics"]["fingerprints"]}, {"asserted_use", "requirement"})
        self.assertEqual(len(detail["observations"]), 1)
        self.assertEqual(detail["observations"][0]["product"], "postgresql")
        alert = detail["alerts"][0]
        self.assertEqual(alert["version_state"], "unknown")
        self.assertTrue(alert["kev"])
        self.assertIn("public company text", " ".join(alert["reasons"]))
        self.assertEqual(alert["status"], "potential")

    def test_duplicate_content_across_urls_skips_extraction_preserves_both_sources(self):
        doc = posting("We use Terraform for our infrastructure.")
        self.store.ingest({"entities": [doc]})
        with patch("signalwatch.technographics.extract", side_effect=AssertionError("duplicate extraction")):
            counts = self.store.ingest({"entities": [posting("We use Terraform for our infrastructure.", key="job:2", url="https://careers.acme.test/1")]})
        self.assertEqual(counts["technographic_duplicates"], 1)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM technographic_documents").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM technographic_sources").fetchone()[0], 2)
        self.assertEqual(self.store.detail("company:acme")["technographics"]["total"], 1)

    def test_duplicate_content_never_drops_second_company(self):
        self.store.ingest({"entities": [{"id": "company:other", "kind": "company", "name": "Other"}, posting("We use Kafka.")]})
        self.store.ingest({"entities": [posting("We use Kafka.", key="job:other", company_id="company:other")]})
        self.assertEqual(self.store.detail("company:other")["technographics"]["total"], 1)
        self.assertEqual(self.store.detail("company:acme")["technographics"]["total"], 1)

    def test_changed_source_removes_prior_assertion_and_alert_but_retains_history(self):
        self.store.ingest({"entities": [posting("We use Terraform.")], "advisories": [{"id": "CVE-2026-23456", "affected": [{"vendor": "hashicorp", "product": "terraform"}]}]})
        self.store.reconcile()
        self.assertEqual(len(self.store.detail("company:acme")["alerts"]), 1)
        self.store.ingest({"entities": [posting("We no longer use Terraform.")]})
        self.store.reconcile()
        detail = self.store.detail("company:acme")
        self.assertEqual(detail["observations"], [])
        self.assertEqual(detail["alerts"], [])
        self.assertEqual([row["status"] for row in detail["technographics"]["fingerprints"]], ["historical"])
        self.assertFalse(any(row["relation"] == "technology_asserted_use" for row in self.store.detail("job:1")["relationships"]))
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM technographic_documents").fetchone()[0], 2)

    def test_shared_syndication_stays_active_until_all_sources_change(self):
        self.store.ingest({"entities": [posting("We use Terraform."), posting("We use Terraform.", key="job:2")]})
        self.store.ingest({"entities": [posting("No technology mentioned.")]})
        self.assertEqual(len(self.store.detail("company:acme")["observations"]), 1)
        self.store.ingest({"entities": [posting("No technology mentioned.", key="job:2")]})
        self.assertEqual(self.store.detail("company:acme")["observations"], [])

    def test_exact_domain_resolution_does_not_merge_ambiguous_companies(self):
        doc = posting("We use Kafka.", company_id="")
        self.store.ingest({"entities": [doc]})
        self.assertEqual(self.store.detail("company:acme")["technographics"]["total"], 1)
        self.store.ingest({"entities": [{"id": "company:other", "kind": "company", "name": "Other"}],
                           "edges": [{"from_id": "company:other", "to_id": "domain:acme.test", "relation": "official_website"}]})
        result = self.store.ingest({"entities": [posting("We use Snowflake.", key="job:3", company_id="")]})
        self.assertEqual(result["technographic_unattributed"], 1)
        self.assertEqual(self.store.detail("company:other")["technographics"]["total"], 0)

    def test_successful_unchanged_fetch_touches_last_seen_only(self):
        doc = posting("Experience with Okta required.")
        self.store.ingest({"entities": [doc]})
        before = self.store.detail("company:acme")["technographics"]["fingerprints"][0]
        self.assertEqual(self.store.touch_technographic_source(doc["source_url"], {"company_id": "company:acme"}, "2030-01-01T00:00:00Z"), 1)
        after = self.store.detail("company:acme")["technographics"]["fingerprints"][0]
        self.assertEqual(before["first_seen_at"], after["first_seen_at"])
        self.assertEqual(after["last_seen_at"], "2030-01-01T00:00:00Z")
        self.assertEqual(after["published_at"], "2026-10-01T00:00:00Z")
        self.assertEqual(self.store.detail("company:acme")["observations"], [])

    def test_content_and_url_hash_are_separate_and_tracking_is_normalized(self):
        left = document_input(posting("We use Kafka.", url="https://jobs.acme.test/1?utm_source=rss"))
        right = document_input(posting("We use Kafka.", url="https://other.test/2"))
        self.assertEqual(left["content_hash"], right["content_hash"])
        self.assertNotEqual(left["url_hash"], right["url_hash"])
        self.assertEqual(left["source_url"], "https://jobs.acme.test/1")

    def test_raw_staging_to_company_evidence_and_reconciliation(self):
        queue = StagingQueue(self.store)
        payload = {"jobs": [{"id": 99, "title": "SRE", "absolute_url": "https://jobs.acme.test/99", "content": "<p>We operate our PostgreSQL clusters.</p>"}]}
        queue.enqueue(json.dumps(payload).encode(), source="public:greenhouse", adapter="public_source", source_url="https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true",
                      metadata={"provider": "greenhouse", "target": {"company_id": "company:acme", "domain": "acme.test"}})
        result = StagingWorker(self.store, {}, queue).drain()
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["dead"], 0)
        row = self.store.detail("company:acme")["technographics"]["fingerprints"][0]
        self.assertEqual(row["status"], "asserted_use")
        self.assertEqual(row["source_url"], "https://jobs.acme.test/99")
        self.assertIsNone(row["cpe"])

    def test_dns_verification_identifies_provider_without_asserting_deployed_product(self):
        self.store.ingest({"entities": [{"id": "source_record:dns:1", "kind": "source_record", "source_url": "https://dns.google/resolve?name=acme.test&type=TXT",
                           "metadata": {"provider": "dns_txt", "target_domain": "acme.test", "provider_fields": {"name": "acme.test.", "data": '"google-site-verification=abc" "MS=ms1234"'}}}]})
        detail = self.store.detail("company:acme")
        self.assertEqual(detail["technographics"]["total"], 2)
        self.assertEqual({row["status"] for row in detail["technographics"]["fingerprints"]}, {"domain_verification"})
        self.assertTrue(all(row["cpe"] is None for row in detail["technographics"]["fingerprints"]))
        self.assertEqual(detail["observations"], [])
