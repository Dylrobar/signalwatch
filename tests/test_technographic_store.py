import json
import unittest
from unittest.mock import patch

from signalwatch.extension_corporate import normalize_corporate
from signalwatch.ingestion import StagingWorker
from signalwatch.staging import StagingQueue
from signalwatch.store import Store
from signalwatch.technographic_store import document_input


def posting(text, key="job:1", company_id="company:acme", url=None):
    board = "other" if company_id == "company:other" else "acme"
    endpoint = "https://boards-api.greenhouse.io/v1/boards/" + board + "/jobs?content=true"
    url = url or "https://boards.greenhouse.io/" + board + "/jobs/1"
    return {"id": key, "kind": "job_posting", "name": "Infrastructure engineer", "source_url": endpoint,
            "metadata": {"provider": "greenhouse", "company_context": {"company_id": company_id, "domain": board + ".test"},
                         "source_binding": {"kind": "configured", "provider": "greenhouse", "endpoint_url": endpoint},
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
            counts = self.store.ingest({"entities": [posting("We use Terraform for our infrastructure.", key="job:2", url="https://boards.greenhouse.io/acme/jobs/2")]})
        self.assertEqual(counts["technographic_duplicates"], 1)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM technographic_documents").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT count(*) FROM technographic_sources").fetchone()[0], 2)
        self.assertEqual(self.store.detail("company:acme")["technographics"]["total"], 1)

    def test_duplicate_content_never_drops_second_company(self):
        self.store.ingest({"entities": [{"id": "company:other", "kind": "company", "name": "Other"}, posting("We use Kafka.")]})
        self.store.set_company_asset("company:other", "https://other.test", evidence="Reviewed ownership", source_url="https://other.test/about")
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

    def test_manual_exclusion_blocks_domain_and_explicit_company_attribution(self):
        for status, role in (("rejected", "owned"), ("candidate", "owned"), ("confirmed", "service")):
            with self.subTest(status=status, role=role):
                self.store.set_company_asset("company:acme", "https://acme.test", status=status, role=role,
                                             evidence="Reviewed association", source_url="https://acme.test/about")
                self.assertEqual(self.store.company_enrichment_targets(), [])
                for company_id in ("", "company:acme"):
                    counts = self.store.ingest({"entities": [posting("We use Kafka.", company_id=company_id)]})
                    self.assertEqual(counts["technographic_unattributed"], 1)
                    self.assertEqual(self.store.detail("company:acme")["technographics"]["documents"], 0)
                    self.assertEqual(self.store.detail("company:acme")["observations"], [])
                self.assertIsNotNone(self.store.detail("job:1"))

    def test_manual_confirmed_domain_is_eligible_without_official_website_edge(self):
        self.store.ingest({"entities": [{"id": "company:other", "kind": "company", "name": "Other"}]})
        self.store.set_company_asset("company:other", "https://other.test", evidence="Reviewed ownership",
                                    source_url="https://other.test/about")
        doc = posting("We use Kafka.", company_id="company:other")
        doc["metadata"]["company_context"]["company_id"] = ""
        self.store.ingest({"entities": [doc]})
        self.assertEqual(self.store.detail("company:other")["technographics"]["documents"], 1)
        self.assertIn({"domain": "other.test", "company_id": "company:other", "name": "Other"}, self.store.company_enrichment_targets())

    def test_rejection_withdraws_existing_evidence_alerts_and_can_be_reset(self):
        doc = posting("We use Terraform.")
        self.store.ingest({"entities": [doc], "advisories": [{"id": "CVE-2026-23456", "affected": [{"vendor": "hashicorp", "product": "terraform"}]}]})
        self.store.reconcile()
        self.assertEqual(len(self.store.detail("company:acme")["alerts"]), 1)
        rejected = self.store.set_company_asset("company:acme", "https://acme.test", status="rejected",
                                                evidence="Wrong company", source_url="https://acme.test/about")
        self.assertEqual(rejected["technographics"]["documents"], 0)
        self.assertEqual(rejected["observations"], [])
        self.assertEqual(rejected["alerts"], [])
        evidence = self.store.detail("job:1")
        self.assertEqual(evidence["metadata"]["fields"]["description"], "We use Terraform.")
        self.assertFalse(any(edge["relation"] == "has_public_evidence" or edge["relation"].startswith("technology_") for edge in evidence["relationships"]))
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM technographic_documents").fetchone()[0], 1)
        restored = self.store.set_company_asset("company:acme", "https://acme.test", status="automatic")
        self.assertEqual(restored["technographics"]["documents"], 1)
        self.assertEqual(len(restored["observations"]), 1)
        self.assertEqual(len(restored["alerts"]), 1)

    def test_manual_decision_reconciles_only_affected_companies_in_same_transaction(self):
        self.store.ingest({"entities": [{"id": "company:other", "kind": "company", "name": "Other"},
                                        posting("We use Terraform.")],
                           "advisories": [{"id": "CVE-2026-23456", "affected": [{"vendor": "hashicorp", "product": "terraform"}]}],
                           "observations": [{"asset_id": "company:other", "vendor": "hashicorp", "product": "terraform",
                                             "origin": "manual", "source_url": "https://other.test"}]})
        self.store.reconcile()
        before = self.store.detail("company:other")["alerts"]
        self.assertEqual(len(before), 1)
        with patch.object(self.store, "reconcile", wraps=self.store.reconcile) as reconcile:
            self.store.set_company_asset("company:acme", "https://acme.test", status="rejected",
                                         evidence="Wrong company", source_url="https://acme.test/about")
        reconcile.assert_called_once()
        self.assertEqual(reconcile.call_args.kwargs["asset_ids"], {"company:acme"})
        self.assertIsNotNone(reconcile.call_args.kwargs["conn"])
        self.assertEqual(self.store.detail("company:other")["alerts"], before)
        self.assertEqual(self.store.detail("company:acme")["alerts"], [])

    def test_empty_scoped_reconciliation_does_not_touch_other_alerts(self):
        self.store.ingest({"entities": [posting("We use Terraform.")],
                           "advisories": [{"id": "CVE-2026-23456", "affected": [{"vendor": "hashicorp", "product": "terraform"}]}]})
        self.store.reconcile()
        before = self.store.detail("company:acme")["alerts"]
        self.assertEqual(self.store.reconcile(asset_ids=[]), {"evaluated": 0, "alerts": 0, "removed": 0, "previous": 0})
        self.assertEqual(self.store.detail("company:acme")["alerts"], before)

    def test_context_change_moves_projection_without_losing_shared_evidence(self):
        self.store.ingest({"entities": [{"id": "company:other", "kind": "company", "name": "Other"},
                                        posting("We use Kafka."), posting("We use Kafka.", key="job:2", url="https://acme.test/2")]})
        self.store.set_company_asset("company:other", "https://other.test", evidence="Reviewed ownership", source_url="https://other.test/about")
        self.store.ingest({"entities": [posting("We use Kafka.", company_id="company:other")]})
        self.assertEqual(self.store.detail("company:acme")["technographics"]["documents"], 1)
        self.assertEqual(self.store.detail("company:other")["technographics"]["documents"], 1)
        self.assertEqual(len(self.store.detail("company:acme")["observations"]), 1)
        self.assertEqual(self.store.detail("company:acme")["observations"][0]["source_url"], "https://acme.test/2")
        links = [edge for edge in self.store.detail("job:1")["relationships"] if edge["relation"] == "has_public_evidence"]
        self.assertEqual({edge["from_id"] for edge in links}, {"company:other"})
        self.store.ingest({"entities": [posting("We use Kafka.", key="job:2", company_id="company:other")]})
        self.assertEqual(self.store.detail("company:acme")["technographics"]["documents"], 0)
        self.assertEqual(self.store.detail("company:acme")["observations"], [])
        self.assertEqual(len(self.store.detail("company:other")["observations"]), 1)

    def test_lost_company_context_withdraws_old_projection(self):
        self.store.ingest({"entities": [posting("We use Kafka.")]})
        doc = posting("We use Kafka.", company_id="company:missing")
        self.store.ingest({"entities": [doc]})
        self.assertEqual(self.store.detail("company:acme")["technographics"]["documents"], 0)
        self.assertEqual(self.store.detail("company:acme")["observations"], [])

    def test_partial_source_refresh_preserves_retained_document_context(self):
        self.store.ingest({"entities": [posting("We use Kafka.")]})
        self.store.ingest({"entities": [{"id": "job:1", "kind": "job_posting", "name": "Refreshed title",
                                        "metadata": {"collector_refresh": True}}]})
        self.assertEqual(self.store.detail("company:acme")["technographics"]["documents"], 1)
        self.assertEqual(len(self.store.detail("company:acme")["observations"]), 1)
        self.assertEqual(self.store.detail("job:1")["metadata"]["fields"]["description"], "We use Kafka.")

    def test_rejected_owner_resolves_domain_ambiguity_in_targets_and_evidence(self):
        self.store.ingest({"entities": [{"id": "company:other", "kind": "company", "name": "Other"}],
                           "edges": [{"from_id": "company:other", "to_id": "domain:acme.test", "relation": "official_website"}]})
        self.assertEqual(self.store.company_enrichment_targets(), [])
        self.store.set_company_asset("company:other", "https://acme.test", status="rejected",
                                    evidence="Wrong company", source_url="https://acme.test/about")
        self.assertEqual(self.store.company_enrichment_targets()[0]["company_id"], "company:acme")
        self.store.ingest({"entities": [posting("We use Kafka.", company_id="")]})
        self.assertEqual(self.store.detail("company:acme")["technographics"]["documents"], 1)
        self.assertEqual(self.store.detail("company:other")["technographics"]["documents"], 0)

    def test_www_alias_cannot_bypass_rejected_apex(self):
        self.store.set_company_asset("company:acme", "https://acme.test", status="rejected",
                                    evidence="Wrong company", source_url="https://acme.test/about")
        doc = posting("We use Kafka.")
        doc["metadata"]["company_context"]["domain"] = "WWW.ACME.TEST."
        result = self.store.ingest({"entities": [doc]})
        self.assertEqual(result["technographic_unattributed"], 1)

    def test_successful_unchanged_fetch_only_advances_last_checked(self):
        doc = posting("Experience with Okta required.")
        self.store.ingest({"entities": [doc]})
        before = self.store.detail("company:acme")["technographics"]["fingerprints"][0]
        self.assertEqual(self.store.touch_technographic_source(doc["source_url"], {"company_id": "company:acme", "domain": "acme.test"}, "2030-01-01T00:00:00Z"), 1)
        after = self.store.detail("company:acme")["technographics"]["fingerprints"][0]
        self.assertEqual(before["first_seen_at"], after["first_seen_at"])
        self.assertEqual(after["last_seen_at"], before["last_seen_at"])
        self.assertEqual(after["last_checked_at"], "2030-01-01T00:00:00Z")
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
        payload = {"jobs": [{"id": 99, "title": "SRE", "absolute_url": "https://acme.test/99", "content": "<p>We operate our PostgreSQL clusters.</p>"}]}
        queue.enqueue(json.dumps(payload).encode(), source="public:greenhouse", adapter="public_source", source_url="https://boards-api.greenhouse.io/v1/boards/acme/jobs?content=true",
                      metadata={"provider": "greenhouse", "target": {"company_id": "company:acme", "domain": "acme.test"},
                                "source_binding": {"kind": "configured", "provider": "greenhouse", "endpoint_url": "https://boards-api.greenhouse.io/v1/boards/acme/jobs"}})
        result = StagingWorker(self.store, {}, queue).drain()
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["dead"], 0)
        row = self.store.detail("company:acme")["technographics"]["fingerprints"][0]
        self.assertEqual(row["status"], "asserted_use")
        self.assertEqual(row["source_url"], "https://acme.test/99")
        self.assertIsNone(row["cpe"])

    def test_dns_verification_identifies_provider_without_asserting_deployed_product(self):
        self.store.ingest({"entities": [{"id": "source_record:dns:1", "kind": "source_record", "source_url": "https://dns.google/resolve?name=acme.test&type=TXT",
                           "metadata": {"provider": "dns_txt", "target_domain": "acme.test", "provider_fields": {"name": "acme.test.", "data": '"google-site-verification=abc" "MS=ms1234"'}}}]})
        detail = self.store.detail("company:acme")
        self.assertEqual(detail["technographics"]["total"], 2)
        self.assertEqual({row["status"] for row in detail["technographics"]["fingerprints"]}, {"domain_verification"})
        self.assertTrue(all(row["cpe"] is None for row in detail["technographics"]["fingerprints"]))
        self.assertEqual(detail["observations"], [])
