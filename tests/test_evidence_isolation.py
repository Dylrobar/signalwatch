import json
import unittest

from signalwatch.store import Store
from signalwatch.technographic_store import backfill_resolution
from signalwatch.text_signals import extract


class EvidenceIsolationTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.ingest({"entities": [{"id": "company:alpha", "kind": "company", "name": "Alpha"},
                                         {"id": "company:beta", "kind": "company", "name": "Beta"}]})
        for name in ("alpha", "beta"):
            self.store.save_company_profile(company_id="company:" + name, name=name.title(),
                                            primary_domain={"alpha": "alpha.example.com", "beta": "beta.example.org"}[name], primary_domain_evidence="Approved company website", primary_domain_source_url="https://" + {"alpha": "alpha.example.com", "beta": "beta.example.org"}[name], aliases=["Shared Brand"])

    def article(self, company="alpha", *, domain=None, key=None):
        domain = domain or {"alpha": "alpha.example.com", "beta": "beta.example.org"}[company]
        return {"id": key or "company_article:" + company, "kind": "company_article", "name": "Our stack",
                "source_url": "https://" + domain + "/feed.xml",
                "metadata": {"provider": "company_feeds", "company_context": {"company_id": "company:" + company, "domain": domain},
                             "fields": {"title": "Our stack", "description": "We use PostgreSQL in production.",
                                        "url": "https://" + domain + "/blog/stack"}}}

    def test_conflicting_company_context_cannot_create_observation_or_evidence_link(self):
        item = self.article("beta", domain="alpha.example.com")
        self.store.ingest({"entities": [item], "edges": [{"from_id": "company:beta", "to_id": item["id"], "relation": "has_public_evidence"}]})
        for company in ("alpha", "beta"):
            detail = self.store.detail("company:" + company)
            self.assertEqual(detail["observations"], [])
            self.assertEqual(detail["technographics"]["documents"], 0)
            self.assertEqual(detail["technographics"]["resolution"]["conflict"], 1)
        self.assertFalse(any(edge["relation"] == "has_public_evidence" for edge in self.store.detail(item["id"])["relationships"]))

    def test_identical_text_remains_separate_between_companies(self):
        self.store.ingest({"entities": [self.article("alpha"), self.article("beta")]})
        with self.store.connection() as conn:
            rows = conn.execute("SELECT organization_id,content_hash FROM technographic_documents").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1], rows[1][1])
        for company in ("alpha", "beta"):
            evidence = self.store.detail("company:" + company)["technographics"]
            self.assertEqual(evidence["documents"], 1)
            self.assertEqual({row["organization_id"] for row in evidence["relationships"]}, {"company:" + company})
            self.assertTrue(all(company + ".example." in row["source_url"] for row in evidence["relationships"]))

    def test_article_link_to_another_owner_is_not_first_party_feed_content(self):
        item = self.article("alpha")
        item["metadata"]["fields"]["url"] = "https://beta.example.org/blog/stack"
        self.store.ingest({"entities": [item]})
        self.assertEqual(self.store.detail("company:alpha")["observations"], [])
        self.assertEqual(self.store.detail("company:beta")["observations"], [])

    def test_external_unowned_feed_cannot_assert_company_stack(self):
        item = self.article("alpha")
        item["source_url"] = "https://unrelated.test/feed.xml"
        self.store.ingest({"entities": [item]})
        detail = self.store.detail("company:alpha")
        self.assertEqual(detail["observations"], [])
        self.assertEqual(detail["technographics"]["resolution"]["candidate"], 1)

    def test_shared_ats_requires_binding_and_matching_board(self):
        item = self.article("alpha")
        item.update(kind="job_posting", source_url="https://boards-api.greenhouse.io/v1/boards/alpha/jobs")
        item["metadata"].update(provider="greenhouse")
        item["metadata"]["fields"]["url"] = "https://boards.greenhouse.io/alpha/jobs/1"
        self.store.ingest({"entities": [item]})
        self.assertEqual(self.store.detail("company:alpha")["observations"], [])
        item["metadata"]["source_binding"] = {"kind": "configured", "provider": "greenhouse", "endpoint_url": item["source_url"]}
        self.store.ingest({"entities": [item]})
        self.assertEqual(len(self.store.detail("company:alpha")["observations"]), 1)
        item["metadata"]["fields"]["url"] = "https://boards.greenhouse.io/beta/jobs/1"
        self.store.ingest({"entities": [item]})
        self.assertEqual(self.store.detail("company:alpha")["observations"], [])

    def test_ats_redirected_endpoint_or_discovery_owner_cannot_rebind(self):
        item = self.article("alpha")
        item.update(kind="job_posting", source_url="https://api.lever.co/v0/postings/beta")
        item["metadata"].update(provider="lever", source_binding={"kind": "configured", "provider": "lever", "endpoint_url": "https://api.lever.co/v0/postings/alpha"})
        item["metadata"]["fields"]["url"] = "https://jobs.lever.co/alpha/1"
        self.store.ingest({"entities": [item]})
        self.assertEqual(self.store.detail("company:alpha")["observations"], [])
        item["source_url"] = "https://api.lever.co/v0/postings/alpha"
        item["metadata"]["source_binding"].update(kind="discovered", discovered_from="https://beta.example.org/careers")
        self.store.ingest({"entities": [item]})
        self.assertEqual(self.store.detail("company:alpha")["observations"], [])

    def test_same_job_entity_cannot_reassign_a_bound_board_to_another_company(self):
        item = self.article("alpha")
        item.update(kind="job_posting", source_url="https://api.lever.co/v0/postings/alpha")
        item["metadata"].update(provider="lever", source_binding={"kind": "configured", "provider": "lever", "endpoint_url": item["source_url"]})
        item["metadata"]["fields"]["url"] = "https://jobs.lever.co/alpha/1"
        self.store.ingest({"entities": [item]})
        self.assertEqual(len(self.store.detail("company:alpha")["observations"]), 1)
        item["metadata"]["company_context"] = {"company_id": "company:beta", "domain": "beta.example.org"}
        self.store.ingest({"entities": [item]})
        self.store.ingest({"entities": [item]})
        for company in ("alpha", "beta"):
            detail = self.store.detail("company:" + company)
            self.assertEqual(detail["observations"], [])
            self.assertEqual(detail["technographics"]["resolution"]["conflict"], 1)

    def test_dns_answer_owner_must_match_query_and_tokens_are_not_deployments(self):
        item = {"id": "source_record:dns", "kind": "source_record", "source_url": "https://dns.google/resolve?name=alpha.example.com&type=TXT",
                "metadata": {"provider": "dns_txt", "target_domain": "alpha.example.com", "provider_fields": {"name": "beta.example.org.", "data": "google-site-verification=abc"}}}
        self.store.ingest({"entities": [item]})
        self.assertEqual(self.store.detail("company:alpha")["technographics"]["documents"], 0)
        item["metadata"]["provider_fields"]["name"] = "alpha.example.com."
        self.store.ingest({"entities": [item]})
        detail = self.store.detail("company:alpha")
        self.assertEqual(detail["observations"], [])
        self.assertEqual(detail["technographics"]["relationships"][0]["status"], "domain_verification")

    def test_alias_only_company_mentions_remain_candidates(self):
        with self.store.connection() as conn:
            outside = extract(conn, {"title": "Alpha and Shared Brand announce news", "url": "https://news.test/post"})
            owned = extract(conn, {"title": "Alpha announces news", "url": "https://alpha.example.com/post"})
        self.assertEqual({row["status"] for row in outside["mentions"]}, {"candidate"})
        self.assertEqual(owned["mentions"][0]["status"], "resolved")

    def test_anchor_change_withdraws_observations_and_backfill_is_idempotent(self):
        self.store.ingest({"entities": [self.article("alpha")]})
        self.assertEqual(len(self.store.detail("company:alpha")["observations"]), 1)
        self.store.save_company_profile(company_id="company:alpha", name="Alpha", primary_domain="replacement.example.net", primary_domain_evidence="Changed domain", primary_domain_source_url="https://replacement.example.net")
        self.assertEqual(self.store.detail("company:alpha")["observations"], [])
        with self.store.connection(write=True) as conn:
            backfill_resolution(self.store, conn)
            backfill_resolution(self.store, conn)
            self.assertEqual(conn.execute("SELECT count(*) FROM evidence_resolution_migrations").fetchone()[0], 1)

    def test_rejecting_root_withdraws_retained_child_evidence(self):
        item = self.article("alpha", domain="careers.alpha.example.com")
        self.store.ingest({"entities": [item]})
        self.assertEqual(len(self.store.detail("company:alpha")["observations"]), 1)
        self.store.set_company_asset("company:alpha", "https://alpha.example.com", status="rejected",
                                     evidence="Ownership rejected", source_url="https://alpha.example.com/about")
        detail = self.store.detail("company:alpha")
        self.assertEqual(detail["observations"], [])
        self.assertEqual(detail["technographics"]["documents"], 0)

    def test_scheduled_enrichment_retains_anchor_after_asset_observation_refresh(self):
        self.store.ingest({"entities": [{"id": "domain:alpha.example.com", "kind": "asset", "name": "Observed asset", "value": ""}]})
        targets = self.store.company_enrichment_targets()
        self.assertIn({"company_id": "company:alpha", "name": "Alpha", "domain": "alpha.example.com"}, targets)


if __name__ == "__main__":
    unittest.main()
