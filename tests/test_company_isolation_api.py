"""Company identity boundaries through the authenticated API and ingestion path."""

import copy
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from signalwatch.api import create_app
from signalwatch.config import load_config
from signalwatch.ingestion import StagingWorker


class CompanyIsolationAPITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / "config.json")
        self.config.update(api_token="isolation-fixture", seed_urls=[], source_targets=[])
        self.config["sources"] = {name: False for name in self.config["sources"]}
        environment = patch.dict(os.environ, {"CELERY_BROKER_URL": ""})
        environment.start()
        self.addCleanup(environment.stop)
        self.open_app()
        self.acme = self.profile("Acme Incorporated", "example.com", aliases=["Orbit"])
        self.nebula = self.profile("Nebula Labs", "example.org", aliases=["Orbit"])

    def open_app(self):
        self.app = create_app(self.config, auto_collect=False)
        self.store = self.app.state.store
        # No lifespan means there is no automatic collection or network fetch.
        # Raw staged fixtures are drained explicitly through the real worker.
        self.client = TestClient(self.app, headers={"Authorization": "Bearer isolation-fixture"})
        self.addCleanup(self.client.close)

    def post(self, path, payload, status=200):
        response = self.client.post(path, json=payload)
        self.assertEqual(response.status_code, status, response.text)
        return response.json()

    def detail(self, company_id):
        response = self.client.get("/api/entity", params={"id": company_id})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def profile(self, name, domain, **values):
        result = self.post("/api/companies/profile", {
            "name": name, "primary_domain": domain,
            "primary_domain_evidence": "Reviewed official company website",
            "primary_domain_source_url": "https://" + domain + "/about", **values,
        })
        return result["id"]

    def article(self, company_id, domain, key, text="We use PostgreSQL in production."):
        return {"id": key, "kind": "company_article", "name": "Our platform",
                "source_url": "https://" + domain + "/feed.xml",
                "metadata": {"provider": "company_feeds",
                             "company_context": {"company_id": company_id, "domain": domain},
                             "fields": {"title": "Our platform", "description": text,
                                        "url": "https://" + domain + "/blog/platform"}}}

    def stage(self, batch):
        receipt = self.post("/api/staging", {
            "source": "integration:company-isolation", "adapter": "normalized_batch",
            "content_type": "application/json", "payload_encoding": "json", "payload": batch,
        }, status=202)
        result = StagingWorker(self.store, self.config, self.app.state.staging).drain()
        self.assertEqual(result["dead"], 0, result)
        self.assertEqual(result["processed"], 1, result)
        row = self.client.get("/api/staging/" + str(receipt["id"]))
        self.assertEqual(row.status_code, 200, row.text)
        self.assertEqual(row.json()["status"], "processed")

    def assert_no_projection(self, company_id):
        detail = self.detail(company_id)
        self.assertEqual(detail["technographics"]["documents"], 0)
        self.assertEqual(detail["technographics"]["fingerprints"], [])
        self.assertEqual(detail["observations"], [])
        self.assertEqual(detail["alerts"], [])

    def test_domain_resolution_uses_longest_anchor_and_label_boundaries(self):
        subsidiary = self.profile("Research Division", "research.example.com")
        for domain, expected in (("EXAMPLE.COM.", self.acme), ("api.example.org", self.nebula),
                                 ("jobs.research.example.com", subsidiary), ("research-example.com", None),
                                 ("example.com.evil.org", None), ("example.org.evil.com", None)):
            with self.subTest(domain=domain):
                result = self.post("/api/companies/resolve", {"domain": domain})
                self.assertEqual(result["organization_id"], expected)
                self.assertEqual(result["status"], "resolved" if expected else "unattributed")
        result = self.post("/api/companies/resolve", {"source_url": "https://jobs.research.example.com/careers"})
        self.assertEqual(result["matched_domain"], "research.example.com")
        self.assertEqual(result["organization_id"], subsidiary)

    def test_duplicate_canonical_anchor_is_rejected_without_partial_profile_writes(self):
        before = self.detail(self.nebula)["company_profile"]
        with self.store.connection() as conn:
            count = conn.execute("SELECT count(*) FROM entities WHERE kind='company'").fetchone()[0]
        conflict = {"name": "Wrong replacement name", "primary_domain": "EXAMPLE.COM.",
                    "primary_domain_evidence": "Conflicting evidence", "primary_domain_source_url": "https://example.com/about"}
        self.post("/api/companies/profile", conflict, status=409)
        self.post("/api/companies/profile", {**conflict, "company_id": self.nebula}, status=409)
        self.assertEqual(self.detail(self.nebula)["company_profile"], before)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM entities WHERE kind='company'").fetchone()[0], count)
        self.assertEqual(self.post("/api/companies/resolve", {"domain": "example.com"})["organization_id"], self.acme)

    def test_unicode_and_ascii_domain_spellings_share_one_identity_anchor(self):
        company_id = self.profile("International Company", "bücher.de")
        self.assertEqual(self.detail(company_id)["company_profile"]["primary_domain"], "xn--bcher-kva.de")
        self.post("/api/companies/profile", {
            "name": "Duplicate International", "primary_domain": "XN--BCHER-KVA.DE.",
            "primary_domain_evidence": "Duplicate", "primary_domain_source_url": "https://xn--bcher-kva.de/about",
        }, status=409)
        resolved = self.post("/api/companies/resolve", {"domain": "jobs.bücher.de"})
        self.assertEqual(resolved["organization_id"], company_id)

    def test_explicit_company_id_cannot_override_another_company_domain(self):
        result = self.post("/api/companies/resolve", {"company_id": self.acme, "domain": "example.org"})
        self.assertEqual(result["status"], "conflict")
        self.assertIsNone(result["organization_id"])
        self.assertEqual(set(result["candidates"]), {self.acme, self.nebula})
        self.stage({"entities": [self.article(self.acme, "example.org", "article:wrong-company")]})
        self.assert_no_projection(self.acme)
        self.assert_no_projection(self.nebula)
        raw = self.detail("article:wrong-company")
        self.assertEqual(raw["metadata"]["fields"]["description"], "We use PostgreSQL in production.")
        self.assertFalse(any(edge["relation"] == "has_public_evidence" for edge in raw["relationships"]))

    def test_shared_aliases_and_company_ids_without_domain_evidence_remain_candidates(self):
        result = self.post("/api/companies/resolve", {"name": "Orbit"})
        self.assertEqual(result["status"], "candidate")
        self.assertIsNone(result["organization_id"])
        self.assertEqual(set(result["candidates"]), {self.acme, self.nebula})
        explicit = self.post("/api/companies/resolve", {"company_id": self.acme})
        self.assertEqual(explicit["status"], "candidate")
        self.assertIsNone(explicit["organization_id"])
        document = self.article("", "publisher.example.net", "article:ambiguous", "Orbit uses PostgreSQL in production.")
        document["metadata"]["company_context"] = {"name": "Orbit"}
        self.stage({"entities": [document]})
        self.assert_no_projection(self.acme)
        self.assert_no_projection(self.nebula)
        self.assertEqual(self.detail("article:ambiguous")["metadata"]["fields"]["description"], document["metadata"]["fields"]["description"])

    def test_identical_text_is_scoped_to_distinct_company_documents_and_observations(self):
        self.stage({"entities": [self.article(self.acme, "example.com", "article:acme"),
                                  self.article(self.nebula, "example.org", "article:nebula")]})
        acme, nebula = self.detail(self.acme), self.detail(self.nebula)
        for company_id, detail in ((self.acme, acme), (self.nebula, nebula)):
            self.assertEqual(detail["technographics"]["documents"], 1)
            self.assertTrue(detail["technographics"]["fingerprints"])
            self.assertEqual({row["organization_id"] for row in detail["technographics"]["fingerprints"]}, {company_id})
            self.assertEqual({row["asset_id"] for row in detail["observations"]}, {company_id})
        left = {row["document_id"] for row in acme["technographics"]["fingerprints"]}
        right = {row["document_id"] for row in nebula["technographics"]["fingerprints"]}
        self.assertTrue(left.isdisjoint(right))
        with self.store.connection() as conn:
            rows = conn.execute("SELECT organization_id,content_hash FROM technographic_documents").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["organization_id"] for row in rows}, {self.acme, self.nebula})
        self.assertEqual(len({row["content_hash"] for row in rows}), 1)

    def test_one_shared_job_board_cannot_remain_bound_to_two_companies(self):
        endpoint = "https://boards-api.greenhouse.io/v1/boards/orbit/jobs?content=true"

        def posting(company_id, domain, key):
            result = self.article(company_id, domain, key)
            result.update(kind="job_posting", source_url=endpoint)
            result["metadata"].update(provider="greenhouse", source_binding={
                "provider": "greenhouse", "kind": "configured", "endpoint_url": endpoint,
            })
            result["metadata"]["fields"]["url"] = "https://boards.greenhouse.io/orbit/jobs/1"
            return result

        self.stage({"entities": [posting(self.acme, "example.com", "job:shared-acme")]})
        self.assertTrue(self.detail(self.acme)["observations"])
        self.stage({"entities": [posting(self.nebula, "example.org", "job:shared-nebula")]})
        self.assert_no_projection(self.acme)
        self.assert_no_projection(self.nebula)
        for entity_id in ("job:shared-acme", "job:shared-nebula"):
            raw = self.detail(entity_id)
            self.assertEqual(raw["metadata"]["fields"]["description"], "We use PostgreSQL in production.")
            self.assertFalse(any(edge["relation"] == "has_public_evidence" for edge in raw["relationships"]))

    def test_legacy_profile_update_preserves_explicit_domain_and_verified_asns(self):
        saved = self.post("/api/companies/profile", {
            "company_id": self.acme, "name": "Acme Incorporated",
            "verified_asns": [{"asn": 64501, "evidence": "Reviewed registry record",
                               "source_url": "https://example.com/network"}],
        })["company_profile"]
        updated = self.post("/api/companies/profile", {
            "company_id": self.acme, "name": "Acme Updated", "notes": "Saved by an older frontend",
        })["company_profile"]
        for field in ("primary_domain", "primary_domain_evidence", "primary_domain_source_url", "verified_asns"):
            self.assertEqual(updated[field], saved[field])
        result = self.post("/api/companies/resolve", {"asn": 64501})
        self.assertEqual(result["status"], "candidate")
        self.assertIsNone(result["organization_id"])
        self.assertEqual(result["candidates"], [self.acme])

    def test_new_identity_anchor_reconciles_alerts_for_other_board_claimants(self):
        self.post("/api/companies/profile", {
            "company_id": self.nebula, "name": "Nebula Labs", "primary_domain": "",
        })
        endpoint = "https://boards-api.greenhouse.io/v1/boards/orbit/jobs?content=true"
        documents = []
        for company_id, domain, key in ((self.acme, "example.com", "job:a"),
                                        (self.nebula, "example.org", "job:n")):
            document = self.article(company_id, domain, key)
            document.update(kind="job_posting", source_url=endpoint)
            document["metadata"].update(provider="greenhouse", source_binding={
                "provider": "greenhouse", "kind": "configured", "endpoint_url": endpoint,
            })
            document["metadata"]["fields"]["url"] = "https://boards.greenhouse.io/orbit/jobs/1"
            documents.append(document)
        self.stage({"entities": documents, "advisories": [{"id": "CVE-2026-12345",
                    "affected": [{"vendor": "postgresql", "product": "postgresql", "part": "a"}]}]})
        self.assertTrue(self.detail(self.acme)["observations"])
        self.assertEqual(self.detail(self.acme)["alerts"], [])
        self.assert_no_projection(self.nebula)

        self.profile("Nebula Labs", "example.org", company_id=self.nebula)

        self.assert_no_projection(self.acme)
        self.assert_no_projection(self.nebula)

    def test_invalid_asn_and_resolution_schema_never_mutate_profiles(self):
        before = self.detail(self.acme)["company_profile"]
        for asn in (0, -1, 4294967296, True, "AS64501", 64501.5):
            with self.subTest(asn=asn):
                self.post("/api/companies/profile", {"company_id": self.acme, "name": "Rejected change",
                          "verified_asns": [{"asn": asn, "evidence": "Registry", "source_url": "https://example.com/network"}]}, status=422)
                self.post("/api/companies/resolve", {"asn": asn}, status=422)
        self.post("/api/companies/resolve", {"domain": "example.com", "force_company": self.nebula}, status=422)
        self.post("/api/companies/profile", {"company_id": self.acme, "name": "Rejected change",
                  "verified_asns": [{"asn": 64501, "evidence": "Registry"}]}, status=422)
        self.assertEqual(self.detail(self.acme)["company_profile"], before)

    def test_company_identity_and_projection_endpoints_require_authentication(self):
        for method, path, payload in (
            ("POST", "/api/companies/profile", {"name": "Unauthorized"}),
            ("POST", "/api/companies/resolve", {"domain": "example.com"}),
            ("GET", "/api/entity?id=" + self.acme, None),
            ("GET", "/api/company-risk?id=" + self.acme, None),
            ("GET", "/api/graph?root_id=" + self.acme, None),
        ):
            with self.subTest(path=path):
                response = self.client.request(method, path, json=payload, headers={"Authorization": ""})
                self.assertEqual(response.status_code, 401)

    def test_company_graph_shared_product_does_not_expose_other_company_paths(self):
        self.stage({"entities": [self.article(self.acme, "example.com", "article:acme"),
                                  self.article(self.nebula, "example.org", "article:nebula")],
                    "advisories": [{"id": "CVE-2026-12345", "severity": 9.1,
                                    "affected": [{"vendor": "postgresql", "product": "postgresql", "part": "a", "version": "14.1"}]}]})
        for domain in ("example.com", "example.org"):
            self.post("/api/observations", {"asset_url": "https://" + domain,
                      "vendor": "postgresql", "product": "postgresql", "version": "14.1",
                      "evidence": "Independent host inventory"})
        self.store.reconcile()
        response = self.client.get("/api/graph", params={"root_id": self.acme, "depth": 5})
        self.assertEqual(response.status_code, 200, response.text)
        graph = response.json()
        ids = {node["id"] for node in graph["nodes"]}
        self.assertIn(self.acme, ids)
        self.assertIn("article:acme", ids)
        self.assertTrue(any(value.startswith("technographic_product:") for value in ids))
        own_alerts = {row["id"] for row in self.detail(self.acme)["alerts"]}
        foreign_alerts = {row["id"] for row in self.detail(self.nebula)["alerts"]}
        self.assertTrue(own_alerts)
        self.assertTrue(own_alerts.issubset(ids))
        self.assertTrue(foreign_alerts.isdisjoint(ids))
        self.assertTrue({self.nebula, "article:nebula", "domain:example.org"}.isdisjoint(ids))
        for edge in graph["edges"]:
            self.assertNotIn(self.nebula, (edge["from_id"], edge["to_id"]))
            self.assertNotIn("article:nebula", (edge["from_id"], edge["to_id"]))
        response = self.client.get("/api/company-risk", params={"id": self.acme})
        self.assertEqual(response.status_code, 200, response.text)
        risks = response.json()["items"]
        self.assertTrue(risks)
        self.assertEqual({row["company_id"] for row in risks}, {self.acme})
        self.assertTrue(all(row["asset_id"] in {self.acme, "domain:example.com"} for row in risks))

    def test_upgrade_rechecks_legacy_projection_instead_of_trusting_valid_but_wrong_owner(self):
        document = self.article(self.acme, "example.com", "article:legacy-wrong")
        self.stage({"entities": [document], "advisories": [{"id": "CVE-2026-12345",
                    "affected": [{"vendor": "postgresql", "product": "postgresql", "part": "a"}]}]})
        self.assertTrue(self.detail(self.acme)["observations"])
        self.assertEqual(self.detail(self.acme)["alerts"], [])
        changed = copy.deepcopy(document)
        changed["source_url"] = "https://example.org/feed.xml"
        changed["metadata"]["company_context"]["domain"] = "example.org"
        changed["metadata"]["fields"]["url"] = "https://example.org/blog/platform"
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE entities SET source_url=?,metadata=? WHERE id=?",
                         (changed["source_url"], json.dumps(changed["metadata"]), changed["id"]))
            conn.execute("DELETE FROM evidence_resolution_migrations WHERE version='company-isolation-v1'")
        self.open_app()
        self.assert_no_projection(self.acme)
        self.assert_no_projection(self.nebula)
        self.assertEqual(self.detail(document["id"])["metadata"]["fields"]["description"], document["metadata"]["fields"]["description"])


if __name__ == "__main__":
    unittest.main()
