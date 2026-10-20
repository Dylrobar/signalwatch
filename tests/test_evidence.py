import csv
import io
import json
import unittest
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.testclient import TestClient

from signalwatch.evidence import decorate, register_evidence_routes
from signalwatch.store import Store
from tests.test_technographic_store import posting


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")
        self.store.ingest({"entities": [{"id": "company:acme", "kind": "company", "name": "Acme"},
                                         {"id": "domain:acme.test", "kind": "domain", "value": "acme.test"},
                                         {"id": "company:other", "kind": "company", "name": "Other"},
                                         {"id": "domain:other.test", "kind": "domain", "value": "other.test"}],
                           "edges": [{"from_id": "company:acme", "to_id": "domain:acme.test", "relation": "official_website"},
                                     {"from_id": "company:other", "to_id": "domain:other.test", "relation": "official_website"}]})
        app = FastAPI()
        register_evidence_routes(app, self.store, {})
        self.client = TestClient(app)

    def get(self, path="evidence", **query):
        return self.client.get("/api/companies/" + path, params={"id": "company:acme", **query})

    def ingest(self, text, **kwargs):
        self.store.ingest({"entities": [posting(text, **kwargs)]})

    def test_filtered_pagination_and_csv_keep_company_scope(self):
        self.ingest("We use PostgreSQL in production.")
        self.ingest("We use Terraform in production.", key="job:2", url="https://boards.greenhouse.io/acme/jobs/2")
        self.ingest("We use Okta in production.", key="job:3", url="https://boards.greenhouse.io/acme/jobs/3")
        self.ingest("We use Snowflake in production.", key="job:other", company_id="company:other")
        page = self.get(limit=1).json()
        self.assertGreater(page["total"], 1)
        items = list(page["items"])
        while page["next_cursor"]:
            page = self.get(limit=1, cursor=page["next_cursor"]).json()
            items.extend(page["items"])
        self.assertEqual(len(items), len({row["id"] for row in items}))
        self.assertEqual(len(items), page["total"])
        self.assertTrue(all(row["organization_id"] == "company:acme" for row in items))
        self.assertNotIn("Snowflake", [row["product_name"] for row in items])
        filtered = self.get(q="Terraform", status="asserted_use").json()
        self.assertEqual(filtered["total"], 1)
        self.assertGreater(len(filtered["categories"]), 1)
        response = self.get("evidence/export", q="Terraform", status="asserted_use")
        self.assertEqual(response.status_code, 200)
        exported = list(csv.DictReader(io.StringIO(response.text)))
        self.assertEqual(len(exported), 1)
        self.assertEqual(exported[0]["product_name"], "Terraform")
        self.assertEqual(exported[0]["filter_q"], "Terraform")

    def test_cursor_invalidates_on_change_and_rejects_cross_company_filters(self):
        self.ingest("We use PostgreSQL and Terraform in production.")
        cursor = self.get(limit=1).json()["next_cursor"]
        self.assertEqual(self.get(cursor=cursor, q="different").status_code, 400)
        self.assertEqual(self.get(cursor="not-json").status_code, 400)
        self.ingest("We use PostgreSQL, Terraform, and Okta in production.")
        self.assertEqual(self.get(cursor=cursor).status_code, 409)

    def test_unchanged_check_does_not_create_history_or_direct_observation(self):
        self.ingest("We use Terraform in production.")
        before = self.get().json()["items"][0]
        count = self.get("history").json()["total"]
        endpoint = posting("")["source_url"]
        self.store.touch_technographic_source(endpoint, {"company_id": "company:acme", "domain": "acme.test"}, "2030-01-01T00:00:00Z")
        after = self.get().json()["items"][0]
        self.assertEqual(before["last_observed_at"], after["last_observed_at"])
        self.assertEqual(after["last_checked_at"], "2030-01-01T00:00:00Z")
        self.assertIsNone(after["direct_observed_at"])
        self.assertEqual(self.get("history").json()["total"], count)

    def test_failed_partial_and_unseen_sources_never_remove_evidence(self):
        self.ingest("We use Terraform in production.")
        before = self.get("history").json()["total"]
        for state in ("partial", "error"):
            record = posting("No technology details available.")
            record["metadata"]["collection_status"] = state
            self.store.ingest({"entities": [record]})
            self.assertEqual(self.get().json()["items"][0]["product_name"], "Terraform")
            self.assertEqual(self.get("history").json()["total"], before)
        self.store.ingest({"entities": []})
        self.assertEqual(self.get("history").json()["total"], before)
        record = posting("No technology details available.")
        record["metadata"]["collection_status"] = "success"
        self.store.ingest({"entities": [record]})
        self.assertEqual(self.get().json()["total"], 0)
        events = self.get("history").json()["items"]
        event = next(row for row in events if row["kind"] == "no_longer_observed")
        self.assertEqual(event["before"][0]["product_name"], "Terraform")
        self.assertEqual(event["after"], [])
        self.assertIn("other sources", event["reason"])

    def test_history_withdraws_when_source_loses_company_ownership(self):
        self.ingest("We use Terraform in production.")
        self.assertGreater(self.get("history").json()["total"], 0)
        self.store.set_company_asset("company:acme", "https://acme.test", status="rejected", evidence="Wrong owner", source_url="https://acme.test")
        self.assertEqual(self.get("history").json()["total"], 0)
        self.assertEqual(self.get().json()["total"], 0)

    def test_failed_source_does_not_block_ownership_revocation(self):
        self.ingest("We use Terraform in production.")
        record = posting("No complete content.")
        record["metadata"]["collection_status"] = "partial"
        self.store.ingest({"entities": [record]})
        self.store.set_company_asset("company:acme", "https://acme.test", status="rejected", evidence="Wrong owner", source_url="https://acme.test")
        self.assertEqual(self.get().json()["total"], 0)
        self.assertEqual(self.get("history").json()["total"], 0)

    def test_migration_is_explicit_candidate_with_before_after(self):
        self.ingest("We are migrating from Oracle Database to PostgreSQL.")
        events = self.get("history").json()["items"]
        migration = next(row for row in events if row["kind"] == "migration_planned")
        self.assertEqual(migration["before"][0]["product_name"], "Oracle Database")
        self.assertEqual(migration["after"][0]["product_name"], "PostgreSQL")
        self.assertIn("not independently verified", migration["reason"])
        self.ingest("We are migrating from Oracle Database to PostgreSQL.\nWe use Terraform in production.")
        self.assertEqual(sum(row["kind"] == "migration_planned" for row in self.get("history").json()["items"]), 1)

    def test_publication_and_direct_response_have_different_freshness(self):
        common = {"first_seen_at": "2026-10-19T00:00:00Z", "last_seen_at": "2026-10-19T00:00:00Z", "published_at": "2020-01-01T00:00:00Z"}
        now = datetime(2026, 10, 20, tzinfo=timezone.utc)
        textual = decorate({**common, "source_type": "greenhouse"}, now=now)
        direct = decorate({**common, "source_type": "http_fingerprint"}, now=now)
        self.assertEqual(textual["freshness"]["status"], "stale")
        self.assertEqual(textual["freshness"]["basis"], "published_at")
        self.assertEqual(direct["freshness"]["status"], "fresh")
        self.assertEqual(direct["direct_observed_at"], common["last_seen_at"])

    def test_capture_time_survives_delayed_ingestion_and_older_replays(self):
        record = posting("We use Terraform in production.")
        record["observed_at"] = "2026-01-02T00:00:00Z"
        self.store.ingest({"entities": [record]})
        item = self.get().json()["items"][0]
        self.assertEqual(item["first_observed_at"], "2026-01-02T00:00:00+00:00")
        self.assertEqual(item["last_observed_at"], item["first_observed_at"])
        historical = posting("No technologies mentioned.")
        historical["observed_at"] = "2026-01-01T00:00:00Z"
        self.store.ingest({"entities": [historical]})
        self.assertEqual(self.get().json()["items"][0]["product_name"], "Terraform")
        self.assertEqual(self.get("history").json()["total"], 1)

    def test_export_escapes_spreadsheet_formulas(self):
        self.ingest("We use Terraform in production.")
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE tech_fingerprints SET evidence_snippet='=HYPERLINK(\"https://example.test\")'")
        rows = list(csv.DictReader(io.StringIO(self.get("evidence/export").text)))
        self.assertTrue(rows[0]["evidence_snippet"].startswith("'="))

    def test_unknown_company_is_not_an_empty_success(self):
        self.assertEqual(self.get(id="company:missing").status_code, 404)
        self.assertEqual(self.get(id="domain:acme.test").status_code, 400)
