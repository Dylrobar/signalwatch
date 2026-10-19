import asyncio
import hashlib
import io
import json
import tempfile
import unittest
import zipfile
from pathlib import Path
from types import SimpleNamespace

from signalwatch.extension_corporate import SOURCE_DEFINITIONS, collect_corporate_sources, normalize_corporate
from signalwatch.ingestion import staging_queue
from signalwatch.store import Store


def item(payload, provider="greenhouse", **metadata):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return {"id": 37, "source": "public:" + provider, "source_url": "https://source.example/records", "payload": body,
            "payload_hash": hashlib.sha256(body).hexdigest(), "content_type": "application/json",
            "observed_at": "2026-10-19T00:00:00Z", "metadata": {"provider": provider, **metadata}}


class FakeHTTP:
    def __init__(self, root, payload, *, content_type="application/json", changed=True, error=None):
        self.path = Path(root) / "response.bin"
        self.path.write_bytes(payload if isinstance(payload, bytes) else json.dumps(payload).encode())
        self.calls = []
        self.error = error
        self.response = SimpleNamespace(path=self.path, headers={"Content-Type": content_type}, status=200,
                                        changed=changed, digest=hashlib.sha256(self.path.read_bytes()).hexdigest())

    async def get(self, url, **options):
        self.calls.append((url, options))
        if self.error:
            raise self.error
        return self.response


class CorporateNormalizationTests(unittest.TestCase):
    def test_catalog_distinguishes_verified_public_credential_and_import_modes(self):
        catalog = {row["id"]: row for row in SOURCE_DEFINITIONS}
        self.assertEqual(len(catalog), len(SOURCE_DEFINITIONS))
        self.assertEqual(catalog["greenhouse"]["access"], "public")
        self.assertEqual(catalog["sam_gov"]["access"], "api_key")
        self.assertEqual(catalog["freight_exports"]["access"], "configured_url")
        for provider in ("indeed", "linkedin_jobs", "glassdoor", "importyeti", "enigma"):
            self.assertEqual(catalog[provider]["access"], "import")
        self.assertTrue(all(row["family"] == "corporate" and row["category"] == "corporate" for row in catalog.values()))

    def test_greenhouse_jobs_keep_searchable_text_without_deployment_claims(self):
        payload = {"jobs": [{"id": 10, "title": "Platform Engineer", "absolute_url": "https://jobs.example/10",
                             "content": "&lt;p&gt;Experience with nginx and Linux.&lt;/p&gt;", "updated_at": "2026-10-18"}]}
        batch = normalize_corporate(item(payload, target={"company_id": "company:test", "domain": "example.com"}))
        entity = batch["entities"][0]
        self.assertEqual(entity["kind"], "job_posting")
        self.assertIn("nginx and Linux", entity["value"])
        self.assertEqual(entity["metadata"]["fields"]["description"], "Experience with nginx and Linux.")
        self.assertFalse(entity["metadata"]["deployment_verified"])
        self.assertEqual(entity["metadata"]["staging"]["raw_reference"], "staging:37")
        self.assertEqual(batch["edges"][0]["relation"], "has_public_evidence")
        self.assertFalse(set(batch) & {"observations", "advisories"})
        self.assertFalse(any(row["kind"] == "company" for row in batch["entities"]))
        changed = normalize_corporate(item({"jobs": [{**payload["jobs"][0], "content": "Updated description"}]}, target={"company_id": "company:test", "domain": "example.com"}))
        self.assertEqual(entity["id"], changed["entities"][0]["id"])

    def test_lever_fields_record_limit_and_empty_boards(self):
        payload = [{"id": "one", "text": "SRE", "descriptionPlain": "Kubernetes experience", "categories": {"location": "Remote"}},
                   {"id": "two", "text": "Engineer"}]
        batch = normalize_corporate(item(payload, "lever", record_limit=1))
        self.assertEqual(len(batch["entities"]), 1)
        self.assertTrue(batch["entities"][0]["metadata"]["coverage_truncated"])
        self.assertEqual(batch["entities"][0]["metadata"]["fields"]["categories"]["location"], "Remote")
        self.assertEqual(normalize_corporate(item({"jobs": []})), {"entities": [], "edges": []})

    def test_sec_columnar_filing_metadata_and_cik_mismatch(self):
        payload = {"cik": "123", "name": "Filer Inc.", "tickers": ["FILER"], "filings": {"recent": {
            "accessionNumber": ["0000000123-26-000001"], "form": ["10-K"], "filingDate": ["2026-10-18"],
            "primaryDocument": ["annual.htm"]}, "files": [{"name": "older.json"}]}}
        batch = normalize_corporate(item(payload, "sec_edgar", target={"cik": "0000000123"}))
        self.assertEqual(len(batch["entities"]), 2)
        self.assertEqual(batch["entities"][0]["metadata"]["evidence_role"], "sec_filer_metadata")
        self.assertEqual(batch["entities"][1]["metadata"]["fields"]["form"], "10-K")
        self.assertTrue(batch["entities"][1]["metadata"]["coverage_truncated"])
        with self.assertRaisesRegex(ValueError, "differs"):
            normalize_corporate(item(payload, "sec_edgar", target={"cik": "124"}))
        payload["filings"]["recent"]["form"] = []
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            normalize_corporate(item(payload, "sec_edgar"))

    def test_registry_search_matches_stay_candidates_and_sam_fields_are_public_subset(self):
        oc = {"results": {"companies": [{"company": {"name": "Search Match Ltd", "company_number": "123", "jurisdiction_code": "gb", "current_status": "Active"}}], "total_count": 2}}
        company = normalize_corporate(item(oc, "opencorporates"))["entities"][0]
        self.assertEqual(company["metadata"]["evidence_role"], "registry_search_candidate")
        self.assertFalse(company["metadata"]["ownership_verified"])
        self.assertTrue(company["metadata"]["coverage_truncated"])
        sam = {"entityData": [{"entityRegistration": {"ueiSAM": "ABCDEFGHIJK1", "legalBusinessName": "Search Match", "registrationStatus": "Active", "secretField": "not normalized"}, "pointsOfContact": {"private": "not normalized"}}]}
        entity = normalize_corporate(item(sam, "sam_gov"))["entities"][0]
        self.assertEqual(entity["metadata"]["fields"]["ueiSAM"], "ABCDEFGHIJK1")
        self.assertNotIn("not normalized", json.dumps(entity))

    def test_pdf_metadata_is_extracted_from_real_pdf_bytes(self):
        from pypdf import PdfWriter
        writer = PdfWriter()
        writer.add_blank_page(width=72, height=72)
        writer.add_metadata({"/Title": "Public report", "/Producer": "Office on Windows", "/Author": "Author"})
        output = io.BytesIO()
        writer.write(output)
        batch = normalize_corporate(item(output.getvalue(), "company_documents"))
        entity = batch["entities"][0]
        self.assertEqual(entity["metadata"]["fields"]["properties"]["Title"], "Public report")
        self.assertIn("Office on Windows", entity["value"])
        self.assertFalse(entity["metadata"]["fields"]["producer_is_deployment_evidence"])
        self.assertFalse(set(batch) & {"observations", "advisories"})

    def test_ooxml_properties_are_extracted_without_technology_inference(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", "<document/>")
            archive.writestr("docProps/core.xml", '<core xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Report</dc:title><dc:creator>Alice</dc:creator></core>')
            archive.writestr("docProps/app.xml", "<Properties><Application>Microsoft Word</Application><AppVersion>16.0</AppVersion></Properties>")
        batch = normalize_corporate(item(output.getvalue(), "company_documents"))
        fields = batch["entities"][0]["metadata"]["fields"]
        self.assertEqual(fields["format"], "ooxml")
        self.assertEqual(fields["properties"]["docProps/core.xml"]["creator"], "Alice")
        self.assertEqual(fields["properties"]["docProps/app.xml"]["Application"], "Microsoft Word")
        self.assertFalse(set(batch) & {"observations", "advisories"})

    def test_invalid_or_oversized_ooxml_does_not_succeed_with_empty_metadata(self):
        for xml in (b"<broken", b"<!DOCTYPE r [<!ENTITY x 'expanded'>]><r>&x;</r>", b"x" * (1024 * 1024 + 1)):
            output = io.BytesIO()
            with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("[Content_Types].xml", "<Types/>")
                archive.writestr("word/document.xml", "<document/>")
                archive.writestr("docProps/core.xml", xml)
            with self.subTest(xml_size=len(xml)), self.assertRaises(ValueError):
                normalize_corporate(item(output.getvalue(), "company_documents"))
        with self.assertRaises(ValueError):
            normalize_corporate(item(b"<html>Not a document</html>", "company_documents"))

    def test_procurement_freight_and_restricted_exports_remain_evidence(self):
        for provider in ("public_procurement", "freight_exports", "indeed", "linkedin_jobs", "glassdoor", "importyeti", "enigma"):
            raw = item(b'id,name,description\n1,Example,Uses nginx on Windows\n', provider)
            raw["content_type"] = "text/csv"
            with self.subTest(provider=provider):
                batch = normalize_corporate(raw)
                self.assertEqual(len(batch["entities"]), 1)
                self.assertFalse(set(batch) & {"observations", "advisories"})
                self.assertEqual(batch["edges"], [])

    def test_malformed_provider_responses_raise_instead_of_inventing_records(self):
        for provider, payload in (("greenhouse", {}), ("lever", {}), ("opencorporates", {}), ("sam_gov", {}), ("sec_edgar", {}), ("unknown", {})):
            with self.subTest(provider=provider), self.assertRaises(ValueError):
                normalize_corporate(item(payload, provider))


class CorporateCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "corporate.db")
        self.config = {"public_source_batch": 3, "public_source_records": 100, "public_source_concurrency": 4,
                       "staging_max_payload_mb": 8, "staging_max_mb": 16, "staging_max_records": 100,
                       "source_targets": [], "provider_credentials": {},
                       "provider_settings": {row["id"]: {"enabled": False} for row in SOURCE_DEFINITIONS}}

    def run_collect(self, http):
        return asyncio.run(collect_corporate_sources(self.config, self.store, http))

    def test_unconfigured_providers_are_not_reported_as_successful(self):
        self.config["provider_settings"] = {}
        http = FakeHTTP(self.root, {})
        result = self.run_collect(http)
        self.assertEqual(http.calls, [])
        self.assertEqual(result["staged"], 0)
        self.assertTrue(all(row["status"] == "unconfigured" for row in result["provider_health"].values()))

    def test_selected_jobs_are_staged_once_and_first_cached_fetch_is_not_lost(self):
        self.config["provider_settings"]["greenhouse"] = {"enabled": True}
        self.config["source_targets"] = [{"domain": "example.com", "name": "Example", "greenhouse_board": "example"}]
        raw = b' {"jobs":[{"id":1,"title":"SRE","content":"nginx"}]}\n'
        http = FakeHTTP(self.root, raw, changed=False)
        first = self.run_collect(http)
        self.assertEqual(first["staged"], 1)
        queued = staging_queue(self.store, self.config).list()["items"][0]
        selected = staging_queue(self.store, self.config).get(queued["id"], include_payload=True)["payload"]
        self.assertEqual(json.loads(selected), json.loads(raw))
        self.assertEqual(queued["metadata"]["source_response_hash"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(queued["metadata"]["source_record_offset"], 0)
        self.assertEqual(queued["metadata"]["source_total_records"], 1)
        self.assertEqual(queued["adapter"], "public_source")
        self.assertEqual(queued["metadata"]["provider"], "greenhouse")
        http.response.status = 304
        second = self.run_collect(http)
        self.assertEqual((second["staged"], second["unchanged"]), (0, 1))
        self.assertEqual(staging_queue(self.store, self.config).stats()["total"], 1)

    def test_each_provider_receives_its_own_request_budget(self):
        self.config["provider_settings"]["public_procurement"] = {"enabled": True, "url": "https://public.example/contracts.csv"}
        self.config["provider_settings"]["freight_exports"] = {"enabled": True, "url": "https://public.example/freight.csv"}
        self.config["public_source_batch"] = 1
        http = FakeHTTP(self.root, b"id,name\n1,Example\n", content_type="text/csv")
        result = self.run_collect(http)
        self.assertEqual(result["requests"], 2)
        self.assertEqual([url for url, _ in http.calls], ["https://public.example/contracts.csv", "https://public.example/freight.csv"])

    def test_per_provider_budget_rotates_targets_across_cycles(self):
        self.config["provider_settings"]["greenhouse"] = {"enabled": True}
        self.config["source_targets"] = [{"greenhouse_board": "one"}, {"greenhouse_board": "two"}]
        self.config["public_source_batch"] = 1
        http = FakeHTTP(self.root, {"jobs": []})
        first = self.run_collect(http)
        self.run_collect(http)
        self.assertEqual(first["provider_health"]["greenhouse"]["pending_targets"], 1)
        self.assertEqual([url for url, _ in http.calls], ["https://boards-api.greenhouse.io/v1/boards/one/jobs", "https://boards-api.greenhouse.io/v1/boards/two/jobs"])

    def test_changed_record_budget_reprocesses_cached_payload_with_new_context(self):
        self.config["provider_settings"]["greenhouse"] = {"enabled": True}
        self.config["source_targets"] = [{"greenhouse_board": "example"}]
        http = FakeHTTP(self.root, {"jobs": [{"id": 1, "title": "One"}, {"id": 2, "title": "Two"}]}, changed=False)
        self.config["public_source_records"] = 1
        self.assertEqual(self.run_collect(http)["records"], 1)
        self.config["public_source_records"] = 2
        second = self.run_collect(http)
        self.assertEqual((second["records"], second["staged"]), (2, 1))

    def test_registry_credentials_are_required_and_do_not_enter_staged_urls_or_errors(self):
        self.config["provider_settings"]["sam_gov"] = {"enabled": True}
        self.config["source_targets"] = [{"name": "Example"}]
        http = FakeHTTP(self.root, {"entityData": []})
        missing = self.run_collect(http)
        self.assertEqual(missing["provider_health"]["sam_gov"]["status"], "unconfigured")
        self.assertEqual(http.calls, [])
        self.config["provider_credentials"]["sam_gov"] = "test-private-key"
        fetched = self.run_collect(http)
        self.assertEqual(fetched["staged"], 1)
        self.assertEqual(http.calls[0][1]["params"]["api_key"], "test-private-key")
        self.assertFalse(http.calls[0][1]["cache"])
        self.assertFalse(http.calls[0][1]["allow_redirects"])
        public = staging_queue(self.store, self.config).list()
        self.assertNotIn("test-private-key", json.dumps(public))
        failed = FakeHTTP(self.root, {}, error=RuntimeError("https://api.sam.gov/?api_key=test-private-key"))
        result = self.run_collect(failed)
        self.assertNotIn("test-private-key", json.dumps(result))
        self.assertEqual(result["provider_health"]["sam_gov"]["status"], "error")

    def test_sec_requires_contact_user_agent_and_pads_configured_cik(self):
        self.config["provider_settings"]["sec_edgar"] = {"enabled": True}
        self.config["source_targets"] = [{"cik": "123", "name": "Example"}]
        http = FakeHTTP(self.root, {"cik": "123", "name": "Example", "filings": {"recent": {"accessionNumber": [], "form": [], "filingDate": []}}})
        missing = self.run_collect(http)
        self.assertEqual(missing["provider_health"]["sec_edgar"]["status"], "unconfigured")
        self.assertFalse(http.calls)
        self.config["provider_settings"]["sec_edgar"]["user_agent"] = "SignalWatch contact@example.test"
        result = self.run_collect(http)
        self.assertEqual(result["staged"], 1)
        self.assertEqual(http.calls[0][0], "https://data.sec.gov/submissions/CIK0000000123.json")
        self.assertEqual(http.calls[0][1]["headers"]["User-Agent"], "SignalWatch contact@example.test")

    def test_registry_credentials_accept_documented_object_forms_without_public_leaks(self):
        self.config["provider_settings"]["opencorporates"] = {"enabled": True}
        self.config["source_targets"] = [{"name": "Example", "domain": "example.test"}]
        for key_name in ("api_key", "token", "key"):
            with self.subTest(key_name=key_name):
                self.config["provider_credentials"]["opencorporates"] = {key_name: " test-private-token "}
                http = FakeHTTP(self.root, {"results": {"companies": []}})
                result = self.run_collect(http)
                self.assertEqual(result["provider_health"]["opencorporates"]["status"], "ok")
                self.assertEqual(http.calls[0][1]["headers"]["X-API-TOKEN"], "test-private-token")
                self.assertNotIn("test-private-token", json.dumps(staging_queue(self.store, self.config).list()))

    def test_restricted_provider_url_does_not_enable_an_unrestricted_scraper(self):
        self.config["provider_settings"]["linkedin_jobs"] = {"enabled": True, "url": "https://www.linkedin.com/jobs/"}
        http = FakeHTTP(self.root, {})
        result = self.run_collect(http)
        self.assertFalse(http.calls)
        self.assertEqual(result["provider_health"]["linkedin_jobs"]["status"], "unconfigured")

    def test_malformed_successful_response_is_reported_as_failure(self):
        self.config["provider_settings"]["greenhouse"] = {"enabled": True}
        self.config["source_targets"] = [{"greenhouse_board": "example"}]
        result = self.run_collect(FakeHTTP(self.root, {"unexpected": []}))
        self.assertEqual(result["staged"], 1)
        self.assertTrue(result["errors"])
        self.assertEqual(result["provider_health"]["greenhouse"]["status"], "error")
        queue = staging_queue(self.store, self.config)
        self.assertEqual(queue.stats()["counts"]["pending"], 1)
        self.assertEqual(queue.get(queue.list()["items"][0]["id"], include_payload=True)["payload"], b'{"unexpected": []}')

    def test_first_cached_304_body_is_staged_and_validated(self):
        self.config["provider_settings"]["greenhouse"] = {"enabled": True}
        self.config["source_targets"] = [{"greenhouse_board": "example"}]
        http = FakeHTTP(self.root, {"jobs": []}, changed=False)
        http.response.status = 304
        result = self.run_collect(http)
        self.assertEqual((result["staged"], result["records"]), (1, 0))
        self.assertEqual(result["provider_health"]["greenhouse"]["status"], "ok")
