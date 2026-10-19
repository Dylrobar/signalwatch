import asyncio
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from signalwatch.extension_corporate import SOURCE_DEFINITIONS, _discovered_links, collect_corporate_sources, normalize_corporate
from signalwatch.http import HTTPError
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.store import Store


CHILD = "8945006U6W5TYUM16C74"
PARENT = "INR2EJN1ERAN0W5ZP974"


def record(lei=CHILD, name="Microsoft India Corporation"):
    return {"type": "lei-records", "id": lei, "attributes": {"lei": lei, "entity": {"legalName": {"name": name}, "status": "ACTIVE", "legalAddress": {"country": "IN"}}, "registration": {"status": "ISSUED"}}}


def envelope(payload, **metadata):
    body = json.dumps(payload).encode()
    return {"id": 1, "source": "public:gleif", "source_url": "https://api.gleif.org/api/v1/lei-records",
            "payload": body, "payload_hash": hashlib.sha256(body).hexdigest(), "observed_at": "2026-10-19T07:00:00Z",
            "metadata": {"provider": "gleif", "target": {"name": "Microsoft", "domain": "microsoft.com", "company_id": "company:ms"}, **metadata}}


class RoutedHTTP:
    def __init__(self, root, routes):
        self.root, self.routes, self.calls = Path(root), routes, []

    async def get(self, url, **options):
        self.calls.append((url, options))
        value = self.routes[url]
        if callable(value):
            value = value(options)
        if isinstance(value, Exception):
            raise value
        body, content_type = value if isinstance(value, tuple) else (json.dumps(value).encode(), "application/json")
        path = self.root / (hashlib.sha256((url + json.dumps(options.get("params"))).encode()).hexdigest() + ".body")
        path.write_bytes(body)
        return SimpleNamespace(path=path, headers={"Content-Type": content_type}, status=200, changed=False,
                               digest=hashlib.sha256(body).hexdigest(), url=url)


class ZeroSetupCorporateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "db.sqlite")
        self.config = {"public_source_batch": 1, "public_source_records": 10, "public_source_concurrency": 2,
                       "staging_max_payload_mb": 8, "staging_max_mb": 16, "staging_max_records": 100,
                       "user_agent": "SignalWatch/0.11", "source_targets": [], "provider_credentials": {},
                       "provider_settings": {row["id"]: {"enabled": False} for row in SOURCE_DEFINITIONS}}

    def collect(self, http):
        return asyncio.run(collect_corporate_sources(self.config, self.store, http))

    def test_gleif_name_results_are_stable_candidates_without_deployment_or_ownership(self):
        payload = {"data": [record()], "meta": {"pagination": {"total": 5}}}
        batch = normalize_corporate(envelope(payload))
        entity = batch["entities"][0]
        self.assertEqual(entity["id"], "legal_entity:lei:" + CHILD)
        self.assertEqual(entity["metadata"]["evidence_role"], "registry_search_candidate")
        self.assertFalse(entity["metadata"]["ownership_verified"])
        self.assertFalse(entity["metadata"]["deployment_verified"])
        self.assertTrue(entity["metadata"]["coverage_truncated"])
        self.assertEqual(batch["edges"][0]["relation"], "registry_candidate")
        self.assertFalse(set(batch) & {"observations", "advisories"})
        other = envelope(payload)
        other["metadata"]["target"]["company_id"] = "company:other"
        self.assertEqual(normalize_corporate(other)["entities"][0]["id"], entity["id"])

    def test_gleif_parent_evidence_links_lei_records_without_claiming_target_ownership(self):
        batch = normalize_corporate(envelope({"data": record(PARENT, "MICROSOFT CORPORATION")}, gleif_child_lei=CHILD, gleif_relation="direct-parent"))
        self.assertEqual(batch["edges"], [{"from_id": "legal_entity:lei:" + CHILD, "to_id": "legal_entity:lei:" + PARENT,
                                          "relation": "reported_direct_parent", "source_url": "https://api.gleif.org/api/v1/lei-records",
                                          "observed_at": "2026-10-19T07:00:00Z", "confidence": 1.0}])
        self.assertEqual(batch["entities"][0]["metadata"]["evidence_role"], "registry_parent_record")
        self.assertEqual(normalize_corporate(envelope({"data": None})), {"entities": [], "edges": []})

    def test_gleif_malformed_shapes_ids_and_parent_context_fail(self):
        malformed = [{}, {"data": "error"}, {"data": [{"id": CHILD}]}, {"data": [record("bad")]},
                     {"data": [dict(record(), attributes={"lei": PARENT, "entity": {"legalName": {"name": "X"}}})]}]
        for payload in malformed:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                normalize_corporate(envelope(payload))
        with self.assertRaises(ValueError):
            normalize_corporate(envelope({"data": record()}, gleif_child_lei=CHILD, gleif_relation="direct-parent"))

    def test_gleif_collects_only_publisher_links_and_rotates_pages_after_cached_results(self):
        self.config["provider_settings"]["gleif"] = {"enabled": True}
        self.config["source_targets"] = [{"name": "Microsoft"}]
        child = record()
        child["relationships"] = {"direct-parent": {"links": {"lei-record": "https://api.gleif.org/api/v1/lei-records/" + CHILD + "/direct-parent"}},
                                  "ultimate-parent": {"links": {"lei-record": "https://unrelated.example/private"}}}
        def search(options):
            return {"data": [child], "meta": {"pagination": {"currentPage": options["params"]["page[number]"], "lastPage": 2, "total": 2}}}
        http = RoutedHTTP(self.root, {"https://api.gleif.org/api/v1/lei-records": search,
                                     "https://api.gleif.org/api/v1/lei-records/" + CHILD + "/direct-parent": {"data": record(PARENT, "MICROSOFT CORPORATION")}})
        first = self.collect(http)
        self.collect(http)
        self.collect(http)
        self.assertEqual(first["staged"], 2)
        self.assertEqual(first["provider_health"]["gleif"]["status"], "ok")
        self.assertEqual([options["params"]["page[number]"] for url, options in http.calls if url.endswith("/lei-records")], [1, 2, 1])
        self.assertFalse(any("unrelated" in url for url, _ in http.calls))
        self.assertTrue(all(options.get("headers") is None for _, options in http.calls))
        self.assertEqual(staging_queue(self.store, self.config).stats()["total"], 3)

    def test_discovery_extracts_company_linked_boards_documents_and_sec_identity_only(self):
        body = b'''<html><a href="https://job-boards.greenhouse.io/example/jobs/1">Jobs</a>
          <iframe src="https://boards.greenhouse.io/embed/job_board?for=example"></iframe>
          <a href="https://jobs.eu.lever.co/example">EU jobs</a><a href="/reports/report.pdf">Report</a>
          <a href="https://evil.example/report.pdf">Other document</a><a href="/careers">Careers</a>
          <a href="https://www.sec.gov/edgar/browse/?CIK=789019">SEC</a>
          <a href="https://job-boards.greenhouse.io.evil.example/false">Bad host</a></html>'''
        links = _discovered_links(body, "https://example.com/", "example.com")
        self.assertEqual([(row["provider"], row["slug"], row["region"]) for row in links["boards"]], [("greenhouse", "example", "global"), ("lever", "example", "eu")])
        self.assertEqual(links["document_urls"], ["https://example.com/reports/report.pdf"])
        self.assertEqual(links["ciks"], ["0000789019"])
        self.assertEqual(links["pages"], ["https://example.com/careers"])

    def test_discovery_and_collection_use_eu_endpoint_pdf_metadata_queue_and_cache(self):
        from pypdf import PdfWriter
        writer, output = PdfWriter(), io.BytesIO()
        writer.add_blank_page(width=72, height=72)
        writer.add_metadata({"/Producer": "Microsoft Word"})
        writer.write(output)
        for provider in ("corporate_discovery", "lever", "company_documents"):
            self.config["provider_settings"][provider] = {"enabled": True}
        self.config["source_targets"] = [{"name": "Example", "domain": "example.com"}]
        http = RoutedHTTP(self.root, {"https://example.com/robots.txt": (b"User-agent: *\nAllow: /", "text/plain"),
                                     "https://example.com/": (b'<html><a href="/careers">Careers</a></html>', "text/html"),
                                     "https://example.com/careers": (b'<html><a href="https://jobs.eu.lever.co/example">Jobs</a><a href="/report.pdf">Report</a></html>', "text/html"),
                                     "https://api.eu.lever.co/v0/postings/example": [{"id": "1", "text": "SRE", "descriptionPlain": "Linux experience"}],
                                     "https://example.com/report.pdf": (output.getvalue(), "application/pdf")})
        first = self.collect(http)
        self.assertEqual(first["staged"], 4)
        self.assertEqual(first["provider_health"]["lever"]["status"], "ok")
        drained = StagingWorker(self.store, self.config).drain(100)
        self.assertEqual(drained["processed"], 4)
        first_calls = len(http.calls)
        second = self.collect(http)
        self.assertEqual(second["staged"], 0)
        self.assertEqual(len(http.calls) - first_calls, 2)
        self.assertEqual(second["provider_health"]["corporate_discovery"]["cached_targets"], 1)
        self.assertEqual(second["provider_health"]["corporate_discovery"]["attempted"], 0)
        with self.store.connection() as conn:
            rows = [json.loads(row[0]) for row in conn.execute("SELECT metadata FROM entities WHERE kind='job_posting'")]
            self.assertEqual(rows[0]["discovered_from"], "https://example.com/careers")
            self.assertEqual(conn.execute("SELECT count(*) FROM observations").fetchone()[0], 0)

    def test_discovery_rotates_targets_and_honors_robot_exclusion(self):
        self.config["provider_settings"]["corporate_discovery"] = {"enabled": True, "batch": 1}
        self.config["source_targets"] = [{"domain": "one.example"}, {"domain": "two.example"}]
        http = RoutedHTTP(self.root, {"https://one.example/robots.txt": (b"User-agent: *\nDisallow: /", "text/plain"),
                                     "https://two.example/robots.txt": HTTPError(404, "https://two.example/robots.txt"),
                                     "https://two.example/": (b"<html>No links</html>", "text/html")})
        one, two = self.collect(http), self.collect(http)
        self.assertEqual(one["provider_health"]["corporate_discovery"]["status"], "error")
        self.assertEqual(two["provider_health"]["corporate_discovery"]["status"], "ok")
        self.assertNotIn("https://one.example/", [url for url, _ in http.calls])
        self.assertEqual(self.store.source_state("corporate_sources")["discovery_cursor"], 0)

    def test_discovery_is_bounded_and_explicit_disable_stops_network(self):
        body = ('<html>' + ''.join('<a href="/report%d.pdf">PDF</a><a href="https://jobs.lever.co/board%d">Jobs</a>' % (index, index) for index in range(50)) + '</html>').encode()
        links = _discovered_links(body, "https://example.com/", "example.com")
        self.assertEqual((len(links["boards"]), len(links["document_urls"])), (4, 4))
        self.config["source_targets"] = [{"name": "Example", "domain": "example.com"}]
        http = RoutedHTTP(self.root, {})
        self.collect(http)
        self.assertEqual(http.calls, [])

    def test_no_contact_or_credential_is_invented_for_sec_or_restricted_sources(self):
        for provider in ("sec_edgar", "importyeti", "linkedin_jobs", "indeed", "opencorporates"):
            self.config["provider_settings"][provider] = {"enabled": True}
        self.config["source_targets"] = [{"name": "Microsoft", "domain": "microsoft.com", "cik": "0000789019"}]
        http = RoutedHTTP(self.root, {})
        result = self.collect(http)
        self.assertEqual(http.calls, [])
        self.assertTrue(all(result["provider_health"][provider]["status"] == "unconfigured" for provider in ("sec_edgar", "importyeti", "linkedin_jobs", "indeed", "opencorporates")))

    def test_public_trade_uses_visible_tables_and_keeps_company_matches_as_candidates(self):
        body = b'''<html><title>Example - Dublin, Ireland - company Report - Import Yeti</title><table>
          <tr><th>HTS Code</th><th>Description</th></tr><tr><td>1234</td><td>Public hardware label</td></tr></table>
          <script>hidden_credentials="not-public"</script><table><tr><th>Email</th></tr><tr><td>locked@example.com</td></tr></table></html>'''
        raw = envelope({})
        raw.update(payload=body, payload_hash=hashlib.sha256(body).hexdigest(), source_url="https://www.importyeti.com/company/example")
        raw["metadata"] = {"provider": "importyeti_public", "target": {"name": "Example", "company_id": "company:example"}}
        batch = normalize_corporate(raw)
        entity = batch["entities"][0]
        self.assertEqual(entity["kind"], "freight_record")
        self.assertEqual(entity["metadata"]["fields"]["reported_address"], "Dublin, Ireland")
        self.assertEqual(entity["metadata"]["evidence_role"], "freight_search_candidate")
        self.assertEqual(batch["edges"][0]["relation"], "freight_candidate")
        self.assertNotIn("not-public", json.dumps(batch))
        self.assertNotIn("locked@example.com", json.dumps(batch))
        changed = copy.deepcopy(raw)
        changed["payload"] = body.replace(b"Public hardware label", b"Corrected public label")
        self.assertEqual(normalize_corporate(changed)["entities"][0]["id"], entity["id"])
        raw["metadata"]["target"]["name"] = "Different company"
        self.assertEqual(normalize_corporate(raw), {"entities": [], "edges": []})

    def test_public_trade_404_is_no_coverage_and_robots_blocks_before_page_request(self):
        self.config["provider_settings"]["importyeti_public"] = {"enabled": True}
        self.config["source_targets"] = [{"name": "Example"}]
        robots = "https://www.importyeti.com/robots.txt"
        page = "https://www.importyeti.com/company/example"
        http = RoutedHTTP(self.root, {robots: (b"User-agent: *\nDisallow: /search?q", "text/plain"), page: HTTPError(404, page)})
        result = self.collect(http)
        self.assertEqual(result["staged"], 0)
        self.assertEqual(result["provider_health"]["importyeti_public"]["unavailable_targets"], 1)
        self.assertEqual(result["provider_health"]["importyeti_public"]["records"], 0)
        blocked = RoutedHTTP(self.root, {robots: (b"User-agent: *\nDisallow: /", "text/plain")})
        self.assertEqual(self.collect(blocked)["provider_health"]["importyeti_public"]["status"], "error")
        self.assertEqual([url for url, _ in blocked.calls], [robots])
