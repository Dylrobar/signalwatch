import asyncio
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from signalwatch.extension_corporate import SOURCE_DEFINITIONS, _discovered_links, collect_corporate_sources, normalize_corporate
from signalwatch.ingestion import staging_queue
from signalwatch.store import Store


def envelope(payload, provider, **target):
    body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
    return {"id": 1, "payload": body, "payload_hash": hashlib.sha256(body).hexdigest(),
            "source_url": "https://example.com/feed.xml", "observed_at": "2026-10-19T20:00:00Z",
            "metadata": {"provider": provider, "target": {"domain": "example.com", **target}}}


class RoutedHTTP:
    def __init__(self, root, routes):
        self.root, self.routes, self.calls = root, routes, []
        self.active, self.peak = 0, 0

    async def get(self, url, **options):
        self.calls.append((url, options))
        self.active += 1
        self.peak = max(self.peak, self.active)
        await asyncio.sleep(0)
        self.active -= 1
        body, content_type = self.routes[url]
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        path = self.root / hashlib.sha256(url.encode()).hexdigest()
        path.write_bytes(body)
        return SimpleNamespace(path=path, status=200, headers={"Content-Type": content_type}, changed=False,
                               digest=hashlib.sha256(body).hexdigest(), url=url)


RSS = b'''<?xml version="1.0"?><rss version="2.0"><channel><title>Engineering</title>
<link>https://example.com/blog</link><description>Engineering blog</description><item>
<guid>post-1</guid><link>https://example.com/blog/our-stack</link><title> Our platform </title>
<description>&lt;p&gt; We operate Kubernetes and Kafka. &lt;/p&gt;</description>
<pubDate>Sun, 18 Oct 2026 10:30:00 -0400</pubDate></item></channel></rss>'''


class TechnographicNormalizationTests(unittest.TestCase):
    def test_ashby_uses_public_documented_fields_without_requiring_undocumented_id(self):
        job = {"title": "SRE", "jobUrl": "https://jobs.ashbyhq.com/example/one", "publishedAt": "2026-10-18T10:30:00+00:00",
               "descriptionHtml": "<p> We run Kubernetes. </p>", "department": "Engineering"}
        batch = normalize_corporate(envelope({"jobs": [job]}, "ashby", company_id="company:example"))
        entity = batch["entities"][0]
        fields = entity["metadata"]["fields"]
        self.assertEqual((fields["title"], fields["url"], fields["description"]), ("SRE", job["jobUrl"], "We run Kubernetes."))
        self.assertEqual(fields["published_at"], job["publishedAt"])
        self.assertEqual(entity["metadata"]["company_context"]["company_id"], "company:example")
        self.assertEqual(batch["edges"][0]["relation"], "has_public_evidence")
        self.assertFalse(entity["metadata"]["deployment_verified"])
        job["descriptionHtml"] = "<p>Updated stack</p>"
        self.assertEqual(entity["id"], normalize_corporate(envelope({"jobs": [job]}, "ashby", company_id="company:example"))["entities"][0]["id"])

    def test_ashby_limits_records_and_rejects_unidentifiable_rows(self):
        job = {"title": "SRE", "jobUrl": "https://jobs.ashbyhq.com/example/one"}
        batch = normalize_corporate(envelope({"jobs": [job, {**job, "jobUrl": "https://jobs.ashbyhq.com/example/two"}]}, "ashby"), max_records=1)
        self.assertTrue(batch["entities"][0]["metadata"]["coverage_truncated"])
        self.assertIsNone(batch["entities"][0]["metadata"]["fields"]["published_at"])
        for payload in ({}, {"jobs": [{"title": "SRE"}]}, {"jobs": [{"jobUrl": job["jobUrl"]}]}):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                normalize_corporate(envelope(payload, "ashby"))

    def test_greenhouse_keeps_first_publication_separate_from_updated_and_observed_dates(self):
        job = {"id": 1, "title": "Security Engineer", "absolute_url": "https://jobs.example/1", "first_published": "2026-09-01T00:00:00Z",
               "updated_at": "2026-10-18T00:00:00Z", "content": "<p> Our security team uses Okta. </p>"}
        fields = normalize_corporate(envelope({"jobs": [job]}, "greenhouse"))["entities"][0]["metadata"]["fields"]
        self.assertEqual(fields["published_at"], job["first_published"])
        self.assertEqual(fields["url"], job["absolute_url"])
        self.assertEqual(fields["description"], "Our security team uses Okta.")
        job.pop("first_published")
        self.assertIsNone(normalize_corporate(envelope({"jobs": [job]}, "greenhouse"))["entities"][0]["metadata"]["fields"]["published_at"])

    def test_lever_includes_responsibility_lists_and_millisecond_publication_date(self):
        job = {"id": "job-one", "text": "Network Engineer", "hostedUrl": "https://jobs.lever.co/example/one", "createdAt": 0,
               "descriptionPlain": " Work with our team. ", "lists": [{"text": " Our infrastructure ", "content": "<ul><li>We manage FortiGate.</li></ul>"}]}
        fields = normalize_corporate(envelope([job], "lever"))["entities"][0]["metadata"]["fields"]
        self.assertEqual(fields["published_at"], "1970-01-01T00:00:00+00:00")
        self.assertEqual(fields["description"], "Work with our team.\nOur infrastructure\nWe manage FortiGate.")
        self.assertEqual((fields["title"], fields["url"]), (job["text"], job["hostedUrl"]))

    def test_long_job_body_keeps_structured_fields_instead_of_collapsing_to_preview(self):
        description = "We use Kubernetes. " * 1200
        fields = normalize_corporate(envelope({"jobs": [{"id": 1, "title": "SRE", "content": description}]}, "greenhouse"))["entities"][0]["metadata"]["fields"]
        self.assertEqual(fields["description"], description.strip()[:12000])
        self.assertNotIn("preview", fields)

    def test_rss_article_preserves_real_publication_date_and_company_context(self):
        batch = normalize_corporate(envelope(RSS, "company_feeds", name="Example"))
        entity = batch["entities"][0]
        self.assertEqual((entity["kind"], entity["metadata"]["evidence_role"]), ("company_article", "company_publication"))
        self.assertEqual(entity["metadata"]["company_context"], {"domain": "example.com", "name": "Example"})
        self.assertEqual(entity["metadata"]["fields"], {"title": "Our platform", "url": "https://example.com/blog/our-stack",
                         "description": "We operate Kubernetes and Kafka.", "published_at": "2026-10-18T14:30:00+00:00"})
        self.assertEqual(batch["edges"], [])

    def test_atom_content_is_used_and_missing_publication_date_is_not_fabricated(self):
        body = b'''<feed xmlns="http://www.w3.org/2005/Atom"><title>Engineering</title><id>https://example.com/feed</id>
<entry><id>urn:uuid:one</id><title>Stack</title><link href="https://example.com/blog/stack"/>
<content type="html">&lt;p&gt; Our databases run PostgreSQL. &lt;/p&gt;</content></entry></feed>'''
        fields = normalize_corporate(envelope(body, "company_feeds"))["entities"][0]["metadata"]["fields"]
        self.assertEqual(fields["description"], "Our databases run PostgreSQL.")
        self.assertIsNone(fields["published_at"])
        with self.assertRaisesRegex(ValueError, "RSS or Atom"):
            normalize_corporate(envelope(b"<html>Feed temporarily unavailable</html>", "company_feeds"))

    def test_discovery_recognizes_only_exact_ashby_host_and_typed_publication_feeds(self):
        body = b'''<html><link rel="alternate" type="application/rss+xml" href="/feed.xml"/>
<link rel="alternate" type="application/atom+xml; charset=utf-8" href="https://feeds.example.org/company.atom"/>
<link rel="alternate" type="text/html" href="/spanish"/><a href="https://jobs.ashbyhq.com/example/one">Jobs</a>
<a href="https://jobs.ashbyhq.com.evil.example/no">Fake board</a><a href="https://blog.example.com/">Engineering</a></html>'''
        links = _discovered_links(body, "https://example.com/", "example.com")
        self.assertEqual(links["feed_urls"], ["https://example.com/feed.xml"])
        self.assertEqual([(row["provider"], row["slug"]) for row in links["boards"]], [("ashby", "example")])
        self.assertEqual(links["pages"], ["https://blog.example.com/"])

    def test_discovery_prioritizes_careers_and_engineering_within_three_page_budget(self):
        body = b'''<html><a href="/about">About</a><a href="/careers">Careers</a><a href="/jobs/other">Other jobs</a>
<a href="/blog">Engineering blog</a><a href="/news">News</a></html>'''
        self.assertEqual(_discovered_links(body, "https://example.com/", "example.com")["pages"][:2],
                         ["https://example.com/careers", "https://example.com/blog"])

    def test_job_and_feed_html_keep_paragraph_boundaries_without_splitting_inline_tech(self):
        body = "<p>We use <strong>Terraform</strong> in production.</p><p>Our logs use Splunk.</p><ul><li>Required experience.</li></ul>"
        job = {"id": 1, "title": "SRE", "content": body}
        description = normalize_corporate(envelope({"jobs": [job]}, "greenhouse"))["entities"][0]["metadata"]["fields"]["description"]
        self.assertEqual(description, "We use Terraform in production.\nOur logs use Splunk.\nRequired experience.")
        feed = RSS.replace(b"&lt;p&gt; We operate Kubernetes and Kafka. &lt;/p&gt;", b"&lt;p&gt;We use &lt;b&gt;Terraform&lt;/b&gt;.&lt;/p&gt;&lt;p&gt;Our logs use Splunk.&lt;/p&gt;")
        description = normalize_corporate(envelope(feed, "company_feeds"))["entities"][0]["metadata"]["fields"]["description"]
        self.assertEqual(description, "We use Terraform .\nOur logs use Splunk.")

    def test_job_offset_selects_bounded_slice_and_rejects_invalid_offsets(self):
        payload = {"jobs": [{"id": index, "title": "Job " + str(index)} for index in range(5)]}
        raw = envelope(payload, "greenhouse")
        raw["metadata"]["record_offset"] = 2
        batch = normalize_corporate(raw, max_records=2)
        self.assertEqual([value["name"] for value in batch["entities"]], ["Job 2", "Job 3"])
        for offset in (-1, True, "2"):
            raw["metadata"]["record_offset"] = offset
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                normalize_corporate(raw, max_records=2)


class TechnographicCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.store = Store(self.root / "db.sqlite")
        self.config = {"public_source_batch": 3, "public_source_records": 100, "public_source_concurrency": 2,
                       "staging_max_payload_mb": 8, "staging_max_mb": 16, "staging_max_records": 100,
                       "source_targets": [{"domain": "example.com", "name": "Example"}],
                       "provider_settings": {row["id"]: {"enabled": False} for row in SOURCE_DEFINITIONS}}

    def collect(self, http):
        return asyncio.run(collect_corporate_sources(self.config, self.store, http))

    def test_discovery_fetches_company_linked_ashby_and_engineering_feed_without_setup(self):
        for provider in ("corporate_discovery", "ashby", "company_feeds"):
            self.config["provider_settings"][provider] = {"enabled": True}
        http = RoutedHTTP(self.root, {
            "https://example.com/robots.txt": (b"User-agent: *\nAllow: /", "text/plain"),
            "https://example.com/": (b'<html><a href="/about">About</a><a href="/careers">Careers</a><a href="/blog">Blog</a></html>', "text/html"),
            "https://example.com/careers": (b'<html><a href="https://jobs.ashbyhq.com/example">Jobs</a></html>', "text/html"),
            "https://example.com/blog": (b'<html><link rel="alternate" type="application/rss+xml" href="/feed.xml"/></html>', "text/html"),
            "https://api.ashbyhq.com/posting-api/job-board/example": ({"jobs": [{"title": "SRE", "jobUrl": "https://jobs.ashbyhq.com/example/one", "descriptionPlain": "We operate Kubernetes."}]}, "application/json"),
            "https://example.com/feed.xml": (RSS, "application/rss+xml")})
        result = self.collect(http)
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["staged"], 5)
        self.assertNotIn("https://example.com/about", [url for url, _ in http.calls])
        cached = self.store.source_state("corporate_sources")["discovery"]["example.com"]
        self.assertEqual((cached["boards"][0]["provider"], cached["feed_urls"]), ("ashby", ["https://example.com/feed.xml"]))
        queued = staging_queue(self.store, self.config).list()["items"]
        ashby = next(value for value in queued if value["metadata"]["provider"] == "ashby")
        self.assertEqual(ashby["metadata"]["discovered_from"], "https://example.com/careers")
        with patch.object(self.store, "touch_technographic_source", create=True, return_value=0) as touch:
            calls = len(http.calls)
            second = self.collect(http)
            self.assertEqual((second["staged"], second["unchanged"], len(http.calls) - calls), (0, 2, 2))
            self.assertEqual(touch.call_count, 2)

    def test_unchanged_source_touches_last_seen_without_reparsing_or_restaging(self):
        self.config["provider_settings"]["company_feeds"] = {"enabled": True}
        self.config["source_targets"][0]["feed_urls"] = ["https://example.com/feed.xml"]
        http = RoutedHTTP(self.root, {"https://example.com/feed.xml": (RSS, "application/rss+xml")})
        self.assertEqual(self.collect(http)["staged"], 1)
        with patch.object(self.store, "touch_technographic_source", create=True, return_value=1) as touch, patch("signalwatch.extension_corporate.normalize_corporate", side_effect=AssertionError("unchanged body parsed")):
            result = self.collect(http)
        self.assertEqual((result["staged"], result["unchanged"]), (0, 1))
        self.assertEqual(touch.call_args.args[:2], ("https://example.com/feed.xml", {"domain": "example.com", "name": "Example"}))
        self.assertTrue(http.calls[-1][1]["cache"])

    def test_discovery_uses_independent_batch_and_bounded_parallelism(self):
        self.config["provider_settings"]["corporate_discovery"] = {"enabled": True, "batch": 5}
        self.config["public_source_batch"] = 1
        self.config["source_targets"] = [{"domain": "company%d.example" % index} for index in range(7)]
        routes = {}
        for target in self.config["source_targets"]:
            routes["https://" + target["domain"] + "/robots.txt"] = (b"User-agent: *\nAllow: /", "text/plain")
            routes["https://" + target["domain"] + "/"] = (b"<html>No links</html>", "text/html")
        http = RoutedHTTP(self.root, routes)
        result = self.collect(http)
        self.assertEqual(result["provider_health"]["corporate_discovery"]["attempted"], 5)
        self.assertEqual(self.store.source_state("corporate_sources")["discovery_cursor"], 5)
        self.assertEqual(http.peak, 2)

    def test_legacy_weekly_cache_revisited_once_for_new_feed_discovery(self):
        import time
        self.config["provider_settings"]["corporate_discovery"] = {"enabled": True}
        self.store.update_source("corporate_sources", discovery={"example.com": {"checked_at": time.time(), "boards": [], "document_urls": [], "pages": [], "ciks": []}})
        http = RoutedHTTP(self.root, {"https://example.com/robots.txt": (b"User-agent: *\nAllow: /", "text/plain"),
                                     "https://example.com/": (b'<html><link rel="alternate" type="application/rss+xml" href="/feed.xml"/></html>', "text/html")})
        self.assertEqual(self.collect(http)["provider_health"]["corporate_discovery"]["attempted"], 1)
        self.assertEqual(self.collect(http)["provider_health"]["corporate_discovery"]["attempted"], 0)

    def test_cached_large_boards_progress_beyond_first_hundred_then_stop_reparsing(self):
        for provider, field, endpoint in (("greenhouse", "greenhouse_board", "https://boards-api.greenhouse.io/v1/boards/example/jobs"),
                                          ("lever", "lever_site", "https://api.lever.co/v0/postings/example"),
                                          ("ashby", "ashby_board", "https://api.ashbyhq.com/posting-api/job-board/example")):
            with self.subTest(provider=provider):
                self.store = Store(self.root / (provider + ".sqlite"))
                self.config["provider_settings"] = {row["id"]: {"enabled": row["id"] == provider} for row in SOURCE_DEFINITIONS}
                self.config["source_targets"] = [{"domain": "example.com", field: "example"}]
                jobs = [{"id": index, "title": "Job " + str(index), "text": "Job " + str(index),
                         "jobUrl": "https://jobs.ashbyhq.com/example/" + str(index)} for index in range(205)]
                payload = jobs if provider == "lever" else {"jobs": jobs}
                http = RoutedHTTP(self.root, {endpoint: (payload, "application/json")})
                self.assertEqual([self.collect(http)["records"] for _ in range(3)], [100, 100, 5])
                with patch("signalwatch.extension_corporate.normalize_corporate", side_effect=AssertionError("completed board parsed")):
                    self.assertEqual(self.collect(http)["unchanged"], 1)
                queue = staging_queue(self.store, self.config)
                items = queue.list()["items"]
                self.assertEqual(len(items), 3)
                self.assertEqual({value["metadata"]["source_record_offset"] for value in items}, {0, 100, 200})
                self.assertEqual({value["metadata"]["record_offset"] for value in items}, {0})
                self.assertEqual(len({value["stream_key"] for value in items}), 1)
                self.assertEqual(sorted(len((json.loads(queue.get(value["id"], include_payload=True)["payload"])["jobs"] if provider != "lever" else json.loads(queue.get(value["id"], include_payload=True)["payload"]))) for value in items), [5, 100, 100])
                self.assertTrue(all(value["metadata"]["source_total_records"] == 205 for value in items))
                entities = [entity for value in items for entity in normalize_corporate(queue.get(value["id"], include_payload=True))["entities"]]
                self.assertEqual({value["name"] for value in entities}, {"Job " + str(index) for index in range(205)})
                if provider == "lever":
                    self.assertEqual(http.calls[0][1]["params"], {"mode": "json"})

    def test_changed_job_board_resets_chunk_cursor_and_failed_chunk_does_not_advance(self):
        self.config["provider_settings"]["greenhouse"] = {"enabled": True}
        self.config["source_targets"][0]["greenhouse_board"] = "example"
        self.config["public_source_records"] = 1
        endpoint = "https://boards-api.greenhouse.io/v1/boards/example/jobs"
        payload = {"jobs": [{"id": 1, "title": "First"}, {"id": 2, "title": "Second"}]}
        http = RoutedHTTP(self.root, {endpoint: (payload, "application/json")})
        self.assertEqual(self.collect(http)["records"], 1)
        identity = next(iter(self.store.source_state("corporate_sources")["job_pages"]))
        with patch("signalwatch.extension_corporate.normalize_corporate", side_effect=ValueError("bad chunk")):
            self.assertTrue(self.collect(http)["errors"])
        self.assertEqual(self.store.source_state("corporate_sources")["job_pages"][identity]["next_offset"], 1)
        payload["jobs"][0]["title"] = "Updated first"
        self.assertEqual(self.collect(http)["records"], 1)
        newest = staging_queue(self.store, self.config).list()["items"][0]
        self.assertEqual(newest["metadata"]["source_record_offset"], 0)

    def test_staged_job_subsets_fit_payload_limit_and_keep_original_response_provenance(self):
        self.config["provider_settings"]["greenhouse"] = {"enabled": True}
        self.config["source_targets"][0]["greenhouse_board"] = "example"
        self.config["staging_max_payload_mb"] = 0.1
        endpoint = "https://boards-api.greenhouse.io/v1/boards/example/jobs"
        jobs = [{"id": index, "title": "Job " + str(index), "content": "We use Terraform. " + "x" * 50000} for index in range(5)]
        http = RoutedHTTP(self.root, {endpoint: ({"jobs": jobs}, "application/json")})
        results = [self.collect(http) for _ in range(3)]
        self.assertEqual([value["records"] for value in results], [2, 1, 2])
        queue = staging_queue(self.store, self.config)
        items = queue.list()["items"]
        self.assertTrue(all(value["payload_size"] <= int(0.1 * 1024 * 1024) for value in items))
        self.assertTrue(all(options["max_bytes"] == 32 * 1024 * 1024 for _, options in http.calls))
        for value in items:
            entity = normalize_corporate(queue.get(value["id"], include_payload=True))["entities"][0]
            self.assertEqual(entity["metadata"]["staging"]["source_response_hash"], value["metadata"]["source_response_hash"])
            self.assertEqual(entity["metadata"]["source_selection"]["total_records"], 5)
