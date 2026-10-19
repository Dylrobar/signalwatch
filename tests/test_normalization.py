import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from signalwatch.normalization import ADAPTERS, NormalizationError, normalize
from signalwatch.store import Store


def staged(value, adapter="auto", content_type="application/json", **options):
    payload = value if isinstance(value, bytes) else value.encode() if isinstance(value, str) else json.dumps(value).encode()
    return {"id": 12, "source": "uploaded-records", "adapter": adapter, "content_type": content_type, "source_url": "https://source.example/data", "metadata": {}, "observed_at": "2026-10-19T00:00:00Z", "payload": payload, "payload_hash": hashlib.sha256(payload).hexdigest(), **options}


class NormalizationTests(unittest.TestCase):
    def test_registry_contains_builtin_adapters(self):
        self.assertTrue({"normalized_batch", "vulnerability_json", "news", "dns", "pdf_metadata", "wireless", "opaque"} <= ADAPTERS.keys())

    def test_normalized_batch_preserves_empty_snapshots_and_deletion_markers(self):
        markers = {"kev_snapshot": [], "observations": [], "observation_snapshots": [{"asset_id": "domain:example.test", "origin": "sbom:inventory"}], "observation_pages": [{"asset_id": "domain:example.test", "source_url": "https://example.test/"}]}
        self.assertEqual(normalize(staged(markers)), markers)

    def test_normalized_batch_rejects_unknown_keys_and_nonarrays(self):
        for value in ({"entities": {}}, {"unexpected": []}, {"entities": ["not an object"]}, {"entities": [{}]}, {"entities": [{"id": "x", "metadata": []}]}):
            with self.subTest(value=value), self.assertRaises(NormalizationError):
                normalize(staged(value, "normalized_batch"))

    def test_normalized_batch_adds_record_provenance(self):
        batch = normalize(staged({"entities": [{"id": "x", "kind": "evidence", "metadata": {"existing": True}}], "advisories": [{"id": "CVE-2026-12345"}]}, "normalized_batch"))
        self.assertTrue(batch["entities"][0]["metadata"]["existing"])
        self.assertEqual(batch["entities"][0]["metadata"]["staging"]["raw_reference"], "staging:12")
        self.assertEqual(batch["advisories"][0]["_staging"]["id"], 12)

    def test_nvd_wrapper_reuses_existing_parser(self):
        record = {"id": "CVE-2026-12345", "descriptions": [{"lang": "en", "value": "NVD evidence"}], "published": "2026-10-01T00:00:00Z", "configurations": []}
        batch = normalize(staged({"vulnerabilities": [{"cve": record}]}))
        self.assertEqual(batch["advisories"][0]["id"], "CVE-2026-12345")
        self.assertEqual(batch["advisories"][0]["source"], "NVD")
        self.assertEqual(batch["advisories"][0]["summary"], "NVD evidence")
        self.assertNotIn("observations", batch)

    def test_github_and_osv_records_use_existing_parsers(self):
        github = {"ghsa_id": "GHSA-aaaa-bbbb-cccc", "summary": "GitHub record", "vulnerabilities": []}
        osv = {"id": "OSV-2026-1", "modified": "2026-10-01T00:00:00Z", "summary": "OSV record", "affected": [{"package": {"ecosystem": "PyPI", "name": "example"}}]}
        records = normalize(staged([github, osv], "vulnerability_json"))["advisories"]
        self.assertEqual([record["id"] for record in records], ["GHSA-aaaa-bbbb-cccc", "OSV:OSV-2026-1"])
        self.assertNotIn("raw", records[1])
        self.assertEqual(records[1]["_staging"]["payload_hash"], staged([github, osv])["payload_hash"])

    def test_canonical_advisory_does_not_invent_publication_time(self):
        record = {"id": "CVE-2026-12345", "title": "Canonical", "affected": [], "aliases": []}
        advisory = normalize(staged(record, "vulnerability_json"))["advisories"][0]
        self.assertNotIn("published", advisory)
        self.assertEqual(advisory["source"], "uploaded-records")

    def test_invalid_vulnerability_data_does_not_complete_with_zero_records(self):
        for value in ({"id": "CVE-2026-12345"}, {"vulnerabilities": "not a list"}, [], "{invalid"):
            with self.subTest(value=value), self.assertRaises(NormalizationError):
                normalize(staged(value, "vulnerability_json"))

    def test_unknown_json_is_evidence_and_cve_text_does_not_create_advisories(self):
        batch = normalize(staged({"description": "CVE-2026-12345 nginx 1.0 is installed", "server": "nginx"}))
        self.assertEqual(batch["entities"][0]["kind"], "evidence")
        self.assertFalse(set(batch) & {"advisories", "observations", "articles"})
        unrelated = normalize(staged({"application": "inventory", "vulnerabilities": [{"name": "mentioned issue"}]}))
        self.assertEqual(unrelated["entities"][0]["kind"], "evidence")

    def test_rss_news_preserves_articles_and_only_mentions_cves(self):
        feed = b'''<?xml version="1.0"?><rss version="2.0"><channel><title>News</title><link>https://news.example/</link><description>Feed</description><item><title>CVE-2026-12345 report</title><link>https://news.example/report?utm_source=test</link><description>Raw story &amp; context</description><pubDate>Sun, 18 Oct 2026 12:00:00 GMT</pubDate></item></channel></rss>'''
        batch = normalize(staged(feed, content_type="application/rss+xml"))
        self.assertEqual(batch["articles"][0]["url"], "https://news.example/report")
        self.assertEqual(batch["articles"][0]["cves"], ["CVE-2026-12345"])
        self.assertEqual(batch["articles"][0]["published"], "2026-10-18T12:00:00+00:00")
        self.assertNotIn("advisories", batch)
        self.assertNotIn("observations", batch)

    def test_atom_feed_and_linkless_rss_entry(self):
        atom = b'<feed xmlns="http://www.w3.org/2005/Atom"><title>News</title><entry><id>https://news.example/id</id><title>Story</title><summary>Text</summary><link href="https://news.example/atom"/></entry></feed>'
        self.assertEqual(normalize(staged(atom, "news"))["articles"][0]["url"], "https://news.example/atom")
        feed = b'<rss version="2.0"><channel><title>News</title><item><title>No link</title><description>Evidence only</description></item></channel></rss>'
        batch = normalize(staged(feed, "news"))
        self.assertEqual(batch["articles"], [])
        self.assertEqual(batch["entities"][0]["kind"], "evidence")

    def test_plain_news_requires_explicit_article_url(self):
        payload = "Unstructured news mentioning CVE-2026-12345"
        batch = normalize(staged(payload, "news", "text/plain"))
        self.assertNotIn("articles", batch)
        batch = normalize(staged(payload, "news", "text/plain", metadata={"title": "Explicit title", "article_url": "https://news.example/plain", "published": "2026-10-18", "feed_url": "https://news.example/feed"}))
        self.assertEqual(batch["articles"][0]["title"], "Explicit title")
        self.assertEqual(batch["articles"][0]["published"], "2026-10-18")

    def test_invalid_news_xml_is_diagnostic(self):
        with self.assertRaises(NormalizationError):
            normalize(staged("<rss><broken", "news", "application/rss+xml"))

    def test_dns_zone_text_preserves_txt_quotes_owner_and_ttl(self):
        payload = 'Bücher.Example. 300 IN TXT "v=spf1 include:_spf.example -all" "more  text"\nBücher.Example. 60 IN MX 10 mail.example.\n'
        batch = normalize(staged(payload, "dns", "text/dns"))
        records = [entity for entity in batch["entities"] if entity["kind"] == "dns_record"]
        self.assertEqual(records[0]["metadata"]["dns"], {"owner": "Bücher.Example.", "name": "xn--bcher-kva.example", "type": "TXT", "ttl": 300, "value": '"v=spf1 include:_spf.example -all" "more  text"'})
        self.assertEqual(records[1]["value"], "10 mail.example.")
        self.assertEqual(batch["edges"][0]["from_id"], "domain:xn--bcher-kva.example")
        self.assertTrue(all(edge["relation"] == "has_dns_record" for edge in batch["edges"]))

    def test_dns_record_families_and_structured_records(self):
        records = [{"name": "example.test.", "type": "A", "data": "192.0.2.1", "TTL": 20}, {"owner": "example.test", "type": "AAAA", "value": "2001:db8::1", "ttl": 10}, {"owner": "example.test", "type": "NS", "value": "ns.example.test."}, {"owner": "www.example.test", "type": "CNAME", "value": "example.test."}]
        batch = normalize(staged({"records": records}, "dns"))
        self.assertEqual(len(batch["edges"]), 4)
        self.assertFalse(any(entity["kind"] in {"company", "technology", "device"} for entity in batch["entities"]))

    def test_dns_invalid_records_fail_atomically(self):
        for payload in ("example.test. 20 IN A 2001:db8::1", "no dns", "example.test. IN SOA unknown", "example.test 30 IN A invalid"):
            with self.subTest(payload=payload), self.assertRaises(NormalizationError):
                normalize(staged(payload, "dns", "text/dns"))

    def test_dns_value_size_is_bounded_and_sources_retain_independent_evidence(self):
        with self.assertRaisesRegex(NormalizationError, "65535"):
            normalize(staged('example.test. 30 IN TXT "' + "x" * 65536 + '"', "dns", "text/dns"))
        payload = {"records": [{"owner": "example.test", "type": "TXT", "value": '"exact"', "ttl": 30}]}
        first = normalize(staged(payload, "dns"))
        second = normalize(staged(payload, "dns", source="other-public-source"))
        self.assertNotEqual(first["edges"][0]["to_id"], second["edges"][0]["to_id"])
        self.assertNotEqual(first["entities"][1]["metadata"]["staging_sources"], second["entities"][1]["metadata"]["staging_sources"])

    def test_pdf_extracted_metadata_and_text(self):
        batch = normalize(staged({"title": "Public report", "author": "Example", "pages": 17, "custom": {"tool": "extractor"}}, "pdf_metadata"))
        entity = batch["entities"][0]
        self.assertEqual(entity["kind"], "document")
        self.assertEqual(entity["metadata"]["extracted"]["pages"], 17)
        self.assertEqual(entity["metadata"]["staging"]["raw_reference"], "staging:12")
        text = normalize(staged("Title: Public report\nPages: 17", "pdf_metadata", "text/plain"))
        self.assertIn("Pages: 17", text["entities"][0]["metadata"]["extracted"]["text"])

    def test_pdf_binary_is_not_extracted_and_large_metadata_is_bounded(self):
        with self.assertRaises(NormalizationError):
            normalize(staged(b"%PDF-1.7\x00\xff", "pdf_metadata", "application/pdf"))
        batch = normalize(staged({"title": "report", "large": "x" * 100000}, "pdf_metadata"))
        self.assertTrue(batch["entities"][0]["metadata"]["extracted"]["truncated"])
        self.assertLess(len(json.dumps(batch)), 13000)

    def test_wireless_csv_keeps_explicit_fields_and_mac_flags(self):
        payload = 'BSSID,SSID,channel,observed_at\n02-11-22-33-44-55,"My, SSID",11,2026-10-18T12:00:00Z\n01:11:22:33:44:55,Broadcast,1,2026-10-18T12:01:00Z\n'
        records = normalize(staged(payload, "wireless", "text/csv"))["entities"]
        self.assertEqual(records[0]["value"], "02:11:22:33:44:55")
        self.assertTrue(records[0]["metadata"]["locally_administered"])
        self.assertFalse(records[0]["metadata"]["multicast"])
        self.assertEqual(records[0]["metadata"]["fields"]["SSID"], "My, SSID")
        self.assertEqual(records[0]["observed_at"], "2026-10-18T12:00:00Z")
        self.assertTrue(records[1]["metadata"]["multicast"])
        self.assertNotIn("vendor", records[0]["metadata"])

    def test_wireless_json_and_text_formats(self):
        records = normalize(staged(["aabb.ccdd.eeff", {"mac": "AABBCCDDEEFF", "channel": 6, "timestamp": 1700000000}], "wireless"))["entities"]
        self.assertEqual([record["value"] for record in records], ["aa:bb:cc:dd:ee:ff"] * 2)
        self.assertEqual(records[1]["metadata"]["fields"]["timestamp"], 1700000000)
        records = normalize(staged("2026-10-18 12:00 aa:bb:cc:dd:ee:ff seen", "wireless", "text/plain"))["entities"]
        self.assertEqual(records[0]["value"], "aa:bb:cc:dd:ee:ff")

    def test_wireless_invalid_mac_does_not_silently_return_empty(self):
        for value in (["notamac"], [{"address": "00:11:22:33:44"}], "no address", [{"ssid": "AP"}]):
            with self.subTest(value=value), self.assertRaises(NormalizationError):
                normalize(staged(value, "wireless"))

    def test_auto_requires_explicit_wireless_and_pdf_metadata_declarations(self):
        wireless = staged(["aa:bb:cc:dd:ee:ff"], metadata={"record_type": "wireless"})
        self.assertEqual(normalize(wireless)["entities"][0]["kind"], "wireless")
        self.assertEqual(normalize(staged(["aa:bb:cc:dd:ee:ff"]))["entities"][0]["kind"], "evidence")
        pdf = staged({"title": "Document"}, metadata={"record_type": "pdf_metadata"})
        self.assertEqual(normalize(pdf)["entities"][0]["kind"], "document")

    def test_json_key_order_does_not_change_generic_identity(self):
        first = normalize(staged('{"b":2,"a":1}'))["entities"][0]
        second = normalize(staged('{"a":1,"b":2}'))["entities"][0]
        self.assertEqual(first["id"], second["id"])
        other = normalize(staged('{"a":1,"b":2}', source="other-public-source"))["entities"][0]
        self.assertNotEqual(first["id"], other["id"])
        stream = normalize(staged('{"a":1,"b":2}', stream_key="other-dataset"))["entities"][0]
        self.assertNotEqual(first["id"], stream["id"])

    def test_record_limit_and_bad_input_are_nonretryable(self):
        with self.assertRaises(NormalizationError):
            normalize(staged(["aa:bb:cc:dd:ee:ff"] * 3, "wireless"), max_records=2)
        with self.assertRaises(NormalizationError):
            normalize(staged("{bad json"))
        with self.assertRaises(NormalizationError):
            normalize(staged({}, "not_an_adapter"))
        with self.assertRaises(NormalizationError):
            normalize(staged({}), max_records=5001)

    def test_binary_unknown_payload_is_bounded_evidence(self):
        batch = normalize(staged(b"\x00\xff\x81" * 10000, content_type="application/octet-stream"))
        entity = batch["entities"][0]
        self.assertIn("preview_base64", entity["metadata"])
        self.assertEqual(entity["metadata"]["payload_bytes"], 30000)
        self.assertLess(len(json.dumps(batch)), 5000)

    def test_heterogeneous_entities_fit_existing_store_without_new_source_tables(self):
        inputs = [staged('example.test. 300 IN TXT "nginx CVE-2026-12345"', "dns", "text/dns"), staged({"title": "Report", "author": "Vendor"}, "pdf_metadata"), staged(["02:11:22:33:44:55"], "wireless"), staged("news text CVE-2026-12345", "news", "text/plain")]
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / "test.db")
            for item in inputs:
                store.ingest(normalize(item))
            with store.connection() as connection:
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM advisories").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT COUNT(*) FROM observations").fetchone()[0], 0)
                kinds = {row[0] for row in connection.execute("SELECT DISTINCT kind FROM entities")}
            self.assertTrue({"domain", "dns_record", "document", "wireless", "evidence"} <= kinds)
