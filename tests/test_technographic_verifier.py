import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from signalwatch.config import load_config
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.store import Store
from signalwatch.technographic_store import document_input
from signalwatch.technographic_verifier import (
    MAX_PROMPT_CHARS,
    METHOD,
    SYSTEM_PROMPT,
    _NoRedirect,
    _chat,
    _endpoint,
    _json,
    verify_batch,
    verifier_enabled,
)
from signalwatch.technographics import extract


class TechnographicVerifierTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "provider_settings": {"technographics": {"verifier_url": "https://models.example/chat/completions", "verifier_model": "configured-model"}},
            "provider_credentials": {"technographics": {"api_key": "configured-key"}},
        }
        self.store = Mock()
        self.store.technographic_document_seen.return_value = False

    def entity(self, body, number=1, company="company:acme"):
        return {"id": f"job_posting:{number}", "kind": "job_posting", "name": "Platform Engineer",
                "source_url": "https://boards-api.greenhouse.io/v1/boards/acme/jobs",
                "metadata": {"provider": "greenhouse", "company_context": {"company_id": company},
                             "fields": {"title": "Platform Engineer", "description": body,
                                        "url": f"https://boards.greenhouse.io/acme/jobs/{number}"}}}

    def test_missing_configuration_makes_zero_network_requests(self):
        variations = [{}, {"provider_settings": self.config["provider_settings"]}]
        for section, field in (("provider_settings", "verifier_url"), ("provider_settings", "verifier_model"), ("provider_credentials", "api_key")):
            config = copy.deepcopy(self.config)
            del config[section]["technographics"][field]
            variations.append(config)
        config = copy.deepcopy(self.config)
        config["provider_credentials"]["technographics"] = "not-a-credential-object"
        variations.append(config)
        for config in variations:
            with self.subTest(config=config), patch("signalwatch.technographic_verifier._chat") as chat:
                batch = {"entities": [self.entity("We use Terraform.")]}
                original = copy.deepcopy(batch)
                self.assertFalse(verifier_enabled(config))
                self.assertIs(verify_batch(batch, config, self.store), batch)
                self.assertEqual(batch, original)
                chat.assert_not_called()
        self.store.technographic_document_seen.assert_not_called()

    def test_explicitly_disabled_verifier_makes_zero_network_requests(self):
        self.config["provider_settings"]["technographics"]["enabled"] = False
        batch = {"entities": [self.entity("We use Terraform.")]}
        with patch("signalwatch.technographic_verifier._chat") as chat:
            self.assertFalse(verifier_enabled(self.config))
            self.assertIs(verify_batch(batch, self.config, self.store), batch)
            chat.assert_not_called()
        self.store.technographic_document_seen.assert_not_called()

    def test_endpoint_requires_https_or_loopback_http_and_exact_url(self):
        valid = ["https://models.example/v1/chat/completions", "http://127.0.0.1:8080/v1/chat/completions",
                 "http://[::1]:8080/v1/chat/completions", "http://localhost:8080/v1/chat/completions"]
        for value in valid:
            self.assertEqual(_endpoint(value), value)
        invalid = [None, "", "http://models.example/v1/chat/completions", "https://user:pass@models.example/v1",
                   "https://models.example:bad/v1", "https://models.example/v1#secret", "https://models.example/ bad",
                   "ftp://models.example/v1", " https://models.example/v1", "https:///v1", "http://127.0.0.1.evil.example/v1"]
        for value in invalid:
            with self.subTest(value=value):
                self.assertIsNone(_endpoint(value))

    def test_incoming_verification_metadata_is_discarded_even_when_inactive(self):
        for config in ({}, self.config):
            entity = self.entity("No technology signature.")
            entity["metadata"]["technographic_verification"] = {"content_hash": document_input(entity)["content_hash"],
                                                                "findings": [{"index": 0, "status": "asserted_use", "confidence": 1.0, "method": METHOD}]}
            with patch("signalwatch.technographic_verifier._chat") as chat:
                verify_batch({"entities": [entity]}, config, self.store)
            self.assertNotIn("technographic_verification", entity["metadata"])
            chat.assert_not_called()

    def test_only_matching_paragraphs_and_taxonomy_identities_are_sent(self):
        entity = self.entity("Private unrelated paragraph with sentinel-unmatched.\nWe use Terraform 1.9.\nOther unrelated material.")
        batch = {"entities": [entity]}
        original = copy.deepcopy(entity)
        with patch("signalwatch.technographic_verifier._chat", return_value=[{"index": 0, "status": "asserted_use", "confidence": 0.92}]) as chat:
            verify_batch(batch, self.config, self.store)
        endpoint, key, model, content = chat.call_args.args
        self.assertEqual((endpoint, key, model), ("https://models.example/chat/completions", "configured-key", "configured-model"))
        payload = json.loads(content)
        self.assertEqual(payload["paragraphs"], ["We use Terraform 1.9."])
        self.assertEqual(payload["candidates"][0]["product_name"], "Terraform")
        self.assertNotIn("sentinel-unmatched", content)
        self.assertNotIn("configured-key", content)
        self.assertNotIn("organization_context", content)
        self.assertNotIn("source_url", content)
        verification = entity["metadata"].pop("technographic_verification")
        self.assertEqual(entity, original)
        self.assertEqual(verification, {"content_hash": document_input(entity)["content_hash"],
                                        "findings": [{"index": 0, "status": "asserted_use", "confidence": 0.92, "method": METHOD}],
                                        "model": "configured-model", "method": METHOD})

    def test_asserted_use_can_be_downgraded_without_changing_identity(self):
        entity = self.entity("We use PAN-OS 11.2 in production.")
        with patch("signalwatch.technographic_verifier._chat", return_value=[{"index": 0, "status": "mention", "confidence": 0.3}]):
            verify_batch({"entities": [entity]}, self.config, self.store)
        checked = entity["metadata"]["technographic_verification"]["findings"]
        self.assertEqual(checked, [{"index": 0, "status": "mention", "confidence": 0.3, "method": METHOD}])
        self.assertEqual(extract(document_input(entity)["text"])[0]["version"], "11.2")

    def test_ambiguous_or_negative_candidates_cannot_be_promoted(self):
        bodies = ["Experience with Terraform required.", "We do not use Terraform.", "We previously used Terraform.",
                  "We plan to deploy Terraform.", "Terraform documentation is available.", "Experience with AWS or Azure preferred."]
        for body in bodies:
            with self.subTest(body=body):
                entity = self.entity(body)
                self.assertNotEqual(extract(document_input(entity)["text"], source_type="greenhouse")[0]["status"], "asserted_use")
                with patch("signalwatch.technographic_verifier._chat", return_value=[{"index": 0, "status": "asserted_use", "confidence": 0.99}]):
                    verify_batch({"entities": [entity]}, self.config, self.store)
                self.assertNotIn("technographic_verification", entity["metadata"])

    def test_duplicate_bodies_are_checked_once_per_organization(self):
        first = self.entity("We use Terraform.", 1)
        second = self.entity("We use Terraform.", 2)
        other_org = self.entity("We use Terraform.", 3, "company:other")
        with patch("signalwatch.technographic_verifier._chat", return_value=[]) as chat:
            verify_batch({"entities": [first, second, other_org]}, self.config, self.store)
        self.assertEqual(chat.call_count, 2)
        self.assertEqual(first["metadata"]["technographic_verification"], second["metadata"]["technographic_verification"])
        self.assertIsNot(first["metadata"]["technographic_verification"], second["metadata"]["technographic_verification"])
        self.assertEqual(self.store.technographic_document_seen.call_count, 2)

    def test_persisted_documents_zero_matches_and_unrelated_entities_make_zero_requests(self):
        self.store.technographic_document_seen.return_value = True
        with patch("signalwatch.technographic_verifier._chat") as chat:
            verify_batch({"entities": [self.entity("We use Terraform.")]}, self.config, self.store)
            chat.assert_not_called()
        self.store.technographic_document_seen.return_value = False
        with patch("signalwatch.technographic_verifier._chat") as chat:
            verify_batch({"entities": [self.entity("No technology signatures here."), {"kind": "domain", "id": "domain:acme.example"}]}, self.config, self.store)
            chat.assert_not_called()

    def test_batch_request_and_paragraph_limits_preserve_original_indices(self):
        paragraphs = [f"We use Terraform 1.{number}. " + "x" * 1200 for number in range(12)]
        entities = [self.entity("\n".join(paragraphs), number) for number in range(5)]
        entities[1:5] = [self.entity(f"We use Terraform 2.{number}.", number) for number in range(1, 5)]
        with patch("signalwatch.technographic_verifier._chat", return_value=[]) as chat:
            verify_batch({"entities": entities}, self.config, self.store)
        self.assertEqual(chat.call_count, 3)
        first_content = chat.call_args_list[0].args[3]
        payload = json.loads(first_content)
        self.assertLessEqual(len(payload["paragraphs"]), 8)
        self.assertLessEqual(len(first_content) + len(SYSTEM_PROMPT), MAX_PROMPT_CHARS)
        self.assertTrue(payload["candidates"])
        self.assertNotIn("technographic_verification", entities[3]["metadata"])

    def test_invalid_classifications_reject_the_entire_response(self):
        good = {"index": 0, "status": "asserted_use", "confidence": 0.9}
        invalid = [None, {}, [good, good], [{**good, "index": -1}], [{**good, "index": 1}], [{**good, "index": True}],
                   [{**good, "index": 0.0}], [{**good, "status": "deployed"}], [{**good, "status": ["mention"]}],
                   [{**good, "confidence": True}], [{**good, "confidence": float("nan")}], [{**good, "confidence": float("inf")}],
                   [{**good, "confidence": -0.1}], [{**good, "confidence": 1.1}], [{**good, "confidence": "0.9"}],
                   [{**good, "product_name": "invented"}], [{"index": 0, "status": "mention"}],
                   [good, {"index": 4, "status": "mention", "confidence": 0.2}]]
        for response in invalid:
            with self.subTest(response=response):
                entity = self.entity("We use Terraform.")
                with patch("signalwatch.technographic_verifier._chat", return_value=response):
                    verify_batch({"entities": [entity]}, self.config, self.store)
                self.assertNotIn("technographic_verification", entity["metadata"])

    def test_network_failure_keeps_deterministic_batch_unchanged(self):
        batch = {"entities": [self.entity("We use Terraform.")]}
        original = copy.deepcopy(batch)
        with patch("signalwatch.technographic_verifier._chat", side_effect=TimeoutError("request timed out")):
            self.assertIs(verify_batch(batch, self.config, self.store), batch)
        self.assertEqual(batch, original)

    def test_staging_worker_persists_checked_classification_and_deduplicates_before_second_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            config = load_config(Path(temporary) / "config.json")
            config.update(copy.deepcopy(self.config))
            store = Store(config["db"])
            store.ingest({"entities": [{"id": "company:acme", "kind": "company", "name": "Acme"}]})
            queue = staging_queue(store, config)
            for number in (1, 2):
                queue.enqueue(json.dumps({"entities": [self.entity("We use PAN-OS 11.2 in production.", number)]}).encode(),
                              source="greenhouse", adapter="normalized_batch", source_url="https://boards-api.greenhouse.io/v1/boards/acme/jobs")
            worker = StagingWorker(store, config, queue)
            with patch("signalwatch.technographic_verifier._chat", return_value=[{"index": 0, "status": "mention", "confidence": 0.3}]) as chat:
                self.assertEqual(worker.drain(limit=1, reconcile=False)["processed"], 1)
                self.assertEqual(worker.drain(limit=1, reconcile=False)["processed"], 1)
                chat.assert_called_once()
            with store.connection() as conn:
                fingerprints = [dict(row) for row in conn.execute("SELECT product_name,version,status,method FROM tech_fingerprints")]
                documents = conn.execute("SELECT count(*) FROM technographic_documents").fetchone()[0]
                sources = conn.execute("SELECT count(*) FROM technographic_sources").fetchone()[0]
            self.assertEqual(fingerprints, [{"product_name": "PAN-OS", "version": "11.2", "status": "mention", "method": METHOD}])
            self.assertEqual((documents, sources), (1, 2))

    def test_transport_uses_exact_endpoint_timeout_bounded_response_and_no_redirects(self):
        response = Mock()
        response.read.return_value = json.dumps({"choices": [{"message": {"content": "[]"}}]}).encode()
        opener = Mock()
        opener.open.return_value.__enter__ = Mock(return_value=response)
        opener.open.return_value.__exit__ = Mock(return_value=False)
        with patch("signalwatch.technographic_verifier.build_opener", return_value=opener) as build:
            self.assertEqual(_chat("https://models.example/exact/path", "key", "specific-model", "matched-content"), [])
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, "https://models.example/exact/path")
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 15})
        self.assertEqual(request.get_header("Authorization"), "Bearer key")
        self.assertEqual(json.loads(request.data)["model"], "specific-model")
        response.read.assert_called_once_with(65537)
        self.assertIsInstance(build.call_args.args[0], _NoRedirect)
        self.assertIsNone(_NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://elsewhere.example/"))

    def test_transport_rejects_oversized_or_non_json_responses(self):
        values = [b"x" * 65537, b"not json", b'{"choices":[]}',
                  b'{"choices":[{"message":{"content":"```json\\n[]\\n```"}}]}',
                  b'{"choices":[{"message":{"content":"[{\\"index\\":0,\\"status\\":\\"mention\\",\\"confidence\\":NaN}]"}}]}']
        for raw in values:
            with self.subTest(raw=raw[:80]):
                response = Mock()
                response.read.return_value = raw
                opener = Mock()
                opener.open.return_value.__enter__ = Mock(return_value=response)
                opener.open.return_value.__exit__ = Mock(return_value=False)
                with patch("signalwatch.technographic_verifier.build_opener", return_value=opener), self.assertRaises((ValueError, UnicodeDecodeError)):
                    _chat("https://models.example/exact/path", "key", "model", "content")
        with self.assertRaises(ValueError):
            _json('{"index":0,"index":1}')
