import base64
import hashlib
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.extension_developer import SOURCE_DEFINITIONS, collect_developer_sources, normalize_developer
from signalwatch.normalization import NormalizationError
from signalwatch.store import Store


def staged(value, provider="github_public", **metadata):
    payload = value if isinstance(value, bytes) else value.encode() if isinstance(value, str) else json.dumps(value).encode()
    return {"id": 81, "source": provider, "source_url": "https://public.example/artifact", "payload": payload, "payload_hash": hashlib.sha256(payload).hexdigest(), "observed_at": "2026-10-19T00:00:00Z", "metadata": {"provider": provider, **metadata}}


class DeveloperNormalizationTests(unittest.TestCase):
    def test_catalog_access_is_explicit_and_all_requested_artifact_families_exist(self):
        catalog = {record["id"]: record for record in SOURCE_DEFINITIONS}
        self.assertTrue({"github_public", "gitlab_public", "bitbucket_public", "wayback_cdx", "commoncrawl", "javascript_artifacts", "dockerhub", "quay", "postman_public", "swaggerhub_public", "appstore_public", "googleplay_public", "chrome_webstore_public", "slack_apps_public"} <= catalog.keys())
        self.assertEqual(catalog["dockerhub"]["access"], "api_key")
        self.assertEqual(catalog["googleplay_public"]["access"], "configured_url")

    def test_repositories_do_not_become_company_deployment(self):
        payload = [{"full_name": "example/portal", "html_url": "https://github.com/example/portal", "private": False, "language": "Go"}, {"full_name": "example/private", "private": True}]
        batch = normalize_developer(staged(payload, artifact_kind="repositories", company_id="company:example"))
        self.assertEqual(len(batch["entities"]), 1)
        self.assertEqual(batch["entities"][0]["kind"], "public_repository")
        self.assertFalse(batch["entities"][0]["metadata"]["deployment_confirmed"])
        self.assertNotIn("observations", batch)
        self.assertEqual(batch["edges"], [])

    def test_malformed_optional_repository_links_do_not_crash_normalization(self):
        batch = normalize_developer(staged([{"name": "public-repo", "links": {"html": "not an object"}}], artifact_kind="repositories"))
        self.assertEqual(batch["entities"][0]["name"], "public-repo")

    def test_npm_manifest_scopes_constraints_and_provenance(self):
        payload = {"dependencies": {"express": "^4.21.0"}, "devDependencies": {"vite": "^6"}}
        batch = normalize_developer(staged(payload, artifact_kind="manifest", manifest_path="package.json", repository="example/web"))
        records = [record for record in batch["entities"] if record["kind"] == "software_evidence"]
        self.assertEqual([record["name"] for record in records], ["express", "vite"])
        self.assertEqual(records[0]["metadata"]["fields"]["constraint"], "^4.21.0")
        self.assertEqual(records[1]["metadata"]["fields"]["scope"], "devDependencies")
        self.assertEqual(records[0]["metadata"]["staging"]["raw_reference"], "staging:81")
        self.assertTrue(all(edge["relation"] == "declares_dependency" for edge in batch["edges"]))
        self.assertNotIn("observations", batch)

    def test_github_base64_contents_response_is_decoded_only_as_manifest(self):
        payload = {"encoding": "base64", "content": base64.b64encode(b'{"dependencies":{"react":"19.0.0"}}').decode()}
        records = normalize_developer(staged(payload, manifest_path="package.json"))["entities"]
        self.assertEqual(records[1]["name"], "react")

    def test_requirements_are_declarations_and_directives_are_not_executed(self):
        payload = "-r secret.txt\n--index-url https://example.invalid\nrequests>=2.32\nDjango==5.1; python_version >= '3.10'\nhttps://example.invalid/download.whl\n"
        records = normalize_developer(staged(payload, manifest_path="requirements.txt"))["entities"]
        self.assertEqual([record["name"] for record in records[1:]], ["requests", "Django"])
        self.assertEqual(records[1]["metadata"]["fields"]["constraint"], ">=2.32")

    def test_additional_manifest_families_are_bounded(self):
        manifests = {
            "pom.xml": '<project xmlns="http://maven.apache.org/POM/4.0.0"><dependencies><dependency><groupId>org.example</groupId><artifactId>library</artifactId><version>${library.version}</version></dependency></dependencies></project>',
            "go.mod": "module example.org/project\nrequire (\n example.org/library v1.2.0 // indirect\n)\n",
            "Cargo.toml": '[dependencies]\nserde = {version="1", features=["derive"]}\n',
            "composer.json": '{"require":{"vendor/package":"^1"}}',
            "Dockerfile": "FROM --platform=linux/amd64 alpine:3.20 AS builder\nRUN echo ignored\nFROM scratch\n",
        }
        for path, payload in manifests.items():
            with self.subTest(path=path):
                batch = normalize_developer(staged(payload, manifest_path=path))
                self.assertTrue(any(record["kind"] == "software_evidence" for record in batch["entities"]))
                self.assertNotIn("observations", batch)

    def test_invalid_manifest_is_dead_letter_eligible(self):
        for payload, path in (("{invalid", "package.json"), ("broken", "Cargo.toml"), ("not XML", "pom.xml"), ("anything", "setup.py")):
            with self.subTest(path=path), self.assertRaises(NormalizationError):
                normalize_developer(staged(payload, manifest_path=path))

    def test_wayback_and_commoncrawl_urls_remain_historical(self):
        wayback = [["timestamp", "original", "statuscode", "mimetype", "digest"], ["20200101000000", "https://old.example/admin", "200", "text/html", "hash"]]
        commoncrawl = b'{"url":"https://old.example/api","timestamp":"20200101000000","status":"200"}\n'
        for provider, payload in (("wayback_cdx", wayback), ("commoncrawl", commoncrawl)):
            with self.subTest(provider=provider):
                batch = normalize_developer(staged(payload, provider, artifact_kind="archive_index"))
                entity = batch["entities"][0]
                self.assertEqual(entity["kind"], "archived_url")
                self.assertTrue(entity["metadata"]["fields"]["historical"])
                self.assertIsNone(entity["metadata"]["fields"]["currently_reachable"])
                self.assertEqual(batch["edges"], [])

    def test_archive_schema_errors_do_not_silently_become_inventory(self):
        for provider, payload in (("wayback_cdx", {"unexpected": []}), ("wayback_cdx", [["not_a_url"]]), ("commoncrawl", "bad json")):
            with self.subTest(provider=provider), self.assertRaises(NormalizationError):
                normalize_developer(staged(payload, provider, artifact_kind="archive_index"))

    def test_container_tag_metadata_preserves_architecture_without_inferring_host_os(self):
        payload = {"results": [{"name": "latest", "images": [{"os": "linux", "architecture": "arm64", "digest": "sha256:abcd"}]}]}
        entity = normalize_developer(staged(payload, "dockerhub", artifact_kind="container_tags", repository="example/web"))["entities"][0]
        self.assertEqual(entity["kind"], "container_tag")
        self.assertEqual(entity["metadata"]["fields"]["images"][0]["os"], "linux")
        self.assertFalse(entity["metadata"]["deployment_confirmed"])

    def test_sourcemap_only_reads_paths_and_ignores_sources_content(self):
        payload = {"version": 3, "file": "bundle.js", "sources": ["webpack://app/node_modules/@scope/library/index.js"], "sourcesContent": ["Never evaluated or inspected for secrets"]}
        batch = normalize_developer(staged(payload, "javascript_artifacts"))
        records = batch["entities"]
        self.assertEqual(records[-1]["name"], "@scope/library")
        self.assertEqual(records[-1]["metadata"]["fields"]["ecosystem"], "npm")
        self.assertNotIn("sourcesContent", json.dumps(batch))

    def test_script_urls_are_references_and_credential_parameters_are_not_indexed(self):
        payload = 'const API="https://api.example/v1"; const other="https://example.invalid/?api_key=sensitive";'
        batch = normalize_developer(staged(payload, "javascript_artifacts"))
        records = [record for record in batch["entities"] if record["kind"] == "source_reference"]
        self.assertEqual([record["value"] for record in records], ["https://api.example/v1"])
        self.assertFalse(records[0]["metadata"]["fields"]["exposure_verified"])

    def test_openapi_and_postman_only_index_declared_routes(self):
        openapi = {"openapi": "3.0.0", "info": {"title": "Public service"}, "paths": {"/devices": {"get": {}, "parameters": []}}}
        postman = {"info": {"name": "Public collection"}, "item": [{"name": "Folder", "item": [{"name": "Inventory", "request": {"method": "GET", "url": {"raw": "https://api.example/devices"}, "auth": {"token": "not indexed"}}}]}]}
        for provider, payload in (("swaggerhub_public", openapi), ("postman_public", postman)):
            with self.subTest(provider=provider):
                batch = normalize_developer(staged(payload, provider))
                self.assertEqual(len(batch["entities"]), 2)
                self.assertEqual(batch["entities"][1]["kind"], "api_route")
                self.assertFalse(batch["entities"][1]["metadata"]["fields"]["exposure_verified"])
                self.assertNotIn("auth", batch["entities"][1]["metadata"]["fields"])
                self.assertNotIn("observations", batch)

    def test_configured_public_listing_becomes_searchable_evidence(self):
        batch = normalize_developer(staged("<html><title>Public listing</title><p>Version 1.2</p></html>", "appstore_public"))
        self.assertEqual(batch["entities"][0]["name"], "Public listing")
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "test.db")
            store.ingest(batch)
            with store.connection() as conn:
                row = conn.execute("SELECT name FROM entities WHERE id=?", (batch["entities"][0]["id"],)).fetchone()
            self.assertEqual("Public listing", row["name"])

    def test_invalid_postman_shape_is_dead_letter_eligible(self):
        with self.assertRaises(NormalizationError):
            normalize_developer(staged({"info": {}, "item": 2}, "postman_public"))

    def test_total_record_limit_includes_dependency_edges(self):
        payload = {"dependencies": {str(index): "1" for index in range(100)}}
        batch = normalize_developer(staged(payload, manifest_path="package.json", record_limit=5), max_records=3)
        self.assertLessEqual(sum(len(records) for records in batch.values()), 3)

    def test_unknown_provider_is_rejected(self):
        with self.assertRaises(NormalizationError):
            normalize_developer(staged("anything", "not_real"))


class FakeHTTP:
    def __init__(self, directory, responses):
        self.directory = Path(directory)
        self.responses = responses
        self.requests = []

    async def get(self, url, **kwargs):
        self.requests.append((url, kwargs))
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        payload = response if isinstance(response, bytes) else json.dumps(response).encode()
        path = self.directory / (str(len(self.requests)) + ".response")
        path.write_bytes(payload)
        return types.SimpleNamespace(path=path, url=url, headers={"Content-Type": "application/json"})


class DeveloperCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.staged = []

        async def stage_payload(config, store, payload, **options):
            self.staged.append((payload, options))
            return {"id": len(self.staged), "duplicate": False}

        self.patch = patch.dict(sys.modules, {"signalwatch.sourcehub": types.SimpleNamespace(stage_payload=stage_payload)})
        self.patch.start()
        self.config = {"provider_settings": {record["id"]: {"enabled": False} for record in SOURCE_DEFINITIONS}, "public_source_batch": 2, "public_source_records": 3}

    async def asyncTearDown(self):
        self.patch.stop()
        self.directory.cleanup()

    async def test_github_fetches_public_org_and_bounded_known_manifests_preserving_bytes(self):
        self.config["provider_settings"]["github_public"] = {"enabled": True}
        self.config["source_targets"] = [{"name": "Example", "domain": "example.test", "github_org": "example"}]
        root = "https://api.github.com"
        payload = b'{ "dependencies": { "express": "^4.21" } }\n'
        http = FakeHTTP(self.directory.name, {
            root + "/orgs/example/repos": [{"full_name": "example/web", "private": False}, {"full_name": "other/external", "private": False}],
            root + "/repos/example/web/contents/": [{"type": "file", "name": "package.json", "path": "package.json", "size": len(payload)}, {"type": "file", "name": "setup.py", "path": "setup.py", "size": 50}],
            root + "/repos/example/web/contents/package.json": payload,
        })
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(result["staged"], 3)
        self.assertEqual(len(http.requests), 3)
        self.assertEqual(self.staged[-1][0], payload)
        self.assertEqual(self.staged[-1][1]["metadata"]["manifest_path"], "package.json")
        self.assertEqual(self.staged[-1][1]["provider"], "github_public")
        self.assertEqual(http.requests[-1][1]["headers"]["Accept"], "application/vnd.github.raw+json")
        self.assertEqual(result["provider_health"]["github_public"]["status"], "healthy")

    async def test_missing_targets_or_credentials_are_unconfigured(self):
        self.config["provider_settings"]["github_public"] = {"enabled": True}
        self.config["provider_settings"]["dockerhub"] = {"enabled": True, "repositories": ["example/web"]}
        http = FakeHTTP(self.directory.name, {})
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(http.requests, [])
        self.assertEqual(result["provider_health"]["github_public"]["status"], "unconfigured")
        self.assertEqual(result["provider_health"]["dockerhub"]["status"], "unconfigured")

    async def test_registry_credential_dict_is_fixed_host_header_only(self):
        self.config["provider_settings"]["dockerhub"] = {"enabled": True, "repositories": ["example/web"]}
        self.config["provider_credentials"] = {"dockerhub": {"token": "private-test-token"}}
        url = "https://hub.docker.com/v2/namespaces/example/repositories/web/tags"
        http = FakeHTTP(self.directory.name, {url: {"results": [{"name": "latest"}]}})
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(http.requests[0][1]["headers"]["Authorization"], "Bearer private-test-token")
        self.assertFalse(http.requests[0][1]["allow_redirects"])
        self.assertNotIn("private-test-token", json.dumps(result))
        self.assertNotIn("private-test-token", repr(self.staged))

    async def test_github_uses_existing_token_or_provider_override_on_fixed_host_only(self):
        self.config["provider_settings"]["github_public"] = {"enabled": True, "url": "https://public.example/export"}
        self.config["source_targets"] = [{"github_org": "example"}]
        self.config["github_token"] = "shared-github-token"
        responses = {"https://public.example/export": [], "https://api.github.com/orgs/example/repos": []}
        http = FakeHTTP(self.directory.name, responses)
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(http.requests[0][1]["headers"], {})
        self.assertEqual(http.requests[1][1]["headers"]["Authorization"], "Bearer shared-github-token")
        self.assertFalse(http.requests[1][1]["allow_redirects"])
        self.config["provider_credentials"] = {"github_public": {"token": "override-github-token"}}
        override = FakeHTTP(self.directory.name, responses)
        await collect_developer_sources(self.config, None, override)
        self.assertEqual(override.requests[1][1]["headers"]["Authorization"], "Bearer override-github-token")
        self.assertNotIn("shared-github-token", json.dumps(result))
        self.assertNotIn("override-github-token", repr(self.staged))

    async def test_target_rotation_survives_store_reopening(self):
        self.config["provider_settings"]["github_public"] = {"enabled": True}
        self.config["source_targets"] = [{"github_org": name} for name in ("first", "second", "third", "fourth")]
        path = Path(self.directory.name) / "rotation.db"
        http = FakeHTTP(self.directory.name, {"https://api.github.com/orgs/" + name + "/repos": [] for name in ("first", "second", "third", "fourth")})
        await collect_developer_sources(self.config, Store(path), http)
        await collect_developer_sources(self.config, Store(path), http)
        self.assertEqual([url for url, _ in http.requests], ["https://api.github.com/orgs/" + name + "/repos" for name in ("first", "second", "third", "fourth")])

    async def test_configured_url_rotation_does_not_starve_later_exports(self):
        urls = ["https://public.example/" + str(index) for index in range(4)]
        self.config["provider_settings"]["postman_public"] = {"urls": urls}
        http = FakeHTTP(self.directory.name, {url: {"info": {}, "item": []} for url in urls})
        store = Store(Path(self.directory.name) / "urls.db")
        await collect_developer_sources(self.config, store, http)
        await collect_developer_sources(self.config, store, http)
        self.assertEqual([url for url, _ in http.requests], urls)

    async def test_manifest_rotation_and_repository_pages_are_checkpointed(self):
        self.config["provider_settings"]["github_public"] = {"enabled": True}
        self.config["source_targets"] = [{"github_org": "example"}]
        root = "https://api.github.com"
        filenames = ["package.json", "requirements.txt", "pom.xml", "go.mod"]
        responses = {root + "/orgs/example/repos": [{"full_name": "example/web", "private": False}], root + "/repos/example/web/contents/": [{"type": "file", "name": name, "path": name, "size": 2} for name in filenames]}
        responses.update({root + "/repos/example/web/contents/" + name: b"{}" for name in filenames})
        http = FakeHTTP(self.directory.name, responses)
        store = Store(Path(self.directory.name) / "manifests.db")
        await collect_developer_sources(self.config, store, http)
        await collect_developer_sources(self.config, store, http)
        manifests = [url.rsplit("/", 1)[-1] for url, _ in http.requests if url.rsplit("/", 1)[-1] in filenames]
        self.assertEqual(manifests, filenames)
        self.config["public_source_batch"] = 1
        pages = FakeHTTP(self.directory.name, responses)
        await collect_developer_sources(self.config, store, pages)
        await collect_developer_sources(self.config, store, pages)
        self.assertEqual([options["params"]["page"] for url, options in pages.requests if url.endswith("/repos")], [1, 2])

    async def test_commoncrawl_discovers_current_index_then_fetches_bounded_urls(self):
        self.config["provider_settings"]["commoncrawl"] = {"enabled": True}
        self.config["source_targets"] = [{"domain": "example.test"}]
        url = "https://index.commoncrawl.org/CC-MAIN-2026-40-index"
        http = FakeHTTP(self.directory.name, {"https://index.commoncrawl.org/collinfo.json": [{"cdx-api": url}], url: b'{"url":"https://example.test/old"}\n'})
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(result["staged"], 2)
        self.assertEqual(http.requests[1][1]["params"]["limit"], 3)
        self.assertEqual(self.staged[-1][1]["metadata"]["artifact_kind"], "archive_index")

    async def test_configured_urls_are_bounded_and_never_receive_provider_credentials(self):
        self.config["provider_settings"]["postman_public"] = {"urls": ["https://public.example/one", "https://public.example/two", "https://public.example/three"]}
        self.config["provider_credentials"] = {"postman_public": "not-to-be-forwarded"}
        http = FakeHTTP(self.directory.name, {"https://public.example/one": {"info": {}, "item": []}, "https://public.example/two": b"public"})
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(result["staged"], 2)
        self.assertEqual(len(http.requests), 2)
        self.assertTrue(all(not request[1]["headers"] for request in http.requests))

    async def test_all_failed_errors_without_echoing_url_queries_or_error_text(self):
        self.config["provider_settings"]["postman_public"] = {"url": "https://public.example/export?item=public"}
        http = FakeHTTP(self.directory.name, {"https://public.example/export?item=public": RuntimeError("secret-error-content")})
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(result["provider_health"]["postman_public"]["status"], "error")
        self.assertNotIn("secret-error-content", json.dumps(result))
        self.assertNotIn("item=public", json.dumps(result))

    async def test_configured_url_with_credential_query_is_rejected_before_request(self):
        self.config["provider_settings"]["postman_public"] = {"url": "https://public.example/export?api_key=private"}
        http = FakeHTTP(self.directory.name, {})
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(http.requests, [])
        self.assertEqual(result["provider_health"]["postman_public"]["status"], "error")
        self.assertNotIn("private", json.dumps(result))
