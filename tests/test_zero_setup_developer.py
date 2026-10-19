import base64
import hashlib
import json
import tempfile
import types
import unittest
from pathlib import Path

from signalwatch.extension_developer import collect_developer_sources, normalize_developer
from signalwatch.normalization import NormalizationError
from signalwatch.store import Store
from tests import test_extension_developer as support

FakeHTTP = support.FakeHTTP
staged = support.staged


class ZeroSetupDeveloperNormalizationTests(unittest.TestCase):
    def dependencies(self, payload, path):
        return [record for record in normalize_developer(staged(payload, manifest_path=path))["entities"] if record["kind"] == "software_evidence"]

    def test_pyproject_preserves_markers_extras_and_exact_versions(self):
        payload = '[project]\ndependencies = ["Requests[security]==2.32.3; python_version >= \'3.11\'", "fastapi>=0.115"]\n[project.optional-dependencies]\ntest = ["pytest~=8.0"]\n[build-system]\nrequires = ["setuptools>=68"]\n'
        records = self.dependencies(payload, "pyproject.toml")
        values = {record["name"]: record["metadata"]["fields"] for record in records}
        self.assertEqual(values["Requests"]["version"], "2.32.3")
        self.assertEqual(values["Requests"]["marker"], 'python_version >= "3.11"')
        self.assertNotIn("version", values["fastapi"])
        self.assertEqual(values["pytest"]["scope"], "optional:test")
        self.assertEqual(values["setuptools"]["scope"], "build-system")

    def test_npm_lock_preserves_multiple_versions_and_skips_links(self):
        payload = {"lockfileVersion": 3, "packages": {"": {"name": "application", "version": "1.0.0"}, "node_modules/express": {"version": "4.21.0"}, "node_modules/other/node_modules/express": {"version": "5.1.0"}, "node_modules/local": {"link": True, "resolved": "packages/local"}, "node_modules/@scope/dependency": {"version": "2.4.0", "dev": True}}}
        records = self.dependencies(payload, "package-lock.json")
        express = [record for record in records if record["name"] == "express"]
        self.assertEqual(len(express), 2)
        self.assertNotEqual(express[0]["id"], express[1]["id"])
        self.assertEqual({record["metadata"]["fields"]["version"] for record in express}, {"4.21.0", "5.1.0"})
        self.assertEqual(records[-1]["name"], "@scope/dependency")
        self.assertNotIn("local", [record["name"] for record in records])

    def test_npm_v1_nested_lock_and_range_versions(self):
        records = self.dependencies({"dependencies": {"a": {"version": "1.2.3", "dependencies": {"b": {"version": "2.0.0"}}}}}, "npm-shrinkwrap.json")
        self.assertEqual([record["name"] for record in records], ["a", "b"])
        records = self.dependencies({"dependencies": {"a": "1.2", "b": "^1.2.3", "c": "1.2.3"}}, "package.json")
        self.assertNotIn("version", records[0]["metadata"]["fields"])
        self.assertNotIn("version", records[1]["metadata"]["fields"])
        self.assertEqual(records[2]["metadata"]["fields"]["version"], "1.2.3")

    def test_cargo_rename_workspace_and_lock_registry_identity(self):
        payload = '[dependencies]\nalias = { package="serde", version="1.0" }\nlocal = { path="local" }\nshared = { workspace=true }\n[workspace.dependencies]\ntokio = "1"\n[target.\'cfg(unix)\'.dependencies]\nlibc="0.2"\n'
        self.assertEqual([record["name"] for record in self.dependencies(payload, "Cargo.toml")], ["serde", "tokio", "libc"])
        lock = '[[package]]\nname="serde"\nversion="1.0.200"\nsource="registry+https://github.com/rust-lang/crates.io-index"\n[[package]]\nname="private"\nversion="1.0.0"\nsource="git+https://git.example/project"\n'
        records = self.dependencies(lock, "Cargo.lock")
        self.assertEqual([record["name"] for record in records], ["serde"])
        self.assertEqual(records[0]["metadata"]["fields"]["version"], "1.0.200")

    def test_python_locks_ignore_local_and_git_packages(self):
        uv = '[[package]]\nname="requests"\nversion="2.32.3"\nsource={registry="https://pypi.org/simple"}\n[[package]]\nname="application"\nversion="1.0.0"\nsource={editable="."}\n'
        poetry = '[[package]]\nname="requests"\nversion="2.32.3"\n[[package]]\nname="git-library"\nversion="1.0.0"\nsource={type="git",url="https://example.org/git"}\n'
        for path, payload in (("uv.lock", uv), ("poetry.lock", poetry)):
            records = self.dependencies(payload, path)
            self.assertEqual([record["name"] for record in records], ["requests"])
            self.assertEqual(records[0]["metadata"]["fields"]["version"], "2.32.3")

    def test_nuget_and_composer_distinguish_platform_and_project_dependencies(self):
        nuget = {"dependencies": {"net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.0, )", "resolved": "13.0.3"}, "Local.Project": {"type": "Project", "resolved": "1.0.0"}}}}
        records = self.dependencies(nuget, "packages.lock.json")
        self.assertEqual([record["name"] for record in records], ["Newtonsoft.Json"])
        self.assertEqual(records[0]["metadata"]["fields"]["ecosystem"], "NuGet")
        self.assertEqual(records[0]["metadata"]["fields"]["version"], "13.0.3")
        records = self.dependencies({"require": {"php": "^8.2", "ext-json": "*", "vendor/library": "^2"}}, "composer.json")
        self.assertEqual([record["name"] for record in records], ["vendor/library"])
        records = self.dependencies({"packages": [{"name": "vendor/library", "version": "v2.1.0"}]}, "composer.lock")
        self.assertEqual(records[0]["metadata"]["fields"]["version"], "v2.1.0")

    def test_candidate_token_findings_are_redacted_stable_and_not_inventory(self):
        token = "ghp_" + "aB12cD34eF56gH78iJ90kL12mN34oP56qR78"
        payload = f'TOKEN="{token}"\nTOKEN_AGAIN="{token}"\n'
        item = staged(payload, artifact_kind="repository_config", artifact_path=".env.example", repository="example/project", company_id="company:example")
        batch = normalize_developer(item)
        findings = [record for record in batch["entities"] if record["kind"] == "secret_finding"]
        self.assertEqual(len(findings), 1)
        fields = findings[0]["metadata"]["fields"]
        self.assertEqual(fields["fingerprint_sha256"], hashlib.sha256(token.encode()).hexdigest())
        self.assertEqual(fields["validation"], "not_performed")
        self.assertEqual(fields["coverage"], "fetched_artifact_only")
        self.assertFalse(findings[0]["metadata"]["ownership_verified"])
        self.assertFalse(findings[0]["metadata"]["deployment_verified"])
        self.assertNotIn(token, json.dumps(batch))
        self.assertIn("[REDACTED]", json.dumps(batch))
        self.assertEqual(batch, normalize_developer(item))
        self.assertNotIn("observations", batch)
        self.assertNotIn("advisories", batch)
        self.assertEqual(batch["edges"][0]["relation"], "contains_potential_secret")

    def test_placeholder_and_low_variety_tokens_do_not_create_findings(self):
        for token in ("ghp_" + "A" * 36, "ghp_EXAMPLE1234567890EXAMPLE12345678901234", "ordinary-password-or-api-name"):
            batch = normalize_developer(staged(token, artifact_kind="repository_config"))
            self.assertFalse(any(record["kind"] == "secret_finding" for record in batch["entities"]))

    def test_base64_manifest_redacts_constraint_and_keeps_raw_provenance(self):
        token = "ghp_" + "aB12cD34eF56gH78iJ90kL12mN34oP56qR78"
        raw = json.dumps({"dependencies": {"library": "git+https://" + token + "@github.com/example/lib"}}).encode()
        item = staged({"encoding": "base64", "content": base64.b64encode(raw).decode()}, manifest_path="package.json")
        batch = normalize_developer(item)
        self.assertNotIn(token, json.dumps(batch))
        self.assertTrue(any(record["kind"] == "secret_finding" for record in batch["entities"]))
        self.assertEqual(batch["entities"][0]["metadata"]["staging"]["payload_hash"], item["payload_hash"])

    def test_private_key_pattern_does_not_retain_key_material(self):
        body = base64.b64encode(bytes(range(96))).decode()
        payload = "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----"
        batch = normalize_developer(staged(payload, artifact_kind="repository_config"))
        self.assertNotIn(body, json.dumps(batch))
        self.assertEqual(batch["entities"][-1]["metadata"]["fields"]["rule"], "private_key")

    def test_bounded_findings_and_record_budget_preserve_secret_priority(self):
        tokens = ["ghp_" + hashlib.sha256(str(index).encode()).hexdigest()[:36] for index in range(60)]
        batch = normalize_developer(staged("\n".join(tokens), artifact_kind="repository_config"))
        self.assertEqual(len([record for record in batch["entities"] if record["kind"] == "secret_finding"]), 50)
        payload = {"dependencies": {f"library{index}": "1.0.0" for index in range(20)}, "token": tokens[0]}
        batch = normalize_developer(staged(payload, manifest_path="package.json", record_limit=5))
        self.assertLessEqual(len(batch["entities"]) + len(batch["edges"]), 5)
        self.assertTrue(any(record["kind"] == "secret_finding" for record in batch["entities"]))

    def test_sourcemap_embedded_source_content_is_not_scanned_or_persisted(self):
        token = "ghp_" + "aB12cD34eF56gH78iJ90kL12mN34oP56qR78"
        batch = normalize_developer(staged({"version": 3, "sources": ["index.js"], "sourcesContent": [token]}, "javascript_artifacts"))
        self.assertFalse(any(record["kind"] == "secret_finding" for record in batch["entities"]))
        self.assertNotIn("secret_scan", batch["entities"][0]["metadata"])
        self.assertNotIn(token, json.dumps(batch))

    def test_app_json_ld_extracts_publisher_metadata_without_sdk_claims(self):
        payload = '<html><script type="application/ld+json">{"@graph":[{"@type":"MobileApplication","name":"Enterprise Mobile","softwareVersion":"4.2.0","operatingSystem":"Android","publisher":{"name":"Published Vendor"}}]}</script></html>'
        record = normalize_developer(staged(payload, "googleplay_public", company_id="company:example"))["entities"][0]
        self.assertEqual(record["name"], "Enterprise Mobile")
        self.assertEqual(record["metadata"]["fields"]["softwareVersion"], "4.2.0")
        self.assertFalse(record["metadata"]["fields"]["binary_inspected"])
        self.assertFalse(record["metadata"]["fields"]["sdks_verified"])
        self.assertFalse(record["metadata"]["ownership_verified"])

    def test_malformed_new_manifest_fails_instead_of_fake_success(self):
        for path, payload in (("pyproject.toml", '[project]\ndependencies=["@ invalid"]'), ("package-lock.json", "{"), ("uv.lock", "not toml")):
            with self.subTest(path=path), self.assertRaises(NormalizationError):
                normalize_developer(staged(payload, manifest_path=path))

    def test_repeat_ingest_deduplicates_findings(self):
        token = "ghp_" + "aB12cD34eF56gH78iJ90kL12mN34oP56qR78"
        batch = normalize_developer(staged(token, artifact_kind="repository_config"))
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "test.db")
            store.ingest(batch)
            store.ingest(batch)
            with store.connection() as connection:
                self.assertEqual(connection.execute("SELECT count(*) FROM entities WHERE kind='secret_finding'").fetchone()[0], 1)
                self.assertEqual(connection.execute("SELECT count(*) FROM observations").fetchone()[0], 0)
                self.assertEqual(connection.execute("SELECT count(*) FROM alerts").fetchone()[0], 0)


class ZeroSetupDeveloperCollectorTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = support.DeveloperCollectorTests.asyncSetUp
    asyncTearDown = support.DeveloperCollectorTests.asyncTearDown
    async def test_known_root_configuration_files_are_bounded_and_marked_as_partial_coverage(self):
        self.config["provider_settings"]["github_public"] = {"enabled": True}
        self.config["source_targets"] = [{"github_org": "example", "company_id": "company:example"}]
        files = [".env.example", "pyproject.toml", "package-lock.json", "arbitrary.py", "huge.lock"]
        root = "https://api.github.com"
        responses = {root + "/orgs/example/repos": [{"full_name": "example/web", "private": False}], root + "/repos/example/web/contents/": [{"name": name, "path": name, "type": "file", "size": 10, "sha": "known-blob-sha"} for name in files]}
        responses.update({root + "/repos/example/web/contents/" + name: b"public artifact" for name in files})
        http = FakeHTTP(self.directory.name, responses)
        result = await collect_developer_sources(self.config, None, http)
        fetched = [url.rsplit("/", 1)[-1] for url, _ in http.requests[2:]]
        self.assertEqual(fetched, [".env.example", "pyproject.toml"])
        health = result["provider_health"]["github_public"]
        self.assertEqual(health["artifact_coverage"]["files_fetched"], 2)
        self.assertFalse(health["artifact_coverage"]["whole_organization_scanned"])
        self.assertFalse(health["artifact_coverage"]["credential_validation"])
        configuration = self.staged[2][1]["metadata"]
        self.assertEqual(configuration["artifact_kind"], "repository_config")
        self.assertEqual(configuration["artifact_path"], ".env.example")
        self.assertEqual(configuration["github_blob_sha"], hashlib.sha1(b"blob 15\0public artifact").hexdigest())
        self.assertNotIn("manifest_path", configuration)
        self.assertTrue(all("Authorization" not in options["headers"] for _, options in http.requests))

    async def test_other_owner_private_and_oversized_files_are_not_fetched(self):
        self.config["provider_settings"]["github_public"] = {"enabled": True}
        self.config["source_targets"] = [{"github_org": "example"}]
        root = "https://api.github.com"
        responses = {root + "/orgs/example/repos": [{"full_name": "other/wrong", "private": False}, {"full_name": "example/private", "private": True}, {"full_name": "example/public", "private": False}], root + "/repos/example/public/contents/": [{"name": "package-lock.json", "path": "package-lock.json", "type": "file", "size": 3 * 1024 * 1024}, {"name": "pyproject.toml", "path": "../pyproject.toml", "type": "file", "size": 20}]}
        self.config["public_source_batch"] = 3
        http = FakeHTTP(self.directory.name, responses)
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(len(http.requests), 2)
        self.assertEqual(result["provider_health"]["github_public"]["artifact_coverage"]["files_fetched"], 0)

    async def test_failed_manifest_does_not_report_scanned_file(self):
        self.config["provider_settings"]["github_public"] = {"enabled": True}
        self.config["source_targets"] = [{"github_org": "example"}]
        root = "https://api.github.com"
        http = FakeHTTP(self.directory.name, {root + "/orgs/example/repos": [{"full_name": "example/public", "private": False}], root + "/repos/example/public/contents/": [{"name": "pyproject.toml", "path": "pyproject.toml", "type": "file", "size": 20}], root + "/repos/example/public/contents/pyproject.toml": RuntimeError("private failure detail")})
        result = await collect_developer_sources(self.config, None, http)
        health = result["provider_health"]["github_public"]
        self.assertEqual(health["status"], "partial")
        self.assertEqual(health["artifact_coverage"]["files_fetched"], 0)
        self.assertNotIn("private failure detail", json.dumps(result))


class LookupHTTP(FakeHTTP):
    def __init__(self, directory, responses, lookup):
        super().__init__(directory, responses)
        self.lookup = lookup
        self.posts = []

    async def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        if isinstance(self.lookup, Exception):
            raise self.lookup
        payload = self.lookup(kwargs["json"]) if callable(self.lookup) else self.lookup
        path = self.directory / ("lookup" + str(len(self.posts)) + ".json")
        path.write_text(json.dumps(payload))
        return types.SimpleNamespace(path=path, url=url, headers={"Content-Type": "application/json"})


class ZeroSetupDependencyLookupTests(unittest.IsolatedAsyncioTestCase):
    asyncSetUp = support.DeveloperCollectorTests.asyncSetUp
    asyncTearDown = support.DeveloperCollectorTests.asyncTearDown

    def http(self, manifest, lookup, path="package.json"):
        self.config["provider_settings"]["github_public"] = {"enabled": True}
        self.config["source_targets"] = [{"github_org": "example", "domain": "example.test"}]
        self.config["public_source_batch"] = 1
        self.config["public_source_records"] = 100
        root = "https://api.github.com"
        payload = json.dumps(manifest).encode() if isinstance(manifest, dict) else manifest.encode()
        responses = {root + "/orgs/example/repos": [{"full_name": "example/web", "private": False}], root + "/repos/example/web/contents/": [{"name": path, "path": path, "type": "file", "size": len(payload)}], root + "/repos/example/web/contents/" + path: payload}
        return LookupHTTP(self.directory.name, responses, lookup)

    async def test_one_batch_queries_twenty_unique_exact_versions_and_rotates(self):
        manifest = {"dependencies": {**{f"library{index}": "1.2.3" for index in range(30)}, "range": "^1.2.3", "partial": "1.2", "unknown": "*"}}
        http = self.http(manifest, lambda body: {"results": [{} for _ in body["queries"]]})
        store = Store(Path(self.directory.name) / "lookup.db")
        first = await collect_developer_sources(self.config, store, http)
        second = await collect_developer_sources(self.config, store, http)
        self.assertEqual(len(http.posts), 2)
        self.assertTrue(all(len(options["json"]["queries"]) == 20 for _, options in http.posts))
        names = {query["package"]["name"] for _, options in http.posts for query in options["json"]["queries"]}
        self.assertEqual(names, {f"library{index}" for index in range(30)})
        self.assertEqual(first["provider_health"]["github_public"]["dependency_lookup"]["status"], "completed")
        self.assertEqual(second["provider_health"]["github_public"]["dependency_lookup"]["requests"], 1)
        self.assertTrue(all(url == "https://api.osv.dev/v1/querybatch" and not options.get("headers") and not options["allow_redirects"] for url, options in http.posts))

    async def test_unchanged_query_and_provenance_are_cached_across_store_reopening(self):
        http = self.http({"dependencies": {"express": "4.21.0"}}, {"results": [{}]})
        path = Path(self.directory.name) / "cached.db"
        await collect_developer_sources(self.config, Store(path), http)
        result = await collect_developer_sources(self.config, Store(path), http)
        self.assertEqual(len(http.posts), 1)
        self.assertEqual(result["provider_health"]["github_public"]["dependency_lookup"]["status"], "cached")
        lookups = [options for _, options in self.staged if options["metadata"]["artifact_kind"] == "dependency_vulnerability_lookup"]
        self.assertEqual(len(lookups), 1)

    async def test_pypi_exact_pins_only_and_name_deduplication(self):
        http = self.http("Requests==2.32.3\nrequests==2.32.3\nDjango>=5.0\nflask~=3.0\n", {"results": [{}]}, "requirements.txt")
        result = await collect_developer_sources(self.config, None, http)
        queries = http.posts[0][1]["json"]["queries"]
        self.assertEqual(len(queries), 1)
        self.assertEqual(queries[0]["package"]["ecosystem"], "PyPI")
        self.assertEqual(queries[0]["version"], "2.32.3")
        self.assertEqual(result["provider_health"]["github_public"]["status"], "healthy")

    async def test_lookup_failure_is_partial_and_not_cached_or_staged_as_success(self):
        http = self.http({"dependencies": {"express": "4.21.0"}}, RuntimeError("private lookup failure detail"))
        store = Store(Path(self.directory.name) / "failed.db")
        result = await collect_developer_sources(self.config, store, http)
        self.assertEqual(result["provider_health"]["github_public"]["status"], "partial")
        self.assertEqual(result["provider_health"]["github_public"]["dependency_lookup"]["status"], "error")
        self.assertFalse(store.source_state("developer_sources").get("osv_lookup_cache"))
        self.assertFalse(any(options["metadata"]["artifact_kind"] == "dependency_vulnerability_lookup" for _, options in self.staged))
        self.assertNotIn("private lookup failure detail", json.dumps(result))

    async def test_misaligned_results_are_rejected_and_ranges_trigger_no_lookup(self):
        http = self.http({"dependencies": {"express": "4.21.0"}}, {"results": []})
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(result["provider_health"]["github_public"]["status"], "partial")
        http = self.http({"dependencies": {"express": "^4.21.0"}}, {"results": []})
        await collect_developer_sources(self.config, None, http)
        self.assertEqual(http.posts, [])

    async def test_reference_graph_uses_original_dependency_identity_without_overwriting_advisory(self):
        response = {"results": [{"vulns": [{"id": "GHSA-9hjg-9r4m-mvj7", "modified": "2026-10-18T12:00:00Z"}], "next_page_token": "more"}]}
        http = self.http({"dependencies": {"express": "4.21.0"}}, response)
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(result["provider_health"]["github_public"]["dependency_lookup"]["status"], "partial")
        original_payload, original_options = next((payload, options) for payload, options in self.staged if options["metadata"]["artifact_kind"] == "manifest")
        lookup_payload, lookup_options = self.staged[-1]
        original = staged(original_payload, **original_options["metadata"])
        original["source_url"] = original_options["source_url"]
        lookup = staged(lookup_payload, **lookup_options["metadata"])
        lookup["source_url"] = lookup_options["source_url"]
        manifest_batch = normalize_developer(original)
        batch = normalize_developer(lookup)
        dependency_id = next(record["id"] for record in manifest_batch["entities"] if record["kind"] == "software_evidence")
        self.assertEqual(batch["edges"][0]["from_id"], dependency_id)
        self.assertEqual(batch["edges"][0]["relation"], "osv_reports_for_declared_version")
        self.assertEqual(batch["entities"][0]["metadata"]["fields"]["status"], "partial_page")
        self.assertNotIn("advisories", batch)
        self.assertNotIn("observations", batch)
        store = Store(Path(self.directory.name) / "references.db")
        advisory_id = "OSV:GHSA-9hjg-9r4m-mvj7"
        store.ingest({"entities": [{"id": advisory_id, "kind": "vulnerability", "name": "Full trusted advisory", "metadata": {"full_record": True}}]})
        store.ingest(manifest_batch)
        store.ingest(batch)
        store.ingest(batch)
        with store.connection() as connection:
            advisory = connection.execute("SELECT name,metadata FROM entities WHERE id=?", (advisory_id,)).fetchone()
            self.assertEqual(advisory["name"], "Full trusted advisory")
            self.assertEqual(json.loads(advisory["metadata"]), {"full_record": True})
            self.assertEqual(connection.execute("SELECT count(*) FROM edges WHERE relation='osv_reports_for_declared_version'").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT count(*) FROM observations").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM advisories").fetchone()[0], 0)

    async def test_normalizer_rejects_response_query_mismatch(self):
        with self.assertRaises(NormalizationError):
            normalize_developer(staged({"results": []}, artifact_kind="dependency_vulnerability_lookup", queries=[{"query": {}, "occurrences": []}]))

    async def test_nonpublic_sources_and_module_replacements_are_not_public_osv_queries(self):
        manifests = [
            ("go.mod", "module example.org/app\nrequire golang.org/x/crypto v0.17.0\nreplace golang.org/x/crypto => example.org/fork/crypto v0.30.0\n"),
            ("go.mod", "module example.org/app\nrequire golang.org/x/crypto v0.17.0\nreplace (\n golang.org/x/crypto => ./fork\n)\n"),
            ("package-lock.json", json.dumps({"packages": {"node_modules/example": {"version": "1.2.3", "resolved": "git+https://github.com/company/private-fork.git#abcdef"}}})),
            ("uv.lock", '[[package]]\nname="private"\nversion="1.2.3"\nsource={registry="https://packages.example.org/simple"}\n'),
            ("requirements.txt", "--index-url https://packages.example.org/simple\nrequests==2.32.3\n"),
            ("pyproject.toml", '[tool.poetry.dependencies]\nprivate={version="1.2.3",source="private"}\n'),
        ]
        for path, payload in manifests:
            with self.subTest(path=path, payload=payload):
                http = self.http(payload, {"results": []}, path)
                result = await collect_developer_sources(self.config, None, http)
                self.assertEqual(http.posts, [])
                self.assertEqual(result["provider_health"]["github_public"]["status"], "healthy")

    async def test_error_envelopes_and_malformed_ids_are_not_cached_or_staged(self):
        for response in ({"results": [{"error": "upstream failure"}]}, {"results": [{"vulns": [{}]}]}, {"error": "failure", "results": [{}]}, {"results": [{"next_page_token": 17}]}):
            with self.subTest(response=response):
                http = self.http({"dependencies": {"express": "4.21.0"}}, response)
                before = len(self.staged)
                result = await collect_developer_sources(self.config, None, http)
                self.assertEqual(result["provider_health"]["github_public"]["status"], "partial")
                self.assertFalse(any(options["metadata"]["artifact_kind"] == "dependency_vulnerability_lookup" for _, options in self.staged[before:]))

    async def test_blob_changed_after_listing_is_not_staged_or_queried(self):
        http = self.http({"dependencies": {"express": "4.21.0"}}, {"results": [{}]})
        http.responses["https://api.github.com/repos/example/web/contents/"][0]["sha"] = "a" * 40
        result = await collect_developer_sources(self.config, None, http)
        self.assertEqual(result["provider_health"]["github_public"]["status"], "partial")
        self.assertEqual(result["provider_health"]["github_public"]["artifact_coverage"]["files_fetched"], 0)
        self.assertFalse(any(options["metadata"]["artifact_kind"] == "manifest" for _, options in self.staged))
        self.assertEqual(http.posts, [])
