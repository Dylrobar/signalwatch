import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from signalwatch.cli import parser
from signalwatch.sbom import parse_sbom
from signalwatch.store import Store


ASSET = "https://app.example/production"


def cyclonedx(rows=(), version="1.7"):
    return {"bomFormat": "CycloneDX", "specVersion": version, "version": 1, "components": list(rows)}


def package(purl="pkg:npm/example-package@1.0.0", version="1.0.0"):
    return {"type": "library", "name": "Display name", "version": version, "purl": purl}


def spdx(rows=(), version="2.3"):
    return {"spdxVersion": "SPDX-" + version, "SPDXID": "SPDXRef-DOCUMENT", "name": "Inventory", "packages": list(rows)}


class SBOMParserTests(unittest.TestCase):
    def test_cyclonedx_supported_versions_and_nested_metadata_components(self):
        for version in ("1.4", "1.5", "1.6", "1.7"):
            with self.subTest(version=version):
                document = cyclonedx([package()], version)
                document["components"][0]["components"] = [package("pkg:pypi/requests@2.31.0", "2.31.0")]
                document["metadata"] = {"component": package("pkg:npm/subject-app@3.0.0", "3.0.0")}
                result = parse_sbom(document, asset_url=ASSET)
                self.assertEqual(result["report"]["format"], "CycloneDX")
                self.assertEqual(result["report"]["spec_version"], version)
                self.assertEqual(result["report"]["total"], 3)
                self.assertEqual(result["report"]["imported"], 3)
                self.assertEqual({row["package"] for row in result["batch"]["observations"]}, {"example-package", "requests", "subject-app"})

    def test_spdx_external_references_accept_purl_and_both_cpe_formats(self):
        for version in ("2.2", "2.3"):
            document = spdx([
                {"SPDXID": "SPDXRef-maven", "name": "Display", "versionInfo": "2.14.1", "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}]},
                {"SPDXID": "SPDXRef-router", "name": "Router", "versionInfo": "1.0", "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "cpe23Type", "referenceLocator": "cpe:2.3:h:vendor:router:1.0:*:*:*:*:*:*:*"}]},
                {"SPDXID": "SPDXRef-os", "name": "OS", "versionInfo": "22.04", "externalRefs": [{"referenceCategory": "SECURITY", "referenceType": "http://spdx.org/rdf/references/cpe22Type", "referenceLocator": "cpe:/o:canonical:ubuntu_linux:22.04"}]},
            ], version)
            result = parse_sbom(document, ASSET)
            self.assertEqual(result["report"]["spec_version"], version)
            observations = result["batch"]["observations"]
            self.assertEqual(observations[0]["package"], "org.apache.logging.log4j:log4j-core")
            self.assertEqual(observations[0]["ecosystem"], "Maven")
            self.assertEqual([row["part"] for row in observations], ["package", "h", "o"])

    def test_scoped_npm_and_encoded_versions_are_preserved(self):
        result = parse_sbom(cyclonedx([package("pkg:npm/%40scope/pkg@1.0.0", "1.0.0"), package("pkg:pypi/local-pkg@1.0%2Bbuild", "1.0+build")]), ASSET)
        observations = result["batch"]["observations"]
        self.assertEqual(observations[0]["package"], "@scope/pkg")
        self.assertEqual(observations[1]["version"], "1.0+build")

    def test_versions_must_agree_between_component_and_all_identifiers(self):
        mismatched = package("pkg:npm/example-package@1.0.0", "2.0.0")
        cross_identifier = package("pkg:npm/example-package@1.0.0", None)
        cross_identifier["cpe"] = "cpe:2.3:a:vendor:product:2.0.0:*:*:*:*:*:*:*"
        result = parse_sbom(cyclonedx([mismatched, cross_identifier]), ASSET)
        self.assertEqual(result["report"]["skipped"], 2)
        self.assertEqual(result["report"]["skip_reasons"], {"version_mismatch": 2})
        self.assertEqual(result["batch"]["observations"], [])

    def test_purl_and_cpe_can_supply_version_when_component_omits_it(self):
        result = parse_sbom(cyclonedx([package(version=None), {"type": "application", "name": "Provided CPE", "cpe": "cpe:2.3:a:vendor:product:4.5:*:*:*:*:*:*:*"}]), ASSET)
        self.assertEqual([row["version"] for row in result["batch"]["observations"]], ["1.0.0", "4.5"])

    def test_multiple_versions_survive_and_duplicate_components_are_counted(self):
        rows = [package(), package("pkg:npm/example-package@2.0.0", "2.0.0"), package()]
        result = parse_sbom(cyclonedx(rows), ASSET)
        self.assertEqual(result["report"]["total"], 3)
        self.assertEqual(result["report"]["imported"], 2)
        self.assertEqual(result["report"]["duplicates"], 1)
        self.assertEqual([row["version"] for row in result["batch"]["observations"]], ["1.0.0", "2.0.0"])

    def test_pypi_name_equivalence_does_not_merge_distinct_npm_names(self):
        rows = [package("pkg:pypi/Example_Package@1.0.0"), package("pkg:pypi/example.package@1.0.0"), package("pkg:npm/example-package@1.0.0"), package("pkg:npm/example_package@1.0.0")]
        result = parse_sbom(cyclonedx(rows), ASSET)
        self.assertEqual(result["report"]["duplicates"], 1)
        self.assertEqual(result["report"]["observations"], 3)

    def test_qualified_distro_repository_and_subpath_purls_are_not_guessed(self):
        rows = [package("pkg:deb/ubuntu/openssl@3.0?distro=ubuntu-22.04", "3.0"), package("pkg:maven/group/name@1.0.0?repository_url=https%3A%2F%2Fprivate.example"), package("pkg:npm/name@1.0.0#src")]
        result = parse_sbom(cyclonedx(rows), ASSET)
        self.assertEqual(result["report"]["skip_reasons"], {"qualified_purl_unsupported": 3})
        self.assertEqual(result["batch"]["observations"], [])
        self.assertTrue(all(isinstance(item, str) for item in result["report"]["warnings"]))

    def test_product_names_do_not_fabricate_identifiers(self):
        result = parse_sbom(cyclonedx([{"type": "application", "supplier": {"name": "nginx"}, "name": "nginx", "version": "1.20.0"}]), ASSET)
        self.assertEqual(result["report"]["skip_reasons"], {"no_supported_identifier": 1})
        self.assertEqual(result["batch"]["observations"], [])

    def test_unknown_versions_remain_unknown_and_excluded_ranges_skip(self):
        rows = [package("pkg:npm/example-package", None), {**package(), "scope": "excluded"}, {**package(), "isExternal": True, "versionRange": "vers:npm/>=1.0.0|<2.0.0"}]
        result = parse_sbom(cyclonedx(rows), ASSET)
        self.assertEqual(result["batch"]["observations"][0]["version"], "")
        self.assertEqual(result["report"]["skip_reasons"], {"excluded_component": 1, "external_version_range": 1})

    def test_unsupported_versions_and_malformed_shapes_fail_before_snapshot(self):
        documents = [cyclonedx(version="1.3"), cyclonedx(version="2.0"), spdx(version="3.0.1"), {"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld", "@graph": []}, {"bomFormat": "CycloneDX", "specVersion": "1.7", "components": {}}, cyclonedx([{**package(), "components": {}}]), spdx([{"externalRefs": [{"referenceType": []}]}])]
        for document in documents:
            with self.subTest(document=document):
                with self.assertRaises(ValueError):
                    parse_sbom(document, ASSET)

    def test_target_and_source_key_are_required_and_canonicalized(self):
        for target in ("", "file:///tmp/asset", "https://user:pass@example.com"):
            with self.assertRaises(ValueError):
                parse_sbom(cyclonedx(), target)
        with self.assertRaises(ValueError):
            parse_sbom(cyclonedx(), ASSET, "")
        result = parse_sbom(cyclonedx(), "EXAMPLE.COM#fragment")
        self.assertEqual(result["batch"]["entities"][0]["id"], "https://example.com/")
        self.assertEqual(result["batch"]["entities"][0]["kind"], "asset")
        self.assertEqual(len(result["batch"]["observation_snapshots"]), 1)


class SBOMStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.store = Store(self.folder / "signalwatch.db")

    def tearDown(self):
        self.temp.cleanup()

    def observations(self):
        with self.store.connection() as connection:
            return [dict(row) for row in connection.execute("SELECT origin,part,version FROM observations WHERE asset_id=? ORDER BY origin,version", (ASSET,))]

    def test_snapshot_refresh_preserves_other_sources_and_multiple_versions(self):
        initial = parse_sbom(cyclonedx([package(), package("pkg:npm/example-package@2.0.0", "2.0.0")]), ASSET)
        self.store.ingest(initial["batch"])
        self.store.ingest(parse_sbom(cyclonedx([package("pkg:npm/example-package@3.0.0", "3.0.0")]), ASSET, "other") ["batch"])
        self.store.ingest({"observations": [{"asset_id": ASSET, "origin": "imported", "ecosystem": "npm", "package": "example-package", "part": "package", "version": "4.0.0", "source_url": ASSET}]})
        self.assertEqual(len(self.observations()), 4)
        self.store.ingest(parse_sbom(cyclonedx([package("pkg:npm/example-package@5.0.0", "5.0.0")]), ASSET)["batch"])
        self.assertEqual({row["version"] for row in self.observations()}, {"3.0.0", "4.0.0", "5.0.0"})
        self.store.ingest(parse_sbom(cyclonedx(), ASSET)["batch"])
        self.assertEqual({row["version"] for row in self.observations()}, {"3.0.0", "4.0.0"})

    def test_cpe_part_and_unknown_pattern_version_survive_storage(self):
        rows = [{"type": "application", "name": "Software", "cpe": "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*"}, {"type": "device", "name": "Hardware", "cpe": "cpe:2.3:h:vendor:product:1.0:*:*:*:*:*:*:*"}, {"type": "application", "name": "Unknown build", "cpe": "cpe:2.3:a:vendor:unknown_build:1.*:*:*:*:*:*:*:*"}]
        self.store.ingest(parse_sbom(cyclonedx(rows), ASSET)["batch"])
        observations = self.observations()
        self.assertEqual(len(observations), 3)
        self.assertEqual(sum(row["version"] == "" for row in observations), 1)
        self.assertEqual({row["part"] for row in observations}, {"a", "h"})

    def test_replacing_vulnerable_snapshot_removes_stale_alert(self):
        self.store.ingest({"advisories": [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-12345"], "title": "Package issue", "source": "osv", "affected": [{"ecosystem": "npm", "package": "example-package", "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]}]})
        self.store.ingest(parse_sbom(cyclonedx([package(), package("pkg:npm/example-package@2.1.0", "2.1.0")]), ASSET)["batch"])
        self.store.reconcile()
        self.assertEqual(self.store.alerts()["total"], 1)
        self.store.ingest(parse_sbom(cyclonedx([package("pkg:npm/example-package@2.1.0", "2.1.0")]), ASSET)["batch"])
        self.store.reconcile()
        self.assertEqual(self.store.alerts()["total"], 0)

    def test_cli_import_and_size_limit(self):
        document_path = self.folder / "inventory.json"
        document_path.write_text(json.dumps(cyclonedx([package()])))
        config_path = self.folder / "config.json"
        config_path.write_text(json.dumps({"db": str(self.folder / "cli.db"), "cache_dir": str(self.folder / "cache"), "sbom_max_mb": 0.5}))
        command = [sys.executable, "-m", "signalwatch", "--config", str(config_path), "import-sbom", str(document_path), "--asset", ASSET, "--source", "pipeline"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["report"]["imported"], 1)
        document_path.write_text(document_path.read_text() + " " * (512 * 1024))
        rejected = subprocess.run(command, capture_output=True, text=True)
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("exceeds the configured size limit", rejected.stderr)

    def test_cli_event_export_options(self):
        args = parser().parse_args(["export", "--kind", "events", "--event-kind", "advisory_new", "--query", "CVE-2026"])
        self.assertEqual((args.kind, args.event_kind, args.query), ("events", "advisory_new", "CVE-2026"))
