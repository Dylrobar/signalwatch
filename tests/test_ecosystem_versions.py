import unittest

from signalwatch.matching import github_version_match, osv_version_match, semver


class EcosystemVersionTests(unittest.TestCase):
    def test_semver_specification_prerelease_order_and_build_equality(self):
        ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
                   "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"]
        self.assertEqual(sorted(ordered, key=semver), ordered)
        self.assertEqual(semver("1.0.0+build.2"), semver("1.0.0+build.999"))
        for value in ("1.0", "01.0.0", "1.0.0-01", "1.0.0-", "1.0.0+a..b", "1.0.0.1"):
            self.assertIsNone(semver(value), value)

    def test_osv_semver_prerelease_and_metadata_boundaries(self):
        affected = {"ecosystem": "npm", "ranges": [{"type": "SEMVER", "events": [
            {"introduced": "1.0.0-beta.2"}, {"fixed": "1.0.0"}]}]}
        for version in ("1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1+build.123"):
            self.assertEqual(osv_version_match(version, affected)[1], "affected_range")
        for version in ("1.0.0-beta.1", "1.0.0", "1.0.0+build.123"):
            self.assertFalse(osv_version_match(version, affected)[0])

    def test_osv_pypi_epoch_and_dev_post_versions(self):
        affected = {"ecosystem": "PyPI", "ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "1!2.0.dev2"}, {"last_affected": "1!2.0.post1"}]}]}
        for version in ("1!2.0rc1", "1!2.0", "1!2.0.post1"):
            self.assertEqual(osv_version_match(version, affected)[1], "affected_range")
        for version in ("2.0", "1!2.0.dev1", "1!2.0.post2"):
            self.assertFalse(osv_version_match(version, affected)[0])

    def test_unsupported_and_malformed_ranges_remain_uncertain(self):
        for interval in ({"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0-r1"}]},
                         {"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "1.0.0"}]},
                         {"type": "SEMVER", "events": [{"fixed": "1.0.0"}]},
                         {"type": "SEMVER", "events": [{"introduced": "0", "fixed": "1.0.0"}]}):
            self.assertEqual(osv_version_match("9.0.0", {"ecosystem": "Debian", "ranges": [interval]})[1], "version_unverified")

    def test_github_ranges_keep_ecosystem_semantics(self):
        self.assertTrue(github_version_match("1.0+local.1", {"ecosystem": "PyPI", "version_range": "== 1.0"})[0])
        self.assertFalse(github_version_match("1.0+local.1", {"ecosystem": "PyPI", "version_range": "> 1.0"})[0])
        self.assertEqual(github_version_match("1.2.0-rc.2", {"ecosystem": "npm", "version_range": ">= 1.2.0-rc.1, < 1.2.0"})[1], "affected_range")
        self.assertEqual(github_version_match("1.2.0-rc.2", {"ecosystem": "npm", "version_range": "< 2.0.0"})[1], "version_unverified")
        self.assertTrue(github_version_match("v1.2.0+build.1", {"ecosystem": "Go", "version_range": ">= v1.2.0, < v1.3.0"})[0])
        self.assertEqual(github_version_match("1.2.0", {"ecosystem": "npm", "version_range": "^1.0.0"})[1], "version_unverified")


if __name__ == "__main__":
    unittest.main()
