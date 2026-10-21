"""Affected/unaffected boundary tests for native CVE JSON 5 rules."""
import unittest

from signalwatch.matching import github_version_match, version_match


def affected(*rules, default="unaffected"):
    return {"version_unverified": True, "cve_versions": list(rules), "cve_default_status": default}


def interval(**changes):
    return {"version": "1.0.0", "lessThan": "2.0.0", "versionType": "semver", "status": "affected", **changes}


class CVEVersionTests(unittest.TestCase):
    def test_exclusive_and_inclusive_boundaries(self):
        for rule, observations in [
            (interval(), {"0.9.9": False, "1.0.0": True, "1.9.9": True, "2.0.0": False}),
            ({"version": "1.0.0", "lessThanOrEqual": "2.0.0", "versionType": "semver", "status": "affected"},
             {"1.0.0": True, "2.0.0": True, "2.0.1": False}),
        ]:
            for version, expected in observations.items():
                with self.subTest(rule=rule, version=version):
                    result = version_match(version, affected(rule))
                    self.assertEqual(result[0], expected)
                    self.assertEqual(result[1], "affected_range" if expected else "unaffected")

    def test_status_changes_patch_and_reintroduce_vulnerability(self):
        data = affected(interval(changes=[{"at": "1.8.0", "status": "affected"},
                                         {"at": "1.5.0", "status": "unaffected"}]))
        for version, expected in {"1.4.9": True, "1.5.0": False, "1.7.0": False, "1.8.0": True, "2.0.0": False}.items():
            with self.subTest(version=version):
                self.assertEqual(version_match(version, data)[0], expected)

    def test_default_affected_with_unaffected_exception(self):
        data = affected(interval(status="unaffected"), default="affected")
        self.assertFalse(version_match("1.5.0", data)[0])
        self.assertEqual(version_match("2.0.0", data)[1], "affected_range")

    def test_exact_opaque_version_and_semver_build_metadata(self):
        self.assertEqual(version_match("release-A", affected({"version": "release-A", "status": "affected"}))[1], "exact")
        self.assertFalse(version_match("release-A", affected({"version": "release-A", "status": "unaffected"}, default="affected"))[0])
        self.assertEqual(version_match("1.2.3+build.2", affected({"version": "1.2.3+build.1", "versionType": "semver", "status": "affected"}))[1], "exact")

    def test_prerelease_order_and_python_epochs(self):
        data = affected(interval(version="1.0.0-rc.1", lessThan="1.0.0"))
        self.assertTrue(version_match("1.0.0-rc.2", data)[0])
        self.assertFalse(version_match("1.0.0", data)[0])
        python = affected(interval(version="1!1.0", lessThan="1!2.0", versionType="python"))
        self.assertTrue(version_match("1!1.5", python)[0])
        self.assertFalse(version_match("2!1.0", python)[0])

    def test_open_ended_and_disjoint_ranges(self):
        data = affected(interval(), interval(version="3.0.0", lessThan="*"))
        self.assertFalse(version_match("2.5.0", data)[0])
        self.assertTrue(version_match("3.0.0", data)[0])
        self.assertTrue(version_match("90.0.0", data)[0])

    def test_conflicts_unknown_and_unsupported_never_become_verified(self):
        cases = [
            affected(interval(), interval(status="unaffected")),
            affected(interval(status="unknown")),
            affected(interval(versionType="rpm")),
            affected(interval(versionType=["semver"])),
            affected(interval(version="*")),
            affected(interval(lessThan="1.0.0")),
            affected(interval(lessThanOrEqual="2.0.0")),
            affected(interval(changes=[{"at": "1.5.0", "status": "affected"}, {"at": "1.5.0", "status": "unaffected"}])),
            affected(interval(changes=[{"at": "2.0.0", "status": "affected"}])),
            affected(interval(changes=None)),
            affected({"version": ">=1.0.0, <2.0.0", "status": "affected"}),
            affected({"version": "release-B", "status": "affected"}),
            affected(default="unknown"),
            {"cve_versions": None},
            affected(*([interval()] * 257)),
        ]
        for data in cases:
            with self.subTest(data=data):
                self.assertEqual(version_match("1.5.0", data)[1], "version_unverified")
        self.assertEqual(version_match(None, affected(interval()))[1], "unknown")


class GitHubAlternativeTests(unittest.TestCase):
    def test_disjoint_branches_and_fixed_boundaries(self):
        data = {"ecosystem": "npm", "version_range": ">=1.0.0, <1.5.0 || >=2.0.0, <2.1.0"}
        for version, expected in {"1.0.0": True, "1.5.0": False, "1.9.0": False, "2.0.0": True, "2.1.0": False}.items():
            with self.subTest(version=version):
                result = github_version_match(version, data)
                self.assertEqual(result[0], expected)
                self.assertEqual(result[1], "affected_range" if expected else "unaffected")

    def test_unsupported_branch_does_not_prove_unaffected(self):
        data = {"ecosystem": "npm", "version_range": "^1.0.0 || >=2.0.0, <2.1.0"}
        self.assertEqual(github_version_match("1.5.0", data)[1], "version_unverified")
        self.assertEqual(github_version_match("2.0.0", data)[1], "affected_range")
        data["version_range"] = "<1.0.0 || "
        self.assertEqual(github_version_match("2.0.0", data)[1], "version_unverified")
        data["version_range"] = " || ".join(["<1.0.0"] * 33)
        self.assertEqual(github_version_match("2.0.0", data)[1], "version_unverified")
