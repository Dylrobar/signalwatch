import json
import unittest

from signalwatch.applicability import evaluate
from signalwatch.store import Store


def cpe(vendor="acme", product="edge", version="*", part="a", **extra):
    return ":".join(["cpe", "2.3", part, vendor, product, version,
                     *(extra.get(key, "*") for key in ("update", "edition", "language", "sw_edition", "target_sw", "target_hw", "other"))])


def observation(**values):
    return {"id": "obs", "asset_id": "domain:acme.test", "vendor": "acme", "product": "edge", "part": "a",
            "version": "1.5", "source_url": "https://acme.test", "evidence": "HTTP identifier", "confidence": .8, **values}


def target_leaf(**values):
    return {"criteria": cpe(), "vulnerable": True, "versionEndExcluding": "2.0", **values}


def windows_leaf(**values):
    return {"criteria": cpe("microsoft", "windows", part="o"), "vulnerable": False, **values}


def config(*leaves, operator="AND", negate=False):
    return [{"operator": operator, "negate": negate, "nodes": [{"operator": "OR", "cpeMatch": [leaf]} for leaf in leaves]}]


class ApplicabilityTests(unittest.TestCase):
    def assess(self, tree, *others, target=None):
        target = target or observation()
        return evaluate(tree, [target, *others], target)

    def test_required_os_is_positive_prerequisite_and_missing_is_unknown(self):
        tree = config(target_leaf(), windows_leaf())
        self.assertEqual(self.assess(tree)["state"], "unknown")
        windows = observation(id="os", vendor="microsoft", product="windows", part="o", version="11")
        result = self.assess(tree, windows)
        self.assertEqual(result["state"], "true")
        self.assertFalse(result["conditions"][1]["vulnerable"])

    def test_other_assets_and_other_operating_systems_do_not_establish_absence(self):
        tree = config(target_leaf(), windows_leaf())
        other = observation(asset_id="domain:other.test", vendor="microsoft", product="windows", part="o", version="11")
        linux = observation(vendor="linux", product="linux_kernel", part="o", version="6.1")
        self.assertEqual(self.assess(tree, other, linux)["state"], "unknown")

    def test_known_prerequisite_version_mismatch_is_false(self):
        windows = observation(vendor="microsoft", product="windows", part="o", version="11")
        tree = config(target_leaf(), windows_leaf(versionEndExcluding="11"))
        self.assertEqual(self.assess(tree, windows)["state"], "false")

    def test_company_text_never_establishes_co_located_operating_system(self):
        target = observation(asset_id="company:acme", origin="technographic:doc-a")
        windows = observation(asset_id="company:acme", origin="technographic:doc-b", vendor="microsoft", product="windows", part="o", version="11")
        for prerequisite in (windows_leaf(), windows_leaf(versionEndExcluding="11")):
            result = self.assess(config(target_leaf(), prerequisite), windows, target=target)
            self.assertEqual(result["state"], "unknown")

    def test_or_alternatives_and_negation(self):
        tree = config(target_leaf(versionEndExcluding="1.0"), target_leaf(versionStartIncluding="1.2"), operator="OR")
        self.assertEqual(self.assess(tree)["state"], "true")
        tree = [{"operator": "AND", "nodes": [{"cpeMatch": [target_leaf()]},
                 {"negate": True, "cpeMatch": [windows_leaf()]}]}]
        self.assertEqual(self.assess(tree)["state"], "unknown")
        windows = observation(vendor="microsoft", product="windows", part="o")
        self.assertEqual(self.assess(tree, windows)["state"], "false")

    def test_other_vulnerable_product_does_not_satisfy_target_or_branch(self):
        other = observation(vendor="other", product="app")
        tree = config(target_leaf(versionEndExcluding="1.0"),
                      {"criteria": cpe("other", "app"), "vulnerable": True}, operator="OR")
        self.assertEqual(self.assess(tree, other)["state"], "false")

    def test_negated_subtrees_preserve_boolean_scope_and_incomplete_trees_are_unknown(self):
        other = observation(vendor="other", product="app")
        tree = [{"negate": True, "operator": "OR", "cpeMatch": [target_leaf(versionEndExcluding="1.0"),
                 {"criteria": cpe("other", "app"), "vulnerable": True}]}]
        self.assertEqual(self.assess(tree, other)["state"], "false")
        tree = [{"operator": "OR", "nodes": [{"cpeMatch": [target_leaf(versionEndExcluding="1.0")]},
                 {"operator": "UNKNOWN", "cpeMatch": [target_leaf()]}]}]
        self.assertEqual(self.assess(tree)["state"], "unknown")

    def test_cpe_attributes_missing_unknown_and_explicit_mismatch_false(self):
        tree = config(target_leaf(criteria=cpe(target_sw="windows")))
        self.assertEqual(self.assess(tree)["state"], "unknown")
        self.assertEqual(self.assess(tree, target=observation(cpe=cpe(version="1.5", target_sw="linux")))["state"], "false")
        self.assertEqual(self.assess(tree, target=observation(cpe=cpe(version="1.5", target_sw="windows")))["state"], "true")

    def test_unknown_and_native_versions_remain_unknown(self):
        tree = config(target_leaf())
        for value in ("", "1.5-rpm1"):
            self.assertEqual(self.assess(tree, target=observation(version=value))["state"], "unknown")
        self.assertEqual(self.assess(config(target_leaf(versionEndExcluding=None)), target=observation(version=""))["state"], "true")

    def test_empty_malformed_and_oversize_are_bounded_unknown(self):
        for tree in (None, {}, {"nodes": []}, {"operator": "XOR"}, {"nodes": "invalid"}, {"ecosystem": "npm"}):
            self.assertEqual(self.assess(tree)["state"], "unknown")
        nested = {"cpeMatch": [target_leaf()]}
        for _ in range(30):
            nested = {"operator": "AND", "nodes": [nested]}
        self.assertEqual(self.assess(nested)["state"], "unknown")
        result = self.assess({"cpeMatch": [target_leaf()] * 600})
        self.assertEqual(result["state"], "unknown")
        self.assertLessEqual(len(result["conditions"]), 40)


class AlertAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.store = Store(":memory:")

    def seed(self, tree=None, observations=None):
        self.store.ingest({"advisories": [{"id": "CVE-2026-12345", "source": "NVD", "configurations": tree,
                          "affected": [{"vendor": "acme", "product": "edge", "versionEndExcluding": "2.0"}]}],
                           "observations": observations or [observation()]})

    def alert(self):
        alert = self.store.alerts()["items"][0]
        if isinstance(alert["assessment"], str):
            alert["assessment"] = json.loads(alert["assessment"])
        return alert

    def test_unknown_prerequisite_retained_then_known_false_resolves(self):
        self.seed(config(target_leaf(), windows_leaf(versionEndExcluding="11")))
        self.assertEqual(self.store.reconcile()["alerts"], 1)
        self.assertEqual(self.alert()["assessment"]["applicability"]["state"], "unknown")
        self.store.ingest({"observations": [observation(vendor="microsoft", product="windows", part="o", version="11")]})
        self.assertEqual(self.store.reconcile()["removed"], 1)

    def test_supporting_and_outside_range_evidence_preserve_chosen_observation(self):
        self.seed(observations=[observation(), observation(source_url="https://acme.test/other", version="1.6", confidence=.6),
                                observation(source_url="https://second.test", version="2.0", confidence=.95),
                                observation(asset_id="domain:other.test", source_url="https://secret.test", version="2.1")])
        self.store.reconcile()
        alert = self.alert()
        evidence = alert["assessment"]["evidence"]
        self.assertEqual(alert["source_url"], "https://acme.test")
        self.assertEqual(alert["confidence"], .8)
        self.assertEqual(len(evidence["supporting"]), 2)
        self.assertEqual(len(evidence["contradicting"]), 1)
        self.assertEqual(evidence["contradicting"][0]["version"], "2.0")
        self.assertEqual(evidence["independent_sources"], 1)
        self.assertNotIn("secret.test", json.dumps(evidence))

    def test_failed_alternative_range_does_not_contradict_matching_range(self):
        self.seed()
        self.store.ingest({"advisories": [{"id": "CVE-2026-12345", "affected": [
            {"vendor": "acme", "product": "edge", "versionEndExcluding": "1.0"},
            {"vendor": "acme", "product": "edge", "versionStartIncluding": "1.2", "versionEndExcluding": "2.0"}]}]})
        self.store.reconcile()
        evidence = self.alert()["assessment"]["evidence"]
        self.assertEqual(len(evidence["supporting"]), 1)
        self.assertEqual(evidence["contradicting"], [])

    def test_syndication_and_negative_text_are_scoped(self):
        from tests.test_technographic_store import posting
        self.store.ingest({"entities": [{"id": "company:acme", "kind": "company", "name": "Acme"},
            {"id": "domain:acme.test", "kind": "domain", "value": "acme.test"},
            {"id": "company:other", "kind": "company", "name": "Other"}],
            "edges": [{"from_id": "company:acme", "to_id": "domain:acme.test", "relation": "official_website"}]})
        self.store.set_company_asset("company:other", "https://other.test", evidence="Reviewed ownership", source_url="https://other.test/about")
        self.store.ingest({"entities": [posting("We use Terraform.", key="a"),
            posting("We use Terraform.", key="mirror", url="https://mirror.test/jobs/1"),
            posting("We no longer use Terraform.", key="old", url="https://acme.test/jobs/old"),
            posting("We never use Terraform.", key="other", company_id="company:other", url="https://secret.test/job")],
            "advisories": [{"id": "CVE-2026-54321", "affected": [{"vendor": "hashicorp", "product": "terraform"}]}]})
        self.store.reconcile()
        evidence = self.alert()["assessment"]["evidence"]
        self.assertEqual(len(evidence["supporting"]), 1)
        self.assertEqual(evidence["independent_sources"], 1)
        self.assertEqual([row["status"] for row in evidence["contradicting"]], ["historical"])
        self.assertNotIn("secret.test", json.dumps(evidence))
        # Retained document history must not bypass current attribution fences.
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE evidence_resolution SET status='conflict' WHERE source_entity_id='old'")
        self.store.reconcile()
        self.assertEqual(self.alert()["assessment"]["evidence"]["contradicting"], [])


if __name__ == "__main__":
    unittest.main()
