import unittest

from signalwatch.technographics import FINDING_LIMIT, METHOD, TEXT_LIMIT, extract


class TechnographicTests(unittest.TestCase):
    def findings(self, text, **kwargs):
        return {row["product_name"]: row for row in extract(text, **kwargs)}

    def test_asserted_operational_use_and_version(self):
        findings = self.findings("We use Windows 11 and macOS 15.2 on our endpoints. We operate our Kubernetes clusters.")
        self.assertEqual(findings["Windows"]["version"], "11")
        self.assertEqual(findings["macOS"]["version"], "15.2")
        self.assertEqual(findings["Kubernetes"]["status"], "asserted_use")
        self.assertTrue(all(row["status"] == "asserted_use" for row in findings.values()))

    def test_requirements_are_not_deployments(self):
        findings = self.findings("Experience with Okta is required. Knowledge of Terraform preferred. PostgreSQL experience is preferred.", source_type="greenhouse")
        self.assertEqual({row["status"] for row in findings.values()}, {"requirement"})

    def test_alternative_products_are_uncertain(self):
        findings = self.findings("Experience with AWS or Azure preferred.", source_type="job")
        self.assertEqual({row["status"] for row in findings.values()}, {"alternative"})
        self.assertTrue(all(row["cpe"] is None for row in findings.values()))

    def test_negation_is_per_product(self):
        findings = self.findings("We use Okta and do not use Snowflake; we use Terraform, not Terragrunt.")
        self.assertEqual(findings["Okta"]["status"], "asserted_use")
        self.assertEqual(findings["Snowflake"]["status"], "negated")
        self.assertEqual(findings["Terraform"]["status"], "asserted_use")
        self.assertEqual(findings["Terragrunt"]["status"], "negated")

    def test_first_person_subject_survives_but_with_operational_verb(self):
        for text in ("We do not use Okta but run Terraform.", "We do not use Okta but currently run Terraform.", "We don't use Okta but run Terraform."):
            with self.subTest(text=text):
                findings = self.findings(text)
                self.assertEqual(findings["Okta"]["status"], "negated")
                self.assertEqual(findings["Terraform"]["status"], "asserted_use")
        findings = self.findings("We use Okta and Acme uses Snowflake but run Terraform.")
        self.assertEqual(findings["Terraform"]["status"], "mention")

    def test_post_product_negation_and_non_negative_not_only(self):
        findings = self.findings("Okta is not used. We use not only Terraform but also Datadog.")
        self.assertEqual(findings["Okta"]["status"], "negated")
        self.assertEqual(findings["Terraform"]["status"], "asserted_use")

    def test_migration_separates_source_and_destination(self):
        findings = self.findings("Migrate our legacy Oracle databases into Snowflake on AWS.", source_type="greenhouse")
        self.assertEqual(findings["Oracle Database"]["status"], "asserted_use")
        self.assertEqual(findings["Snowflake"]["status"], "planned")
        self.assertEqual(findings["AWS"]["status"], "planned")

    def test_completed_migration_preserves_historical_source(self):
        findings = self.findings("We migrated from Oracle Database to PostgreSQL.")
        self.assertEqual(findings["Oracle Database"]["status"], "historical")
        self.assertEqual(findings["PostgreSQL"]["status"], "asserted_use")

    def test_migration_experience_does_not_prove_any_deployment(self):
        findings = self.findings("Experience migrating Oracle Database to Snowflake.", source_type="lever")
        self.assertTrue(all(row["status"] != "asserted_use" for row in findings.values()))

    def test_planned_and_historical_stack_not_active(self):
        findings = self.findings("We previously used Splunk Enterprise. We plan to deploy Datadog. Our GlobalProtect deployment is planned.")
        self.assertEqual(findings["Splunk Enterprise"]["status"], "historical")
        self.assertEqual(findings["Datadog"]["status"], "planned")
        self.assertEqual(findings["GlobalProtect"]["status"], "planned")

    def test_third_party_case_study_does_not_become_first_party(self):
        for text in ("Acme uses Snowflake for analytics.", "Our customers use Okta.", "We help customers use AWS."):
            with self.subTest(text=text):
                self.assertTrue(all(row["status"] != "asserted_use" for row in extract(text, source_type="case_study")))

    def test_quoted_customer_use_is_not_the_publishers_stack(self):
        for text in ('Our customer said, "We use Terraform."',
                     'Our client explained, “We use Datadog.”',
                     'Our partner said: "We use Snowflake and AWS."'):
            with self.subTest(text=text):
                self.assertTrue(all(row["status"] == "mention" for row in extract(text, source_type="company_feeds")))

    def test_product_subject_change_does_not_inherit_first_party_use(self):
        for text in ("We use Okta and Acme uses Snowflake.", "We use Okta while Snowflake released a patch."):
            with self.subTest(text=text):
                findings = self.findings(text)
                self.assertEqual(findings["Okta"]["status"], "asserted_use")
                self.assertEqual(findings["Snowflake"]["status"], "mention")
        self.assertEqual(self.findings("We use GitLab and evaluated Datadog.")["Datadog"]["status"], "planned")

    def test_product_subject_and_customer_stack_are_not_first_party(self):
        for text in ("We use Okta; Snowflake customers use Terraform.",
                     "We use Okta and Snowflake customers use Terraform.",
                     "We use Okta and Snowflake released a patch.",
                     "We use Okta and Snowflake is a provider we evaluated."):
            with self.subTest(text=text):
                findings = self.findings(text)
                self.assertEqual(findings["Okta"]["status"], "asserted_use")
                self.assertEqual(findings["Snowflake"]["status"], "mention")
                if "Terraform" in findings:
                    self.assertEqual(findings["Terraform"]["status"], "mention")

    def test_negation_of_a_threat_or_qualification_is_not_asset_negation(self):
        self.assertEqual(extract("No vulnerability in Okta has been reported.")[0]["status"], "mention")
        self.assertEqual(extract("No experience with Okta is required.", source_type="job")[0]["status"], "requirement")
        self.assertEqual(extract("We do not use AWS or Azure.")[1]["status"], "negated")

    def test_specific_products_are_separate_from_vendor_mentions(self):
        findings = self.findings("CrowdStrike and Fortinet announced news. We use CrowdStrike Falcon, FortiGate, FortiOS 7.4.3, Palo Alto Panorama, PAN-OS 11.1 and GlobalProtect.")
        self.assertEqual(findings["CrowdStrike"]["status"], "mention")
        self.assertEqual(findings["Fortinet"]["status"], "mention")
        self.assertTrue({"Palo Alto Panorama", "PAN-OS", "GlobalProtect", "CrowdStrike Falcon", "FortiGate", "FortiOS"}.issubset(findings))
        self.assertEqual(findings["FortiOS"]["version"], "7.4.3")
        self.assertEqual(extract("Falcon birds and panorama photographs. CIC membership."), [])

    def test_specific_cloud_and_splunk_products_do_not_collapse(self):
        findings = self.findings("We use AWS EKS, Azure Active Directory, Splunk Cloud and Splunk Enterprise, Terraform and Terragrunt.")
        self.assertEqual(set(findings), {"AWS EKS", "Microsoft Entra ID", "Splunk Cloud", "Splunk Enterprise", "Terraform", "Terragrunt"})
        self.assertNotEqual(findings["Splunk Cloud"]["product"], findings["Splunk Enterprise"]["product"])
        self.assertEqual(findings["Terraform"]["vendor"], "hashicorp")

    def test_job_qualification_heading_survives_newlines(self):
        findings = self.findings("Requirements:\nKubernetes\nTerraform\nResponsibilities:\nManage our Okta directory.", source_type="ashby")
        self.assertEqual(findings["Kubernetes"]["status"], "requirement")
        self.assertEqual(findings["Terraform"]["status"], "requirement")
        self.assertEqual(findings["Okta"]["status"], "asserted_use")

    def test_unrelated_version_not_attached_and_boundary_matching(self):
        findings = self.findings("We use GitLab to run a 1000 host fleet. A Postgres-like service is discussed. macOSification is unrelated.")
        self.assertEqual(findings["GitLab"]["version"], "")
        self.assertEqual(extract("We manage our FortiGate 100F appliances.")[0]["version"], "")
        self.assertNotIn("macOS", findings)
        self.assertEqual(extract("Kubernetesify gitlabrunner falconsensor"), [])

    def test_terminal_punctuation_preserves_complete_version(self):
        self.assertEqual(extract("We use PAN-OS 11.2.")[0]["version"], "11.2")
        self.assertEqual(extract("We use GitLab 17.4.1.")[0]["version"], "17.4.1")
        self.assertEqual(extract("We use Okta 1.2 and Okta 2.3.")[1]["version"], "2.3")
        self.assertEqual(extract("We use FortiGate 100F.")[0]["version"], "")

    def test_evidence_bounded_and_only_matching_context_returned(self):
        text = "Unrelated private text.\n" + "We use Datadog for our application monitoring.\n" + "No technology here."
        row = extract(text)[0]
        self.assertEqual(row["evidence_snippet"], "We use Datadog for our application monitoring.")
        self.assertEqual(row["method"], METHOD)
        self.assertTrue(all(key in row for key in ("vendor", "product", "product_name", "vendor_name", "category", "part", "version", "cpe", "evidence_snippet", "status", "confidence", "method")))
        self.assertEqual(extract("x" * TEXT_LIMIT + "\nWe use Okta."), [])
        self.assertLessEqual(len(extract("\n".join(f"We use Okta for tenant {number}." for number in range(1000)))), FINDING_LIMIT)
        self.assertLessEqual(len(extract("x" * 5000 + " We use Datadog " + "y" * 5000)[0]["evidence_snippet"]), 600)

    def test_repeated_identical_evidence_deduplicates(self):
        self.assertEqual(len(extract("We use Datadog.\nWe use Datadog.")), 1)
