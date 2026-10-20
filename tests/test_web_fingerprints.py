import json
import unittest
from unittest.mock import patch

from signalwatch.extract import cpe_parts
from signalwatch.web_fingerprints import CSP_DOMAINS, HTML_LIMIT, analyze_http_response


class FingerprintTests(unittest.TestCase):
    def analyze(self, headers=None, html="", **kwargs):
        return analyze_http_response("https://example.test/?token=URL-SECRET", headers or {}, html, **kwargs)

    def direct(self, rows):
        return {(row["vendor"], row["product"]): row for row in rows if row["status"] == "http_detected"}

    def test_existing_header_identities_and_versions(self):
        cases = [("Server", "nginx/1.24.0", "f5", "nginx", "1.24.0"),
                 ("Server", "Apache/2.4.62 (Ubuntu)", "apache", "http_server", "2.4.62"),
                 ("Server", "Microsoft-IIS/10.0", "microsoft", "internet_information_services", "10.0"),
                 ("X-Powered-By", "PHP/8.3.5", "php", "php", "8.3.5"),
                 ("X-Powered-By", "ASP.NET/4.0", "microsoft", "asp.net", "4.0"),
                 ("X-Powered-By", "Express/4.21.0", "expressjs", "express", "4.21.0"),
                 ("X-Powered-By", "Next.js v14.2.3", "vercel", "next.js", "14.2.3")]
        for name, value, vendor, product, version in cases:
            with self.subTest(value=value):
                found = self.direct(self.analyze({name: value}))[(vendor, product)]
                self.assertEqual(found["version"], version)
                self.assertEqual(found["evidence_type"], "header")
                self.assertEqual(cpe_parts(found["cpe"])["version"], version)
                self.assertEqual(len(found["cpe"].split(":")), 13)

    def test_edge_header_presence_has_no_made_up_cpe_or_exposed_header_values(self):
        cases = [("CF-Ray", "cloudflare", "cloudflare"), ("X-Amz-Cf-Id", "amazon", "cloudfront"),
                 ("X-Amz-Cf-Pop", "amazon", "cloudfront"), ("X-Iinfo", "imperva", "incapsula")]
        for name, vendor, product in cases:
            with self.subTest(name=name):
                rows = self.analyze({name: "RAW-HEADER-SECRET"})
                found = self.direct(rows)[(vendor, product)]
                self.assertNotIn("cpe", found)
                self.assertNotIn("RAW-HEADER-SECRET", json.dumps(rows))
                self.assertNotIn("URL-SECRET", json.dumps(rows))
        self.assertIn(("varnish-software", "varnish_cache"), self.direct(self.analyze({"X-Varnish": "123"})))
        self.assertIn(("amazon", "cloudfront"), self.direct(self.analyze({"Via": "1.1 gateway (CloudFront)"})))
        self.assertIn(("imperva", "incapsula"), self.direct(self.analyze({"X-CDN": "Incapsula"})))
        self.assertIn(("cloudflare", "cloudflare"), self.direct(self.analyze({"Server": "cloudflare"})))

    def test_reviewed_product_headers_preserve_specific_identity_and_version(self):
        cases = [("Server", "Jetty(12.0.7)", "eclipse", "jetty", "12.0.7"),
                 ("Server", "Jetty(9.4.54.v20240208)", "eclipse", "jetty", "9.4.54.v20240208"),
                 ("Server", "Caddy/v2.8.4", "caddyserver", "caddy", "2.8.4"),
                 ("X-Jenkins", "2.479.1", "jenkins", "jenkins", "2.479.1")]
        for header, value, vendor, product, version in cases:
            with self.subTest(value=value):
                finding = self.direct(self.analyze({header: value}))[(vendor, product)]
                self.assertEqual(finding["version"], version)
                self.assertEqual(cpe_parts(finding["cpe"])["vendor"], vendor)
                self.assertEqual(cpe_parts(finding["cpe"])["product"], product)
                self.assertEqual(cpe_parts(finding["cpe"])["version"], version)
        self.assertEqual(self.direct(self.analyze({"Server": "Caddy"}))[("caddyserver", "caddy")]["version"], "")

    def test_reviewed_headers_reject_mentions_similar_names_and_invalid_versions(self):
        for headers in ({"Server": "CaddyProxy/2.8.4"}, {"Server": "Gateway with Jetty(12.0.7)"},
                        {"Server": "Jetty(12.0.7) documentation"}, {"X-Jenkins": "unknown"},
                        {"X-Jenkins": "2.479.1; admin=secret"}, {"X-Powered-By": "Caddy/v2.8.4"}):
            self.assertFalse(self.analyze(headers), headers)
        self.assertFalse(self.analyze(html="<p>We integrate with Jenkins, Caddy and Jetty.</p>"))

    def test_reviewed_jenkins_header_reaches_exact_product_cve_correlation(self):
        from signalwatch.collectors import _web_fingerprints
        from signalwatch.store import Store
        store = Store(":memory:")
        _, observations, _ = _web_fingerprints("https://ci.example.test", {"X-Jenkins": "2.479.1"}, "")
        store.ingest({"observations": observations, "advisories": [
            {"id": "CVE-2026-12345", "affected": [{"vendor": "jenkins", "product": "jenkins", "versionEndExcluding": "2.480"}]},
            {"id": "CVE-2026-12346", "affected": [{"vendor": "jenkins", "product": "git_plugin", "versionEndExcluding": "9.0"}]}]})
        self.assertEqual(store.reconcile()["alerts"], 1)
        self.assertEqual(store.alerts()["items"][0]["advisory_id"], "CVE-2026-12345")
        _, observations, _ = _web_fingerprints("https://ci.example.test", {"X-Jenkins": "2.480"}, "")
        store.ingest({"observations": observations})
        self.assertEqual(store.reconcile()["alerts"], 0)

    def test_cookie_names_only_and_no_ambiguous_stack_guesses(self):
        rows = self.analyze({"Set-Cookie": ["JSESSIONID=SESSION-SECRET; Path=/; HttpOnly", "ASP.NET_SessionId=ASP-SECRET",
                                            "XSRF-TOKEN=TOKEN-SECRET", "unrelated=laravel_session"]})
        direct = self.direct(rows)
        self.assertIn(("java", "servlet"), direct)
        self.assertIn(("microsoft", "asp.net"), direct)
        self.assertNotIn(("apache", "tomcat"), direct)
        self.assertNotIn(("microsoft", "internet_information_services"), direct)
        self.assertNotIn(("laravel", "framework"), direct)
        serialized = json.dumps(rows)
        for secret in ("SESSION-SECRET", "ASP-SECRET", "TOKEN-SECRET", "URL-SECRET"):
            self.assertNotIn(secret, serialized)
        self.assertFalse(any(row.get("cpe", "").startswith("cpe:2.3:a:oracle:jdk:") for row in rows))

    def test_cookie_markers_accept_sanitized_names_and_repeated_headers(self):
        rows = self.analyze({"set-cookie": ["__cf_bm=secret; Expires=Wed, 21 Oct 2026 07:28:00 GMT", "laravel_session=secret; HttpOnly"]},
                            cookie_names=("incap_ses_123", "visid_incap_123", "SVPNCOOKIE", "NSC_AAAC", "_dd_s"))
        products = self.direct(rows)
        for key in (("cloudflare", "cloudflare"), ("laravel", "framework"), ("imperva", "incapsula"),
                    ("fortinet", "fortios"), ("citrix", "netscaler_gateway"), ("datadog", "rum")):
            self.assertIn(key, products)
        self.assertEqual(products[("fortinet", "fortios")]["part"], "o")
        self.assertEqual(products[("fortinet", "fortios")]["cpe"].split(":")[2], "o")
        self.assertNotIn("secret", json.dumps(rows))
        self.assertFalse(self.analyze(cookie_names=("laravel_session_custom", "__cf_bm_fake", "XSRF-TOKEN")))

    def test_cookie_values_cannot_spoof_technology_cookie_names(self):
        for value in ('unrelated="hello, laravel_session=SECRET"; Path=/',
                      'unrelated=hello, laravel_session=SECRET; Path=/',
                      'unrelated=SECRET; Expires=Wed, 21 Oct 2026 07:28:00 GMT; Path=/'):
            with self.subTest(value=value):
                self.assertFalse(self.analyze({"Set-Cookie": value}))

    def test_meta_attributes_can_appear_in_any_order_and_ignore_plain_mentions(self):
        rows = self.analyze(html='''<meta content='WordPress 6.5.2' NAME='generator'>
            <meta content="Drupal 10.3.2" name="application-name"><meta name="generator" content="Joomla! 5.1.0">
            <p>We compare Tomcat, Fortinet, WordPress, Next.js and Sentry.init() in this article.</p>''')
        direct = self.direct(rows)
        self.assertEqual(direct[("wordpress", "wordpress")]["version"], "6.5.2")
        self.assertEqual(direct[("drupal", "drupal")]["version"], "10.3.2")
        self.assertEqual(direct[("joomla", "joomla!")]["version"], "5.1.0")
        self.assertIn(r"joomla\!", direct[("joomla", "joomla!")]["cpe"])
        self.assertEqual(len(direct), 3)

    def test_resource_signatures_discard_query_credentials(self):
        rows = self.analyze(html='''<script src="/_next/static/chunks/page.js?token=NEXT-SECRET"></script>
            <script src="https://js.stripe.com/v3/?key=STRIPE-SECRET"></script>
            <script src="/js/jquery-3.7.1.min.js?auth=JQUERY-SECRET"></script>
            <link href="/wp-content/themes/theme.css?signature=WP-SECRET" rel="stylesheet">
            <script src="/sites/default/files/drupal.js"></script>''')
        direct = self.direct(rows)
        self.assertEqual(direct[("jquery", "jquery")]["version"], "3.7.1")
        for key in (("vercel", "next.js"), ("stripe", "stripe"), ("wordpress", "wordpress"), ("drupal", "drupal")):
            self.assertIn(key, direct)
        self.assertNotIn("SECRET", json.dumps(rows))
        self.assertNotIn("cpe", direct[("stripe", "stripe")])
        self.assertNotIn(("nodejs", "node.js"), {(row["vendor"], row["product"]) for row in rows})
        self.assertNotIn(("oracle", "mysql"), {(row["vendor"], row["product"]) for row in rows})

    def test_script_hosts_and_paths_are_matched_at_boundaries(self):
        html = '''<script src="https://js.stripe.com.attacker.test/v3/"></script>
            <script src="https://browser.sentry-cdn.com.attacker.test/7.0.0/bundle.js"></script>
            <script src="/loader?next=/_next/static/chunk.js&amp;wp=/wp-content/plugin.js"></script>
            <p>/_next/static/chunk.js /wp-content/themes/ browser.sentry-cdn.com</p>'''
        self.assertFalse(self.analyze(html=html))

    def test_browser_sdk_version_never_becomes_sentry_server_version(self):
        rows = self.analyze({"Content-Security-Policy": "connect-src https://o123.sentry.io"},
                            '<script src="https://browser.sentry-cdn.com/8.31.0/bundle.min.js?secret=TOKEN"></script>')
        direct = self.direct(rows)
        self.assertEqual(direct[("sentry", "javascript_sdk")]["version"], "8.31.0")
        self.assertNotIn("cpe", direct[("sentry", "javascript_sdk")])
        server = next(row for row in rows if row["product"] == "sentry")
        self.assertEqual((server["status"], server["version"]), ("csp_integration", ""))
        self.assertNotIn("cpe", server)
        self.assertNotIn("TOKEN", json.dumps(rows))

    def test_dom_and_inline_hydration_markers(self):
        rows = self.analyze(html='''<app-root ng-version='17.1.0'></app-root>
            <script id="__NEXT_DATA__" type="application/json">{"token":"PRIVATE"}</script>
            <script>window.__NEXT_DATA__={token:"PRIVATE"}; Sentry.init({dsn:"PRIVATE"}); DD_RUM.init({token:"PRIVATE"});</script>''')
        direct = self.direct(rows)
        self.assertEqual(direct[("angular", "angular")]["version"], "17.1.0")
        self.assertEqual(direct[("angular", "angular")]["evidence_type"], "dom")
        self.assertIn(("vercel", "next.js"), direct)
        self.assertIn(("sentry", "javascript_sdk"), direct)
        self.assertIn(("datadog", "rum"), direct)
        self.assertNotIn("PRIVATE", json.dumps(rows))

    def test_datadog_script_and_packaged_jquery(self):
        rows = self.analyze(html='''<script src="https://www.datadoghq-browser-agent.com/us1/v5/datadog-rum.js"></script>
            <script src="https://cdn.example/jquery@3.7.1/dist/jquery.min.js"></script>''')
        direct = self.direct(rows)
        self.assertIn(("datadog", "rum"), direct)
        self.assertEqual(direct[("jquery", "jquery")]["version"], "3.7.1")

    def test_gateway_titles_forms_and_cookies_require_specific_evidence(self):
        cases = [('<title>Apache Tomcat/9.0.82</title>', ("apache", "tomcat")),
                 ('<form action="/global-protect/login.esp"></form>', ("paloaltonetworks", "globalprotect")),
                 ('<script>var client = PanGlobalProtect;</script>', ("paloaltonetworks", "globalprotect")),
                 ('<title>FortiGate SSL VPN</title><form action="/remote/login"></form>', ("fortinet", "fortios")),
                 ('<title>Citrix Gateway</title>', ("citrix", "netscaler_gateway")),
                 ('<title>MikroTik RouterOS v7.17.2</title>', ("mikrotik", "routeros"))]
        for html, key in cases:
            with self.subTest(key=key):
                self.assertIn(key, self.direct(self.analyze(html=html)))
        portal = self.direct(self.analyze(html='<form action="/global-protect/login.esp"></form>'))
        self.assertNotIn("cpe", portal[("paloaltonetworks", "globalprotect")])
        self.assertFalse(self.analyze(html='<form action="/remote/login"></form><a href="/vpn/index.html">VPN</a>'))
        self.assertNotIn(("apache", "http_server"), self.direct(self.analyze({"Server": "Apache Tomcat/9.0.82"})))
        self.assertFalse(self.analyze({"Server": "Apache-Coyote/1.1"}))

    def test_stronger_versioned_evidence_survives_weaker_markers(self):
        rows = self.analyze({"X-Powered-By": "Next.js 14.2.3", "Server": "nginx"},
                            '<script src="/_next/static/chunks/page.js"></script>')
        nextjs = self.direct(rows)[("vercel", "next.js")]
        self.assertEqual((nextjs["version"], nextjs["evidence_type"]), ("14.2.3", "header"))
        self.assertEqual(self.direct(rows)[("f5", "nginx")]["version"], "")

    def test_implied_dependencies_are_unversioned_and_do_not_override_direct(self):
        rows = self.analyze({"X-Powered-By": "PHP/8.3.5"}, '<meta name="generator" content="WordPress 6.5.2">')
        php = [row for row in rows if row["product"] == "php"]
        self.assertEqual(len(php), 1)
        self.assertEqual(php[0]["version"], "8.3.5")
        rows = self.analyze(html='<script src="/_next/static/page.js"></script>')
        react = next(row for row in rows if row["product"] == "react")
        self.assertEqual((react["status"], react["version"], react["evidence_type"]), ("implied_dependency", "", "implied"))
        self.assertEqual(react["implied_by"], ["Next.js"])
        self.assertNotIn("cpe", react)
        self.assertLess(react["confidence"], self.direct(rows)[("vercel", "next.js")]["confidence"])

    def test_implication_closure_is_transitive_and_cycle_safe(self):
        with patch("signalwatch.web_fingerprints.IMPLIES", {"nextjs": ("react", "php"), "react": ("php",), "php": ("nextjs",)}):
            rows = self.analyze({"X-Powered-By": "Next.js"})
        self.assertEqual(len(rows), 3)
        self.assertEqual({row["product"] for row in rows}, {"next.js", "react", "php"})
        self.assertEqual(sum(row["status"] == "http_detected" for row in rows), 1)

    def test_csp_parses_vendor_hosts_and_preserves_integration_provenance(self):
        for domain, key in CSP_DOMAINS.items():
            with self.subTest(domain=domain):
                rows = self.analyze({"Content-Security-Policy": "connect-src 'self' https://*." + domain + ":443/path?token=PRIVATE"})
                self.assertEqual(len(rows), 1)
                row = rows[0]
                self.assertEqual(row["status"], "csp_integration")
                self.assertEqual(row["evidence_type"], "csp")
                self.assertEqual(row["csp_directive"], "connect-src")
                self.assertEqual(row["matched_host"], domain)
                self.assertEqual(row["version"], "")
                self.assertNotIn("cpe", row)
                self.assertNotIn("PRIVATE", json.dumps(row))

    def test_csp_ignores_lookalikes_paths_reporting_keywords_and_userinfo(self):
        values = ["connect-src https://okta.com.evil.test https://notokta.com https://evil.test/okta.com",
                  "report-uri https://okta.com; report-to https://auth0.com",
                  "script-src 'nonce-okta.com' 'sha256-auth0.com' data: blob:",
                  "connect-src https://okta.com@evil.test https://evil.test@okta.com",
                  "not-a-directive https://okta.com", "connect-src okta.com:broken"]
        for value in values:
            with self.subTest(value=value):
                self.assertFalse(self.analyze({"Content-Security-Policy": value}))
        self.assertFalse(self.analyze({"Content-Security-Policy-Report-Only": "connect-src https://okta.com"}))

    def test_csp_duplicate_directives_and_multiple_policies(self):
        self.assertFalse(self.analyze({"Content-Security-Policy": "connect-src 'self'; connect-src https://okta.com"}))
        rows = self.analyze({"Content-Security-Policy": "connect-src 'self', connect-src https://okta.com; script-src https://cdn.okta.com"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["product"], "okta")

    def test_direct_and_csp_evidence_remain_separate(self):
        rows = self.analyze({"Content-Security-Policy": "frame-src https://checkout.stripe.com"},
                            '<script src="https://js.stripe.com/v3/"></script>')
        stripe = [row for row in rows if row["product"] == "stripe"]
        self.assertEqual({row["status"] for row in stripe}, {"http_detected", "csp_integration"})

    def test_headers_preserve_multiple_values_case_insensitively(self):
        class Headers:
            def multi_items(self):
                return [("SET-COOKIE", "laravel_session=SECRET"), ("set-cookie", "NSC_AAAC=SECRET"),
                        ("CONTENT-SECURITY-POLICY", "connect-src https://okta.com"),
                        ("content-security-policy", "script-src https://js.stripe.com")]
        rows = self.analyze(Headers())
        self.assertEqual(len(self.direct(rows)), 2)
        self.assertEqual(sum(row["status"] == "csp_integration" for row in rows), 2)
        self.assertNotIn("SECRET", json.dumps(rows))

    def test_bounded_html_and_valid_contract(self):
        self.assertFalse(self.analyze(html=" " * HTML_LIMIT + '<meta name="generator" content="WordPress 6.5.2">'))
        self.assertFalse(self.analyze(html="é" * (HTML_LIMIT // 2) + '<script src="/_next/static/a.js"></script>'))
        rows = self.analyze({"Server": "nginx/1.24.0"}, b'<meta name="generator" content="WordPress 6.5.2">')
        self.assertLessEqual(len(rows), 100)
        for row in rows:
            self.assertEqual(row["method"], "http_fingerprint_v1")
            self.assertIsInstance(row["version"], str)
            self.assertTrue(all(row[field] for field in ("vendor", "product", "vendor_name", "product_name", "category", "part", "evidence_type")))
            self.assertLessEqual(len(row["evidence_snippet"]), 300)


if __name__ == "__main__":
    unittest.main()
