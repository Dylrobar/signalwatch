import unittest

from signalwatch.signal_filter import filter_signals, qualify_signal


class SignalFilterTests(unittest.TestCase):
    def test_requires_product_and_indicator_in_either_order(self):
        self.assertTrue(qualify_signal("Patch released for OpenSSL", ["openssl"], ["patch"])["qualified"])
        self.assertFalse(qualify_signal("OpenSSL performance report", ["openssl"], ["patch"])["qualified"])
        self.assertFalse(qualify_signal("Patch released for unknown software CVE-2026-12345", ["openssl"], ["patch"])["qualified"])

    def test_product_boundaries_and_regex_metacharacters_are_literal(self):
        self.assertFalse(qualify_signal("nginxify exploit", ["nginx"], ["exploit"])["qualified"])
        result = qualify_signal("Vulnerability in C++ and .NET", ["C++", ".NET"], ["vulnerability"])
        self.assertEqual(result["matched_products"], ["C++", ".NET"])
        self.assertTrue(result["qualified"])

    def test_multitoken_terms_accept_whitespace_and_preserve_match_reasons(self):
        result = qualify_signal("Windows 11 remote\ncode execution", ["Windows 11"], ["remote code execution"])
        self.assertEqual(result["matched_indicators"], ["remote code execution"])
        missing = qualify_signal("CVE-2026-12345", [], ["exploit"])
        self.assertEqual(missing["reasons"], ["product_identifier_missing", "exploit_or_patch_indicator_missing"])

    def test_batch_counts_are_explicit_and_original_records_unchanged(self):
        records = [{"title": "nginx exploit"}, {"title": "nginx tutorial"}, {"title": "unknown exploit"}]
        result = filter_signals(records, ["nginx"], ["exploit"])
        self.assertEqual(result["counts"], {"records": 3, "qualified": 1, "filtered": 2})
        self.assertEqual(result["reason_counts"], {"exploit_or_patch_indicator_missing": 1, "product_identifier_missing": 1})
        self.assertEqual(records[0], {"title": "nginx exploit"})
        self.assertTrue(result["qualified"][0]["_signal"]["qualified"])
