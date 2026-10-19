import json
import tempfile
import traceback
import unittest
from pathlib import Path

from signalwatch.proxies import (
    MAX_PROXY_BYTES, ProxyConfigurationError, ProxyPool, ProxyUnavailableError, direct_hosts_from_env,
)


class DirectHostConfigurationTests(unittest.TestCase):
    def test_default_routes_only_official_cisa_and_nvd_hosts_directly(self):
        self.assertEqual(direct_hosts_from_env({}), {
            "www.cisa.gov", "nvd.nist.gov", "services.nvd.nist.gov",
        })

    def test_explicit_empty_list_routes_every_host_through_configured_proxy(self):
        for value in ("", "  ", " , , "):
            with self.subTest(value=value):
                self.assertEqual(direct_hosts_from_env({"SIGNALWATCH_PROXY_DIRECT_HOSTS": value}), set())

    def test_override_replaces_defaults_and_canonicalizes_exact_hosts(self):
        hosts = direct_hosts_from_env({"SIGNALWATCH_PROXY_DIRECT_HOSTS":
            " API.Example.test., api.example.test, bücher.example, 192.0.2.1, [2001:0db8::1], , "})
        self.assertEqual(hosts, {"api.example.test", "xn--bcher-kva.example", "192.0.2.1", "2001:db8::1"})

    def test_malformed_direct_hosts_fail_closed_without_echoing_values(self):
        for value in ("https://private-value.example", "private-value.example:443", "*.private-value.example",
                      ".private-value.example", "user:private-value@host.test", "host.test/private-value",
                      "host.test?token=private-value", "host.test#private-value", "bad private-value.test",
                      "bad\nprivate-value.test", "%70rivate-value.test", "bad..private-value.test",
                      "host.test,[fe80::1%private-value]", None, 1, "x" * 16385):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(ProxyConfigurationError) as raised:
                direct_hosts_from_env({"SIGNALWATCH_PROXY_DIRECT_HOSTS": value})
            self.assertNotIn("private-value", str(raised.exception))

    def test_invalid_direct_host_does_not_leak_value_through_exception_chain(self):
        env = {"SIGNALWATCH_PROXY_DIRECT_HOSTS": "user:private-value@host.test"}
        try:
            direct_hosts_from_env(env)
        except ProxyConfigurationError as error:
            self.assertNotIn("private-value", "".join(traceback.format_exception(error)))
        else:
            self.fail("Invalid direct host was accepted")


class ProxyConfigurationTests(unittest.TestCase):
    def pool(self, entries, **env):
        return ProxyPool.from_env({"SIGNALWATCH_PROXY_LIST_JSON": json.dumps(entries), **env})

    def test_disabled_without_environment(self):
        self.assertIsNone(ProxyPool.from_env({}))

    def test_imported_objects_use_entrypoint_and_port_not_exit_ip(self):
        pool = self.pool([{"entryPoint": "proxy.example.test", "port": 8040,
                           "ip": "192.0.2.19", "countryCode": "US"}])
        self.assertEqual(pool.choose().url, "http://proxy.example.test:8040")

    def test_canonicalizes_and_deduplicates_supported_authorities(self):
        pool = self.pool(["PROXY.example.test:80", "http://proxy.example.test",
                          "https://secure.example.test", "[2001:db8::1]:8080",
                          {"entryPoint": "2001:db8::1", "port": "8080"}])
        self.assertEqual([pool.choose().url for _ in range(4)], [
            "http://proxy.example.test:80", "https://secure.example.test:443",
            "http://[2001:db8::1]:8080", "http://proxy.example.test:80",
        ])

    def test_credentials_are_separate_and_hidden_from_repr(self):
        pool = self.pool(["proxy.example.test:8080"], SIGNALWATCH_PROXY_USERNAME="test-user",
                         SIGNALWATCH_PROXY_PASSWORD="test-password=")
        endpoint = pool.choose()
        self.assertEqual(endpoint.auth.login, "test-user")
        self.assertEqual(endpoint.auth.password, "test-password=")
        self.assertNotIn("test-user", endpoint.url)
        self.assertNotIn("test-password", repr(endpoint))
        self.assertNotIn("test-password", repr(pool))

    def test_cache_key_is_stable_for_normalized_endpoint_set_without_credentials(self):
        original = self.pool(["FIRST.example.test:80", "second.example.test:8080"])
        reordered = self.pool(["second.example.test:8080", "http://first.example.test", "first.example.test:80"],
                              SIGNALWATCH_PROXY_USERNAME="test-user", SIGNALWATCH_PROXY_PASSWORD="test-password")
        different = self.pool(["different.example.test:8080"])
        self.assertEqual(original.cache_key, reordered.cache_key)
        self.assertNotEqual(original.cache_key, different.cache_key)
        self.assertRegex(original.cache_key, r"^[0-9a-f]{64}$")
        with self.assertRaises(AttributeError):
            original.cache_key = "replacement"

    def test_partial_or_orphaned_credentials_fail_closed(self):
        for env in ({"SIGNALWATCH_PROXY_USERNAME": "test-user"},
                    {"SIGNALWATCH_PROXY_PASSWORD": "test-password"},
                    {"SIGNALWATCH_PROXY_USERNAME": "test-user", "SIGNALWATCH_PROXY_PASSWORD": "test-password"}):
            with self.subTest(keys=list(env)), self.assertRaises(ProxyConfigurationError):
                ProxyPool.from_env(env)

    def test_invalid_credentials_are_sanitized(self):
        for username, password in (("test:user", "test-password"), ("test-user", "test\npassword"),
                                   ("test-user", "\u2603")):
            with self.subTest(username=username), self.assertRaises(ProxyConfigurationError) as raised:
                self.pool(["proxy.example.test:8080"], SIGNALWATCH_PROXY_USERNAME=username,
                          SIGNALWATCH_PROXY_PASSWORD=password)
            self.assertEqual(str(raised.exception), "Invalid proxy credentials")

    def test_rejects_ambiguous_or_unsafe_authorities(self):
        invalid = ["http://test-user:test-password@proxy.example.test:80", "proxy.example.test",
                   "socks5://proxy.example.test:80", "http://proxy.example.test:80/",
                   "http://proxy.example.test:80?", "http://proxy.example.test:80#",
                   "http://proxy.example.test:", "http://proxy.example.test:0",
                   "http://proxy.example.test:65536", "http://proxy.example.test:-1",
                   "http://proxy.example.test:abc", "http://bad host:80",
                   "http://bad\nhost:80", "http://%65xample.test:80",
                   "http://[2001:db8::1]ignored:80", "http://[fe80::1%eth0]:80",
                   "http://999.1.2.3:80", "http://-bad.test:80", "http://bad..test:80",
                   "http://" + "a" * 64 + ".test:80", "2001:db8::1:80", 123,
                   {"entryPoint": "proxy.example.test", "port": True},
                   {"entryPoint": "http://proxy.example.test", "port": 80},
                   {"entryPoint": "proxy.example.test:80", "port": 80},
                   {"entryPoint": "[proxy.example.test]", "port": 80},
                   {"entryPoint": "[192.0.2.1]", "port": 80},
                   {"entryPoint": "proxy.example.test", "port": 1.5}, {}]
        for entry in invalid:
            with self.subTest(entry=entry), self.assertRaises(ProxyConfigurationError) as raised:
                self.pool([entry])
            self.assertNotIn("test-password", str(raised.exception))
            self.assertNotIn("proxy.example.test", str(raised.exception))

    def test_invalid_object_does_not_leak_input_in_traceback(self):
        entry = {"entryPoint": "user:private-password@proxy.example.test", "port": 80}
        try:
            self.pool([entry])
        except ProxyConfigurationError as error:
            self.assertNotIn("private-password", "".join(traceback.format_exception(error)))
        else:
            self.fail("Invalid endpoint was accepted")

    def test_file_and_inline_are_mutually_exclusive(self):
        with self.assertRaises(ProxyConfigurationError):
            ProxyPool.from_env({"SIGNALWATCH_PROXY_LIST_JSON": "[]", "SIGNALWATCH_PROXY_LIST_FILE": "unused"})

    def test_file_import_and_size_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "proxies.json"
            path.write_text(json.dumps(["proxy.example.test:8080"]))
            self.assertEqual(ProxyPool.from_env({"SIGNALWATCH_PROXY_LIST_FILE": str(path)}).choose().url,
                             "http://proxy.example.test:8080")
            path.write_bytes(b" " * (MAX_PROXY_BYTES + 1))
            with self.assertRaisesRegex(ProxyConfigurationError, "size limit"):
                ProxyPool.from_env({"SIGNALWATCH_PROXY_LIST_FILE": str(path)})
        with self.assertRaises(ProxyConfigurationError) as raised:
            ProxyPool.from_env({"SIGNALWATCH_PROXY_LIST_FILE": "/missing/private-proxy-path"})
        self.assertNotIn("private-proxy-path", str(raised.exception))

    def test_json_shape_and_bounds(self):
        for raw in ("{\"password\":\"private-value\"", "null", "{}", "[]", "[\"proxy.example.test:80\",]",
                    json.dumps(["proxy.example.test:80"] * 257), " " * (MAX_PROXY_BYTES + 1),
                    "[" * 2000 + "]" * 2000):
            with self.subTest(length=len(raw)), self.assertRaises(ProxyConfigurationError) as raised:
                ProxyPool.from_env({"SIGNALWATCH_PROXY_LIST_JSON": raw})
            self.assertNotIn("private-value", str(raised.exception))
        self.assertIsNotNone(self.pool(["proxy.example.test:80"] * 256))


class ProxySelectionTests(unittest.TestCase):
    def setUp(self):
        self.now = 100.0
        self.pool = ProxyPool.from_env({"SIGNALWATCH_PROXY_LIST_JSON": json.dumps([
            "first.example.test:8080", "second.example.test:8080", "third.example.test:8080",
        ])}, clock=lambda: self.now)
        self.first, self.second, self.third = [self.pool.choose() for _ in range(3)]

    def test_round_robin_and_exclusions(self):
        self.assertEqual(self.pool.choose(exclude=[self.first]), self.second)
        self.assertEqual(self.pool.choose(exclude=[self.third.url]), self.first)
        with self.assertRaises(ProxyUnavailableError) as raised:
            self.pool.choose(exclude=[self.first, self.second, self.third])
        self.assertIsNone(raised.exception.retry_after)

    def test_cooling_endpoints_are_skipped_and_recover(self):
        self.pool.fail(self.first, 60)
        self.pool.fail(self.second, 10)
        self.pool.fail(self.third, 20)
        with self.assertRaises(ProxyUnavailableError) as raised:
            self.pool.choose()
        self.assertEqual(raised.exception.retry_after, 10)
        with self.assertRaises(ProxyUnavailableError) as raised:
            self.pool.choose(exclude=[self.second])
        self.assertEqual(raised.exception.retry_after, 20)
        self.now += 10
        self.assertEqual(self.pool.choose(), self.second)
        self.now += 50
        self.assertEqual(self.pool.choose(), self.third)
        self.assertEqual(self.pool.choose(), self.first)

    def test_repeated_failure_does_not_shorten_cooldown(self):
        self.pool.fail(self.first)
        self.pool.fail(self.first, 1)
        with self.assertRaises(ProxyUnavailableError) as raised:
            self.pool.choose(exclude=[self.second, self.third])
        self.assertEqual(raised.exception.retry_after, 60)

    def test_authentication_rejection_disables_entire_pool(self):
        self.pool.reject_auth()
        self.now += 10000
        with self.assertRaisesRegex(ProxyUnavailableError, "authentication was rejected") as raised:
            self.pool.choose()
        self.assertIsNone(raised.exception.retry_after)

    def test_provider_cooldown_applies_to_every_endpoint(self):
        self.pool.defer(90)
        self.pool.defer(10)
        with self.assertRaises(ProxyUnavailableError) as raised:
            self.pool.choose()
        self.assertEqual(raised.exception.retry_after, 90)
        self.now += 20
        with self.assertRaises(ProxyUnavailableError) as raised:
            self.pool.choose(exclude=[self.first])
        self.assertEqual(raised.exception.retry_after, 70)
        self.now += 70
        self.assertEqual(self.pool.choose(), self.first)

    def test_retained_endpoint_rechecks_auth_and_longest_cooldown_without_rotating(self):
        self.pool.ensure_available(self.first)
        self.pool.fail(self.first, 120)
        self.pool.defer(60)
        with self.assertRaises(ProxyUnavailableError) as raised:
            self.pool.ensure_available(self.first)
        self.assertEqual(raised.exception.retry_after, 120)
        with self.assertRaises(ProxyUnavailableError) as raised:
            self.pool.ensure_available(self.second)
        self.assertEqual(raised.exception.retry_after, 60)
        self.now += 120
        self.pool.ensure_available(self.first)
        self.assertEqual(self.pool.choose(), self.first)
        self.pool.reject_auth()
        with self.assertRaisesRegex(ProxyUnavailableError, "authentication was rejected"):
            self.pool.ensure_available(self.first)

    def test_invalid_cooldowns_are_rejected(self):
        for value in (-1, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.pool.fail(self.first, value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.pool.defer(value)


if __name__ == "__main__":
    unittest.main()
