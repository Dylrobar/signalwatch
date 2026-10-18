import asyncio
import json
import socket
import tempfile
import unittest
from pathlib import Path
from urllib.parse import urlencode
from unittest.mock import AsyncMock

from signalwatch.dns import DNSResolver, DNSResult, parse_answer
from signalwatch.http import FetchResult


def reply(name, query_type, answers=None, status=0):
    return {"Status": status, "Question": [{"name": name + ".", "type": query_type}], "Answer": answers or [], "Authority": [{"name": "example.", "type": 6, "TTL": 60, "data": "ns.example. hostmaster.example. 1 60 60 60 60"}]}


def address(name, value="192.0.2.1", ttl=60, query_type=1):
    return {"name": name + ".", "type": query_type, "TTL": ttl, "data": value}


class FixtureHTTP:
    def __init__(self, directory, responses=None):
        self.directory = Path(directory)
        self.responses = responses or {}
        self.calls = []
        self.active = 0
        self.peak = 0

    async def get(self, url, **options):
        params = options["params"]
        self.calls.append((url, options))
        self.active += 1
        self.peak = max(self.peak, self.active)
        sequence = len(self.calls)
        try:
            await asyncio.sleep(.001)
            name, family = params["name"], params["type"]
            value = self.responses.get((name, family), reply(name, family, [address(name)] if family == 1 else []))
            if isinstance(value, Exception):
                raise value
            path = self.directory / f"query-{sequence}.json"
            path.write_text(json.dumps(value))
            return FetchResult(path, 200, {}, url + "?" + urlencode(params), True, str(sequence))
        finally:
            self.active -= 1


class DNSParsingTests(unittest.TestCase):
    def test_answer_owner_and_cname_chain_and_http_age_bound_cache_ttl(self):
        response = reply("www.example", 1, [
            {"name": "www.example.", "type": 5, "TTL": 30, "data": "cdn.example."},
            address("cdn.example", "192.0.2.1", 60),
            address("unrelated.example", "192.0.2.99", 60),
            address("cdn.example", "2001:db8::1", 60, 28),
        ])
        result = parse_answer(response, "www.example", 1, "https://dns.google/resolve", "https://dns.google/resolve?name=www.example&type=A", "2026-10-18T12:00:00+00:00", {"Age": "10", "Cache-Control": "public, max-age=15"})
        self.assertEqual([record["value"] for record in result["records"]], ["cdn.example", "192.0.2.1"])
        self.assertEqual(result["records"][0]["ttl"], 30)
        self.assertEqual(result["records"][0]["remaining_ttl"], 20)
        self.assertEqual(result["ttl"], 5)

    def test_nxdomain_discards_answers_and_servfail_is_error(self):
        negative = parse_answer(reply("missing.example", 1, [address("missing.example")], 3), "missing.example", 1, "resolver", "query", "now")
        self.assertEqual(negative["records"], [])
        self.assertEqual(negative["errors"], [])
        self.assertEqual(negative["status"], "NXDOMAIN")
        failure = parse_answer(reply("missing.example", 1, [address("missing.example")], 2), "missing.example", 1, "resolver", "query", "now")
        self.assertEqual(failure["records"], [])
        self.assertIn("SERVFAIL", failure["errors"][0])

    def test_wrong_family_and_mismatched_question_rejected(self):
        response = reply("example.com", 28, [address("example.com", "192.0.2.1", 60, 28)])
        result = parse_answer(response, "example.com", 28, "resolver", "query", "now")
        self.assertEqual(result["records"], [])
        self.assertIn("Invalid AAAA", result["errors"][0])
        with self.assertRaises(ValueError):
            parse_answer(response, "other.example", 28, "resolver", "query", "now")
        invalid_data = reply("example.com", 1, [address("example.com", value=1)])
        self.assertEqual(parse_answer(invalid_data, "example.com", 1, "resolver", "query", "now")["records"], [])
        response["Status"] = False
        with self.assertRaises(ValueError):
            parse_answer(response, "example.com", 28, "resolver", "query", "now")

    def test_ttl_zero_and_no_store_are_not_clamped_positive(self):
        response = reply("example.com", 1, [address("example.com", ttl=0)])
        self.assertEqual(parse_answer(response, "example.com", 1, "resolver", "query", "now")["ttl"], 0)
        response["Answer"][0]["TTL"] = 60
        self.assertEqual(parse_answer(response, "example.com", 1, "resolver", "query", "now", {"Cache-Control": "no-store"})["ttl"], 0)
        self.assertEqual(parse_answer(response, "example.com", 1, "resolver", "query", "now", {"Age": "90"})["ttl"], 0)


class DNSResolutionTests(unittest.IsolatedAsyncioTestCase):
    async def test_system_success_does_not_request_doh(self):
        with tempfile.TemporaryDirectory() as folder:
            http = FixtureHTTP(folder)
            resolver = DNSResolver({"dns_mode": "fallback"}, http)
            result = DNSResult([{"name": "example.com", "type": "A", "value": "192.0.2.1", "ttl": None, "resolver": "system", "observed_at": "now"}], [], {"system": "NOERROR"}, "now", "system")
            resolver._system = AsyncMock(return_value=result)
            self.assertIs(await resolver.resolve("EXAMPLE.COM."), result)
            self.assertEqual(http.calls, [])

    async def test_system_failure_recovers_through_doh_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            http = FixtureHTTP(folder)
            resolver = DNSResolver({"dns_mode": "fallback"}, http)
            resolver._system = AsyncMock(side_effect=socket.gaierror("resolver unavailable"))
            result = await resolver.resolve("example.com")
            self.assertEqual(result.errors, [])
            self.assertIn("resolver unavailable", result.system_error)
            self.assertEqual(result.mode, "doh")
            self.assertEqual(resolver.errors, {})
            entities, edges = result.graph("example.com", "https://example.com/")
            self.assertEqual(entities[0]["value"], "192.0.2.1")
            self.assertEqual(entities[0]["metadata"]["dns"]["ttl"], 60)
            self.assertIn("name=example.com", edges[0]["source_url"])
            self.assertIn("edns_client_subnet=0.0.0.0%2F0", edges[0]["source_url"])
            self.assertEqual(edges[0]["relation"], "resolves_to")
            for _, options in http.calls:
                self.assertFalse(options["cache"])
                self.assertEqual(options["params"]["edns_client_subnet"], "0.0.0.0/0")

    async def test_one_family_failure_keeps_other_family_and_exposes_error(self):
        with tempfile.TemporaryDirectory() as folder:
            http = FixtureHTTP(folder, {("example.com", 28): reply("example.com", 28, status=2)})
            resolver = DNSResolver({"dns_mode": "doh"}, http)
            result = await resolver.resolve("example.com")
            self.assertTrue(any(record["value"] == "192.0.2.1" for record in result.records))
            self.assertIn("example.com AAAA: SERVFAIL", result.errors[0])
            self.assertEqual(resolver.errors["example.com"], result.errors)
            self.assertFalse(result.complete)
            self.assertNotIn("example.com", resolver.cache)

    async def test_ip_literals_do_not_query_dns_or_create_dns_edges(self):
        with tempfile.TemporaryDirectory() as folder:
            http = FixtureHTTP(folder)
            resolver = DNSResolver({"dns_mode": "fallback"}, http)
            resolver._system = AsyncMock()
            result = await resolver.resolve("2001:0db8::1")
            entities, edges = result.graph("2001:0db8::1", "https://[2001:db8::1]/")
            self.assertEqual(entities[0]["value"], "2001:db8::1")
            self.assertEqual(edges, [])
            resolver._system.assert_not_awaited()
            self.assertEqual(http.calls, [])

    async def test_cname_followup_only_accepts_answer_records(self):
        with tempfile.TemporaryDirectory() as folder:
            http = FixtureHTTP(folder, {
                ("www.example", 1): reply("www.example", 1, [{"name": "www.example.", "type": 5, "TTL": 20, "data": "cdn.example."}]),
                ("www.example", 28): reply("www.example", 28),
                ("cdn.example", 1): reply("cdn.example", 1, [address("cdn.example", "192.0.2.10"), address("unrelated.example", "192.0.2.99")]),
            })
            resolver = DNSResolver({"dns_mode": "doh"}, http)
            result = await resolver.resolve("www.example")
            self.assertEqual(result.errors, [])
            self.assertEqual([record["value"] for record in result.records if record["type"] == "A"], ["192.0.2.10"])
            _, edges = result.graph("www.example", "https://www.example/")
            self.assertTrue(any(edge["relation"] == "cname_to" for edge in edges))
            self.assertLessEqual(result.ttl, 20)

    async def test_cache_expiry_and_zero_ttl_require_fresh_queries(self):
        with tempfile.TemporaryDirectory() as folder:
            http = FixtureHTTP(folder)
            resolver = DNSResolver({"dns_mode": "doh"}, http)
            first = await resolver.resolve("example.com")
            second = await resolver.resolve("example.com")
            self.assertTrue(second.cached)
            self.assertEqual(first.observed_at, second.observed_at)
            self.assertEqual(len(http.calls), 2)
            resolver.cache["example.com"] = (0, first)
            self.assertFalse((await resolver.resolve("example.com")).cached)
            self.assertEqual(len(http.calls), 4)
            http.responses[("zero.example", 1)] = reply("zero.example", 1, [address("zero.example", ttl=0)])
            await resolver.resolve("zero.example")
            await resolver.resolve("zero.example")
            self.assertEqual(len(http.calls), 8)

    async def test_doh_workers_are_bounded_before_http_requests(self):
        with tempfile.TemporaryDirectory() as folder:
            http = FixtureHTTP(folder)
            resolver = DNSResolver({"dns_mode": "doh", "dns_concurrency": 3}, http)
            await asyncio.gather(*(resolver.resolve(f"host{index}.example") for index in range(20)))
            self.assertLessEqual(http.peak, 3)
            self.assertEqual(len(http.calls), 40)
