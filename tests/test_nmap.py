import asyncio
import hashlib
import json
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient

from signalwatch.api import create_app
from signalwatch.config import load_config
from signalwatch.engine import Engine
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.nmap import PROFILES, collect_nmap, parse_nmap_xml, scan_documents, scan_options
from signalwatch.normalization import NormalizationError, normalize
from signalwatch.store import Store


XML = (Path(__file__).parent / "fixtures/nmap/services.xml").read_bytes()
STAMP = "2026-10-19T06:00:00+00:00"


class NmapXMLTests(unittest.TestCase):
    def item(self, payload=XML):
        return {"id": 1, "source": "nmap", "adapter": "nmap_xml", "payload": payload,
                "payload_hash": hashlib.sha256(payload).hexdigest(), "received_at": STAMP, "metadata": {}}

    def test_xml_maps_exact_open_ports_banners_and_cpes_with_edges(self):
        batch = normalize(self.item())
        by_kind = {}
        for entity in batch["entities"]:
            by_kind.setdefault(entity["kind"], []).append(entity)
            self.assertEqual(entity["metadata"]["staging"]["raw_reference"], "staging:1")
        self.assertEqual({kind: len(rows) for kind, rows in by_kind.items()}, {"ip": 2, "open_port": 3, "service_banner": 2, "cpe_product": 3})
        self.assertEqual({entity["value"] for entity in by_kind["open_port"]}, {"tcp://192.0.2.10:22", "tcp://192.0.2.10:443", "udp://[2001:db8::10]:53"})
        self.assertEqual({entity["value"] for entity in by_kind["service_banner"]}, {"ssh OpenSSH 9.6p1 Ubuntu", "http nginx 1.24.0"})
        nginx = next(entity for entity in by_kind["cpe_product"] if entity["metadata"]["product"] == "nginx")
        self.assertEqual((nginx["metadata"]["vendor"], nginx["metadata"]["version"], nginx["confidence"]), ("nginx", "1.24.0", 0.9))
        linux = next(entity for entity in by_kind["cpe_product"] if entity["metadata"]["part"] == "o")
        self.assertEqual(linux["metadata"]["version"], "*")
        ids = {entity["id"] for entity in batch["entities"]}
        self.assertTrue(all(edge["from_id"] in ids and edge["to_id"] in ids for edge in batch["edges"]))
        self.assertEqual([edge["relation"] for edge in batch["edges"]].count("has_open_port"), 3)
        self.assertEqual([edge["relation"] for edge in batch["edges"]].count("has_service_banner"), 2)
        self.assertEqual([edge["relation"] for edge in batch["edges"]].count("identifies_product"), 3)
        self.assertEqual(normalize(self.item()), batch)

    def test_table_lookup_does_not_create_a_banner_or_product(self):
        batch = parse_nmap_xml(b'<nmaprun><host><address addr="192.0.2.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" method="table" conf="3"/></port></ports></host></nmaprun>', STAMP)
        self.assertEqual([row["kind"] for row in batch["entities"]], ["ip", "open_port"])

    def test_invalid_xml_run_state_addresses_ports_and_limits(self):
        for payload in [b'<nmaprun>', b'<rss/>', b'<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>', XML.replace(b'portid="22"', b'portid="65536"'), XML.replace(b'addr="192.0.2.10"', b'addr="invalid"')]:
            with self.subTest(payload=payload[:80]), self.assertRaises(NormalizationError):
                normalize(self.item(payload))
        with self.assertRaisesRegex(NormalizationError, "record limit"):
            normalize(self.item(), max_records=5)
        self.assertEqual(parse_nmap_xml(b'<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>', STAMP), {"entities": [], "edges": []})

    def test_large_full_scan_splits_without_dropping_ports(self):
        root = ET.fromstring('<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><ports/></host></nmaprun>')
        ports = root.find("host/ports")
        for number in range(1, 2501):
            ports.append(ET.fromstring(f'<port protocol="tcp" portid="{number}"><state state="open"/><service name="http" product="nginx" method="probed"><cpe>cpe:/a:nginx:nginx:1.24</cpe></service></port>'))
        documents = list(scan_documents(root))
        self.assertGreater(len(documents), 1)
        normalized = [normalize(self.item(payload)) for payload in documents]
        self.assertTrue(all(sum(map(len, batch.values())) <= 5000 for batch in normalized))
        self.assertEqual(sum(row["kind"] == "open_port" for batch in normalized for row in batch["entities"]), 2500)


class NmapCollectorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.config = load_config(Path(self.directory.name) / "config.json")
        self.config["provider_settings"]["nmap"]["targets"] = ["192.0.2.10"]
        self.store = Store(self.config["db"])
        self.commands = []
        self.processes = []

    async def spawn(self, *command, **options):
        self.commands.append((command, options))
        Path(command[command.index("-oX") + 1]).write_bytes(XML)
        process = SimpleNamespace(returncode=0, communicate=AsyncMock(return_value=(b"", b"")))
        self.processes.append(process)
        return process

    async def test_all_profiles_execute_without_shell_and_ingest_original_xml(self):
        for profile in PROFILES:
            self.config["provider_settings"]["nmap"]["profile"] = profile
            self.config["provider_settings"]["nmap"]["targets"] = ["192.0.2.10", "192.0.2.10", "example.test"]
            with patch("signalwatch.nmap.shutil.which", return_value="/usr/bin/nmap"), patch("signalwatch.nmap.asyncio.create_subprocess_exec", side_effect=self.spawn):
                result = await collect_nmap(self.config, self.store, None)
            command, options = self.commands[-1]
            self.assertEqual(command[0:3], ("/usr/bin/nmap", "-sT", "-n"))
            self.assertTrue(all(argument in command for argument in PROFILES[profile]))
            self.assertNotIn("shell", options)
            self.assertEqual((result["targets"], result["scans"], result["staged"]), (2, 1, 2))
            self.assertEqual(result["errors"], [])
            report = StagingWorker(self.store, self.config).drain(reconcile=False)
            self.assertEqual((report["processed"], report["dead"]), (2, 0))
        self.assertEqual(self.store.search(kind="open_port")["total"], 3)
        self.assertEqual(self.store.search(kind="service_banner")["total"], 2)
        self.assertEqual(self.store.search(kind="cpe_product")["total"], 3)
        self.assertEqual(self.store.stats()["observations"], 0)

    async def test_mixed_families_use_two_batched_processes(self):
        self.config["provider_settings"]["nmap"]["targets"] = ["192.0.2.10", "198.51.100.1/24", "2001:db8::1", "2001:db8:1::/64"]
        target_files = []

        async def spawn(*command, **options):
            target_files.append(Path(command[command.index("-iL") + 1]).read_text())
            return await self.spawn(*command, **options)

        with patch("signalwatch.nmap.shutil.which", return_value="/usr/bin/nmap"), patch("signalwatch.nmap.asyncio.create_subprocess_exec", side_effect=spawn):
            result = await collect_nmap(self.config, self.store, None)
        self.assertEqual(result["scans"], 2)
        self.assertEqual(target_files, ["192.0.2.10\n198.51.100.0/24\n", "2001:db8::1\n2001:db8:1::/64\n"])
        self.assertNotIn("-6", self.commands[0][0])
        self.assertIn("-6", self.commands[1][0])

    async def test_missing_targets_skip_and_missing_binary_fails(self):
        self.config["provider_settings"]["nmap"]["targets"] = []
        with patch("signalwatch.nmap.asyncio.create_subprocess_exec") as spawn:
            result = await collect_nmap(self.config, self.store, None)
        spawn.assert_not_called()
        self.assertEqual(result["provider_health"]["nmap"]["status"], "unconfigured")
        self.config["provider_settings"]["nmap"]["targets"] = ["192.0.2.10"]
        with patch("signalwatch.nmap.shutil.which", return_value=None), self.assertRaisesRegex(RuntimeError, "unavailable"):
            await collect_nmap(self.config, self.store, None)

    async def test_timeout_and_cancellation_kill_and_reap_process(self):
        for error in [asyncio.TimeoutError(), asyncio.CancelledError()]:
            process = SimpleNamespace(returncode=None, communicate=AsyncMock(side_effect=[error, (b"", b"")]), kill=lambda: None)
            process.kill = unittest.mock.Mock()
            with patch("signalwatch.nmap.shutil.which", return_value="/usr/bin/nmap"), patch("signalwatch.nmap.asyncio.create_subprocess_exec", new=AsyncMock(return_value=process)):
                if isinstance(error, asyncio.CancelledError):
                    with self.assertRaises(asyncio.CancelledError):
                        await collect_nmap(self.config, self.store, None)
                else:
                    result = await collect_nmap(self.config, self.store, None)
                    self.assertEqual(result["provider_health"]["nmap"]["status"], "error")
                    self.assertIn("TimeoutError", result["errors"][0])
            process.kill.assert_called_once()
            self.assertEqual(process.communicate.await_count, 2)

    async def test_engine_routes_nmap_collector(self):
        engine = Engine(self.config, self.store)
        engine.collector = SimpleNamespace(http=None)
        with patch("signalwatch.engine.collect_nmap", new=AsyncMock(return_value={"records": 1})) as collector:
            self.assertEqual(await engine._collect_source("nmap"), {"records": 1})
        collector.assert_awaited_once_with(self.config, self.store, None)

    async def test_failed_process_and_unresolved_targets_are_errors(self):
        for returncode, xml in [(2, XML), (0, b'<nmaprun><runstats><finished exit="success"/><hosts total="0"/></runstats></nmaprun>')]:
            async def spawn(*command, **options):
                process = await self.spawn(*command, **options)
                process.returncode = returncode
                Path(command[command.index("-oX") + 1]).write_bytes(xml)
                return process

            with patch("signalwatch.nmap.shutil.which", return_value="/usr/bin/nmap"), patch("signalwatch.nmap.asyncio.create_subprocess_exec", side_effect=spawn):
                result = await collect_nmap(self.config, self.store, None)
            self.assertEqual(result["provider_health"]["nmap"]["status"], "error")
            self.assertEqual(result["staged"], 0)
            self.assertEqual(staging_queue(self.store, self.config).stats()["counts"]["pending"], 0)

    async def test_zero_open_ports_is_a_successful_scan(self):
        async def spawn(*command, **options):
            process = await self.spawn(*command, **options)
            Path(command[command.index("-oX") + 1]).write_bytes(b'<nmaprun><runstats><finished exit="success"/><hosts up="1" total="1"/></runstats></nmaprun>')
            return process

        with patch("signalwatch.nmap.shutil.which", return_value="/usr/bin/nmap"), patch("signalwatch.nmap.asyncio.create_subprocess_exec", side_effect=spawn):
            result = await collect_nmap(self.config, self.store, None)
        self.assertEqual((result["scans"], result["staged"]), (1, 0))
        self.assertEqual(result["provider_health"]["nmap"]["status"], "healthy")


class NmapSettingsTests(unittest.TestCase):
    def test_target_validation_and_profile_options(self):
        self.assertEqual(scan_options({"targets": ["EXAMPLE.TEST.", "192.0.2.1", "EXAMPLE.TEST."]})[2], ["example.test", "192.0.2.1"])
        for options in [{"profile": "bad"}, {"profile": []}, {"timeout": 0}, {"timeout": None}, {"timeout": float("inf")}, {"targets": "192.0.2.1"}, {"targets": ["-iL /tmp/file"]}, {"targets": ["example.test\n--script=all"]}, {"targets": ["192.0.2.1;touch /tmp/x"]}]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                scan_options(options)

    def test_existing_settings_api_configures_nmap_and_rejects_invalid_profiles(self):
        with tempfile.TemporaryDirectory() as folder:
            config = load_config(Path(folder) / "config.json")
            with TestClient(create_app(config, auto_collect=False)) as client:
                result = client.post("/api/sources/settings", json={"provider_settings": {"nmap": {"profile": "service_version", "targets": ["192.0.2.1"]}}})
                self.assertEqual(result.status_code, 200, result.text)
                saved = json.loads(Path(config["config_path"]).read_text())["provider_settings"]["nmap"]
                self.assertEqual(saved["profile"], "service_version")
                self.assertEqual(saved["targets"], ["192.0.2.1"])
                self.assertEqual(client.post("/api/sources/settings", json={"provider_settings": {"nmap": {"profile": "invalid"}}}).status_code, 422)
                catalog = client.get("/api/sources/catalog").json()
                self.assertTrue(next(row for row in catalog["items"] if row["id"] == "nmap")["enabled"])
