import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.config import load_config
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.store import Store


class IngestionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.config = load_config(self.root / "config.json")
        self.store = Store(self.config["db"])
        self.queue = staging_queue(self.store, self.config)
        self.worker = StagingWorker(self.store, self.config, self.queue)

    def tearDown(self):
        self.temp.cleanup()

    def test_all_required_formats_share_queue_and_existing_inventory_models(self):
        inputs = [
            ("vulnerability_json", b'{"id":"CVE-2026-97001","title":"Staged advisory","affected":[]}', {}),
            ("news", b"Staged news describes CVE-2026-97001", {"article_url": "https://news.example/staged"}),
            ("dns", b'queue.example. 300 IN TXT "v=spf1 -all"', {}),
            ("pdf_metadata", b'{"title":"Staged report","author":"Publisher","pages":12}', {}),
            ("wireless", b'MAC,SSID,channel\n02:11:22:33:44:55,Recorded network,6\n', {}),
        ]
        items = [self.queue.enqueue(payload, source=adapter, adapter=adapter, metadata=metadata,
                                    source_url="https://source.example/" + adapter)
                 for adapter, payload, metadata in inputs]
        result = self.worker.drain()
        self.assertEqual((result["claimed"], result["processed"], result["dead"]), (5, 5, 0))
        kinds = self.store.stats()["entity_kinds"]
        for kind in ("vulnerability", "article", "dns_record", "document", "wireless"):
            self.assertGreater(kinds.get(kind, 0), 0, kind)
        self.assertEqual(self.store.search(kind="company")["total"], 0)
        self.assertEqual(self.store.stats()["observations"], 0)
        for item, (_, payload, _) in zip(items, inputs):
            saved = self.queue.get(item["id"], include_payload=True)
            self.assertEqual(saved["payload"], payload)
            self.assertEqual(saved["status"], "processed")
            self.assertNotIn("payload", self.queue.get(item["id"]))

    def test_poison_input_is_retained_and_other_sources_continue(self):
        bad = self.queue.enqueue(b"{broken", source="bad-feed", adapter="vulnerability_json")
        good = self.queue.enqueue(b"unstructured text", source="other-feed", adapter="opaque")
        result = self.worker.drain()
        self.assertEqual((result["dead"], result["processed"]), (1, 1))
        self.assertEqual(self.queue.get(bad["id"], include_payload=True)["payload"], b"{broken")
        self.assertIn("JSON", self.queue.get(bad["id"])["error"])
        self.assertEqual(self.queue.get(good["id"])["status"], "processed")

    def test_transient_failure_retries_without_blocking_other_sources(self):
        bad = self.queue.enqueue(b"temporary", source="transient", adapter="opaque")
        self.queue.enqueue(b"valid", source="other", adapter="opaque")
        with patch("signalwatch.ingestion.normalize", side_effect=[RuntimeError("Temporary ingestion failure"), {"entities": []}]):
            result = self.worker.drain()
        self.assertEqual((result["retried"], result["processed"]), (1, 1))
        self.assertEqual(self.queue.get(bad["id"])["attempts"], 1)
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE raw_ingress SET available_at=0 WHERE id=?", (bad["id"],))
        self.assertEqual(self.worker.drain()["processed"], 1)
        self.assertEqual(self.queue.get(bad["id"])["attempts"], 2)

    def test_matching_failure_retries_after_ack_and_on_worker_restart(self):
        item = self.queue.enqueue(b"retained evidence", source="matching", adapter="opaque")
        with patch.object(self.store, "reconcile", side_effect=RuntimeError("Matching temporarily unavailable")):
            result = self.worker.drain()
        self.assertEqual(self.queue.get(item["id"])["status"], "processed")
        self.assertIn("matching_error", result)
        self.assertTrue(self.worker.needs_matching)
        self.assertIn("matching", self.worker.drain())
        self.assertFalse(self.worker.needs_matching)
        restarted = StagingWorker(self.store, self.config, self.queue)
        self.assertIn("matching", restarted.drain())

    def test_cli_raw_file_stage_work_and_exact_payload_export(self):
        source = self.root / "metadata.json"
        source.write_bytes(b'  {"title":"CLI staged report","pages":5}\n')
        prefix = [sys.executable, "-m", "signalwatch", "--config", str(self.root / "config.json")]
        staged = json.loads(subprocess.check_output(prefix + ["stage", str(source), "--source", "cli-test", "--adapter", "pdf_metadata"]))
        processed = json.loads(subprocess.check_output(prefix + ["staging", "work"]))
        self.assertEqual(processed["processed"], 1)
        payload = subprocess.check_output(prefix + ["staging", "show", str(staged["id"]), "--payload"])
        self.assertEqual(payload, source.read_bytes())
        self.assertEqual(self.store.search("CLI staged report", kind="document")["total"], 1)

    def test_staging_only_worker_enforces_existing_event_retention(self):
        self.config["events_max_rows"] = 1
        for number in range(3):
            self.queue.enqueue(json.dumps({"id": f"CVE-2026-{98000 + number}", "title": "Staged advisory", "affected": []}).encode(),
                               source="history", adapter="vulnerability_json")
        result = self.worker.drain()
        self.assertEqual(result["processed"], 3)
        self.assertEqual(result["events_pruned"], 2)
        self.assertEqual(self.store.events()["total"], 1)
