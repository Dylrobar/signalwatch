"""Bound per-source cleanup by its edges, not the entire company catalogue."""

import json
import unittest

from signalwatch.store import Store
from signalwatch.technographic_store import _detach_sources
from signalwatch.text_signals import refresh_company_resolution


class IdentityBackfillScalingTests(unittest.TestCase):
    def measure(self, company_count, operation):
        store = Store(":memory:")
        self.addCleanup(store._keeper.close)
        with store.connection(write=True) as conn:
            conn.executemany("INSERT INTO entities VALUES(?,?,?,?,?,?,?,?,?)", [
                ("company:" + str(index), "company", "Company " + str(index), "", "{}", "now", "", 1, "now")
                for index in range(company_count)
            ] + [("source:one", "article", "Source", "", "{}", "now", "https://publisher.example.net/", 1, "now"),
                 ("technology:one", "technology", "Technology", "", "{}", "now", "", 1, "now")])
            prepare, execute, verify = operation(store, conn)
            prepare()
            ticks = 0

            def progress():
                nonlocal ticks
                ticks += 1
                return 0

            conn.set_progress_handler(progress, 1)
            try:
                execute()
            finally:
                conn.set_progress_handler(None, 0)
            verify()
            return ticks

    def assert_bounded(self, operation):
        small = self.measure(1000, operation)
        large = self.measure(10000, operation)
        # SQLite VM work is deterministic enough to catch catalogue scans
        # without relying on machine speed or fragile EXPLAIN wording.
        self.assertLessEqual(large, max(2000, small * 2), (small, large))

    def test_source_detachment_probes_only_linked_company_identities(self):
        def operation(store, conn):
            def prepare():
                conn.executemany("INSERT INTO edges VALUES(?,?,?,?,?,?)", [
                    (owner, "source:one", relation, "", "now", 1)
                    for owner in ("company:0", "company:1", "technology:one")
                    for relation in ("has_public_evidence", "candidate_evidence", "unrelated")
                ])

            def execute():
                _detach_sources(store, conn, "source:one", "company:1", None, "now")

            def verify():
                rows = {(row[0], row[1]) for row in conn.execute("SELECT from_id,relation FROM edges")}
                for relation in ("has_public_evidence", "candidate_evidence"):
                    self.assertNotIn(("company:0", relation), rows)
                    self.assertIn(("company:1", relation), rows)
                    self.assertIn(("technology:one", relation), rows)
                self.assertIn(("company:0", "unrelated"), rows)

            return prepare, execute, verify

        self.assert_bounded(operation)

    def test_cached_text_refresh_probes_only_article_mention_identities(self):
        def operation(store, conn):
            def prepare():
                conn.execute("INSERT INTO articles VALUES(?,?,?,?,?,?,?,?,?)", (
                    "source:one", "https://publisher.example.net/", "Source", "Body", None, "Fixture", "[]", "{}", "now"))
                extraction = {"mentions": [{"entity_id": owner, "status": "resolved", "confidence": 1}
                                           for owner in ("company:0", "technology:one")]}
                conn.execute("INSERT INTO text_signals VALUES(?,?,?,?,?)", (
                    "source:one", "hash", "old", json.dumps(extraction), "now"))
                conn.executemany("INSERT INTO signal_mentions VALUES(?,?,?,?,?,?)", [
                    ("source:one", owner, "resolved", "Quoted mention", 1, "https://publisher.example.net/")
                    for owner in ("company:0", "technology:one")])
                conn.executemany("INSERT INTO edges VALUES(?,?,?,?,?,?)", [
                    ("source:one", owner, "text_mentions", "https://publisher.example.net/", "now", 1)
                    for owner in ("company:0", "technology:one")])

            def execute():
                refresh_company_resolution(store, conn)

            def verify():
                mentions = dict(conn.execute("SELECT entity_id,status FROM signal_mentions"))
                self.assertEqual(mentions, {"company:0": "candidate", "technology:one": "resolved"})
                edges = {(row[0], row[1]) for row in conn.execute("SELECT to_id,relation FROM edges WHERE from_id='source:one'")}
                self.assertNotIn(("company:0", "text_mentions"), edges)
                self.assertIn(("company:0", "candidate_mention"), edges)
                self.assertIn(("technology:one", "text_mentions"), edges)

            return prepare, execute, verify

        self.assert_bounded(operation)


if __name__ == "__main__":
    unittest.main()
