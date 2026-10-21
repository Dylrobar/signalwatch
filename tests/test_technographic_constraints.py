import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.store import SCHEMA, Store
from signalwatch.reviews import ensure_schema as ensure_review_schema
from signalwatch.technographic_constraints import ensure_constraints
from signalwatch.technographic_store import SCHEMA as TECH_SCHEMA


class TechnographicConstraintsTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.addCleanup(self.conn.close)
        self.conn.executescript(SCHEMA + TECH_SCHEMA)
        ensure_review_schema(self.conn)
        for name, kind in (("company:a", "company"), ("company:b", "company"), ("domain:x", "domain"),
                           ("raw:a", "job_posting"), ("raw:b", "job_posting"), ("raw:shared", "job_posting")):
            self.conn.execute("INSERT INTO entities(id,kind,name,value,updated_at) VALUES(?,?,?,?,?)", (name, kind, name, name, "now"))

    def document(self, key, company):
        self.conn.execute("INSERT INTO technographic_documents VALUES(?,?,?,?,?,?,?,?)", (key, company, key, "Title", "Raw excerpt", None, "now", "now"))

    def source(self, key, company, document):
        self.conn.execute("INSERT INTO technographic_sources VALUES(?,?,?,?,?,?,?,?,?)", (company, key, document, "https://example.test/" + key, key, "endpoint", "posting", "now", "now"))

    def fingerprint(self, key, company, document):
        self.conn.execute("""INSERT INTO tech_fingerprints(id,organization_id,document_id,vendor,product,vendor_name,product_name,
         category,part,status,confidence,evidence_snippet,method,first_seen_at,last_seen_at)
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (key, company, document, "vendor", "product", "Vendor", "Product", "Database", "a", "asserted_use", 0.9, "We use Product", "parser", "now", "now"))

    def observation(self, key, company, document, source):
        self.conn.execute("""INSERT INTO observations(id,asset_id,vendor,product,vendor_name,product_name,source_url,observed_at,raw,origin)
         VALUES(?,?,?,?,?,?,?,?,?,?)""", (key, company, "vendor", "product", "Vendor", "Product", "https://example.test/" + source, "now", "{}", "technographic:" + document))

    def alert(self, key, company):
        self.conn.execute("""INSERT INTO alerts(id,asset_id,advisory_id,rank,confidence,reasons,first_seen,last_seen,checked_token)
         VALUES(?,?,?,?,?,?,?,?,?)""", (key, company, "CVE-2026-1234", 1, 0.9, "[]", "now", "now", "old"))

    def valid_pair(self):
        for suffix in ("a", "b"):
            self.document("doc:" + suffix, "company:" + suffix)
            self.source("raw:" + suffix, "company:" + suffix, "doc:" + suffix)
            self.fingerprint("fp:" + suffix, "company:" + suffix, "doc:" + suffix)

    def test_unknown_and_noncompany_organizations_are_rejected_on_insert_and_update(self):
        ensure_constraints(self.conn)
        for organization in ("missing", "domain:x"):
            with self.subTest(organization=organization), self.assertRaises(sqlite3.IntegrityError):
                self.document("invalid", organization)
        self.valid_pair()
        for table in ("technographic_documents", "tech_fingerprints", "technographic_sources"):
            with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(f"UPDATE {table} SET organization_id='domain:x' WHERE organization_id='company:a'")

    def test_document_scope_must_match_every_source_and_fingerprint(self):
        ensure_constraints(self.conn)
        self.valid_pair()
        with self.assertRaises(sqlite3.IntegrityError):
            self.source("raw:shared", "company:b", "doc:a")
        with self.assertRaises(sqlite3.IntegrityError):
            self.fingerprint("foreign", "company:b", "doc:a")
        with self.assertRaises(sqlite3.IntegrityError):
            self.source("missing-source", "company:a", "doc:a")
        for table in ("tech_fingerprints", "technographic_sources"):
            with self.subTest(table=table), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(f"UPDATE {table} SET document_id='doc:b' WHERE organization_id='company:a'")

    def test_one_raw_source_cannot_be_active_under_two_companies(self):
        ensure_constraints(self.conn)
        self.valid_pair()
        with self.assertRaises(sqlite3.IntegrityError):
            self.source("raw:a", "company:b", "doc:b")
        self.conn.execute("DELETE FROM technographic_sources WHERE source_entity_id='raw:a'")
        self.source("raw:a", "company:b", "doc:b")
        self.assertEqual(self.conn.execute("SELECT organization_id FROM technographic_sources WHERE source_entity_id='raw:a'").fetchone()[0], "company:b")

    def test_company_identity_cannot_change_while_scoped_evidence_exists(self):
        ensure_constraints(self.conn)
        self.valid_pair()
        for sql in ("UPDATE entities SET kind='vendor' WHERE id='company:a'", "UPDATE entities SET id='company:other' WHERE id='company:a'",
                    "UPDATE entities SET id=NULL WHERE id='company:a'", "UPDATE technographic_documents SET id=NULL WHERE id='doc:a'",
                    "UPDATE tech_fingerprints SET id=NULL WHERE id='fp:a'"):
            with self.subTest(sql=sql), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(sql)
        self.conn.execute("UPDATE entities SET name='Updated name' WHERE id='company:a'")

    def test_source_entity_identity_cannot_invalidate_legacy_source_reference(self):
        ensure_constraints(self.conn)
        self.valid_pair()
        for identity in ("renamed", None):
            with self.subTest(identity=identity), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute("UPDATE entities SET id=? WHERE id='raw:a'", (identity,))

    def test_deleting_company_cascades_only_its_projections_and_keeps_raw_sources(self):
        ensure_constraints(self.conn)
        self.valid_pair()
        for suffix in ("a", "b"):
            self.observation("obs:" + suffix, "company:" + suffix, "doc:" + suffix, "raw:" + suffix)
            self.alert("alert:" + suffix, "company:" + suffix)
            self.conn.execute("INSERT INTO edges(from_id,to_id,relation) VALUES(?,?,?)", ("company:" + suffix, "raw:" + suffix, "has_public_evidence"))
        self.conn.execute("DELETE FROM entities WHERE id='company:a'")
        for table in ("technographic_documents", "tech_fingerprints", "technographic_sources"):
            self.assertEqual([row[0] for row in self.conn.execute(f"SELECT organization_id FROM {table}")], ["company:b"])
        self.assertEqual([row[0] for row in self.conn.execute("SELECT asset_id FROM observations")], ["company:b"])
        self.assertEqual([row[0] for row in self.conn.execute("SELECT asset_id FROM alerts")], ["company:b"])
        self.assertEqual(self.conn.execute("SELECT count(*) FROM entities WHERE id IN ('raw:a','raw:b')").fetchone()[0], 2)

    def test_source_deletion_clears_last_active_projection_but_keeps_document_history(self):
        ensure_constraints(self.conn)
        self.valid_pair()
        self.observation("obs:a", "company:a", "doc:a", "raw:a")
        self.source("raw:shared", "company:a", "doc:a")
        self.conn.execute("DELETE FROM entities WHERE id='raw:a'")
        self.assertEqual(self.conn.execute("SELECT count(*) FROM observations").fetchone()[0], 1)
        self.conn.execute("DELETE FROM entities WHERE id='raw:shared'")
        self.assertEqual(self.conn.execute("SELECT count(*) FROM observations").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM technographic_documents").fetchone()[0], 2)

    def test_resolution_requires_existing_source_and_company(self):
        ensure_constraints(self.conn)
        values = ("raw:a", "company:a", "resolved", "explicit", "Known", "[]", "", "{}", "", "now")
        self.conn.execute("INSERT INTO evidence_resolution VALUES(?,?,?,?,?,?,?,?,?,?)", values)
        for column, value in (("organization_id", "domain:x"), ("source_entity_id", "missing")):
            with self.subTest(column=column), self.assertRaises(sqlite3.IntegrityError):
                self.conn.execute(f"UPDATE evidence_resolution SET {column}=?", (value,))
        self.conn.execute("DELETE FROM entities WHERE id='company:a'")
        self.assertEqual(self.conn.execute("SELECT count(*) FROM evidence_resolution").fetchone()[0], 0)
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM entities WHERE id='raw:a'").fetchone())

    def test_legacy_invalid_rows_are_quarantined_and_scoped_reconciliation_removes_false_alert(self):
        self.valid_pair()
        self.document("bad-doc", "domain:x")
        self.source("raw:shared", "company:b", "doc:a")
        self.fingerprint("bad-fp", "company:b", "doc:a")
        self.observation("bad-obs", "company:b", "doc:a", "raw:shared")
        self.observation("good-obs", "company:a", "doc:a", "raw:a")
        self.alert("bad-alert", "company:b")
        self.alert("good-alert", "company:a")
        affected = ensure_constraints(self.conn)
        self.assertEqual(affected, {"company:b", "domain:x"})
        Store.reconcile(Store.__new__(Store), asset_ids=affected, conn=self.conn)
        self.assertEqual([row[0] for row in self.conn.execute("SELECT id FROM observations")], ["good-obs"])
        self.assertEqual([row[0] for row in self.conn.execute("SELECT id FROM alerts")], ["good-alert"])
        quarantined = list(self.conn.execute("SELECT table_name,row_json FROM technographic_integrity_quarantine"))
        self.assertEqual({row[0] for row in quarantined}, {"technographic_documents", "technographic_sources", "tech_fingerprints", "observations"})
        self.assertTrue(all(isinstance(json.loads(row[1]), dict) for row in quarantined))
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM entities WHERE id='raw:shared'").fetchone())

    def test_ambiguous_legacy_source_owner_is_not_arbitrarily_selected(self):
        self.valid_pair()
        self.source("raw:shared", "company:a", "doc:a")
        self.source("raw:shared", "company:b", "doc:b")
        self.assertEqual(ensure_constraints(self.conn), {"company:a", "company:b"})
        self.assertEqual(self.conn.execute("SELECT count(*) FROM technographic_sources WHERE source_entity_id='raw:shared'").fetchone()[0], 0)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM technographic_sources").fetchone()[0], 2)

    def test_document_lookup_preserves_exact_origin_prefix_validation(self):
        self.valid_pair()
        self.observation("valid", "company:a", "doc:a", "raw:a")
        self.observation("invalid", "company:a", "doc:a", "raw:a")
        self.conn.execute("UPDATE observations SET origin='Technographic:doc:a' WHERE id='invalid'")
        self.assertEqual(ensure_constraints(self.conn), {"company:a"})
        self.assertEqual([row[0] for row in self.conn.execute("SELECT id FROM observations")], ["valid"])

    def test_many_documents_for_one_product_require_bounded_migration_work(self):
        count = 2000
        for index in range(count):
            source, document = f"raw:large:{index}", f"doc:large:{index}"
            self.conn.execute("INSERT INTO entities(id,kind,name,value,updated_at) VALUES(?,'job_posting','Raw','Raw','now')", (source,))
            self.document(document, "company:a")
            self.source(source, "company:a", document)
            self.fingerprint(f"fp:large:{index}", "company:a", document)
            self.observation(f"obs:large:{index}", "company:a", document, source)
        steps = 0

        def progress():
            nonlocal steps
            steps += 1000
            return 0

        self.conn.set_progress_handler(progress, 1000)
        try:
            self.assertEqual(ensure_constraints(self.conn), set())
        finally:
            self.conn.set_progress_handler(None, 0)
        # Count SQLite VM instructions rather than timing the test: scanning
        # every same-product fingerprint per observation grows quadratically.
        self.assertLess(steps, count * 1000)
        self.assertEqual(self.conn.execute("SELECT count(*) FROM observations").fetchone()[0], count)

    def test_migration_is_idempotent_and_rolls_back_with_its_caller(self):
        self.document("bad-doc", "domain:x")
        self.conn.commit()
        ensure_constraints(self.conn)
        self.conn.rollback()
        self.assertIsNotNone(self.conn.execute("SELECT 1 FROM technographic_documents WHERE id='bad-doc'").fetchone())
        self.assertEqual(ensure_constraints(self.conn), {"domain:x"})
        self.conn.commit()
        statements = []
        self.conn.set_trace_callback(statements.append)
        self.assertEqual(ensure_constraints(self.conn), set())
        self.assertFalse(any("DELETE" in sql or "tech_bad_documents" in sql for sql in statements))

    def test_store_startup_repairs_legacy_scope_and_reopen_skips_completed_repair(self):
        self.document("bad-doc", "domain:x")
        self.source("raw:shared", "domain:x", "bad-doc")
        self.fingerprint("bad-fp", "domain:x", "bad-doc")
        self.observation("bad-obs", "domain:x", "bad-doc", "raw:shared")
        self.alert("bad-alert", "domain:x")
        self.alert("unrelated-alert", "company:b")
        self.conn.commit()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "legacy.db"
            with sqlite3.connect(path) as legacy:
                self.conn.backup(legacy)
            migrated = Store(path)
            with migrated.connection() as conn:
                self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
                for table in ("technographic_documents", "technographic_sources", "tech_fingerprints", "observations"):
                    self.assertEqual(conn.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)
                self.assertEqual([row[0] for row in conn.execute("SELECT id FROM alerts")], ["unrelated-alert"])
                self.assertEqual(conn.execute("SELECT count(*) FROM technographic_integrity_quarantine").fetchone()[0], 4)
                self.assertIsNotNone(conn.execute("SELECT 1 FROM entities WHERE id='raw:shared'").fetchone())
                self.assertEqual(conn.execute("PRAGMA foreign_key_check").fetchall(), [])
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute(
                        "INSERT INTO technographic_documents VALUES(?,?,?,?,?,?,?,?)",
                        ("invalid", "domain:x", "invalid", "Title", "Text", None, "now", "now"))
            with patch("signalwatch.technographic_constraints._repair") as repair:
                reopened = Store(path)
            repair.assert_not_called()
            with reopened.connection() as conn:
                self.assertEqual(conn.execute("SELECT count(*) FROM technographic_integrity_quarantine").fetchone()[0], 4)
