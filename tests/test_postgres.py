"""Real PostgreSQL integration and parity suite.

CI provides PostgreSQL 16. Locally set SIGNALWATCH_TEST_POSTGRES_URL to a
throwaway database owned by the test user; each test uses an isolated schema.
No production URL is consulted and no existing schema is cleared.
"""
import importlib
import os
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from signalwatch.store import Store
from signalwatch.postgres_migrate import migrate_sqlite

TEST_URL = os.environ.get('SIGNALWATCH_TEST_POSTGRES_URL', '')
ORIGINAL_STORE_INIT = Store.__init__


class PostgresEnvironment:
    def __init__(self):
        self.schemas = []
        self.paths = {}
    def url(self):
        import psycopg
        name = 'sw_test_' + uuid.uuid4().hex
        with psycopg.connect(TEST_URL, autocommit=True) as conn:
            conn.execute('CREATE SCHEMA ' + name)
        self.schemas.append(name)
        parsed = urlsplit(TEST_URL)
        query = dict(parse_qsl(parsed.query))
        query['options'] = '-c search_path=' + name + ',public'
        return urlunsplit(parsed._replace(query=urlencode(query, quote_via=quote)))
    def cleanup(self):
        import psycopg
        with psycopg.connect(TEST_URL, autocommit=True) as conn:
            for name in self.schemas:
                conn.execute('DROP SCHEMA ' + name + ' CASCADE')
    def initialize_store(self, store, path):
        path = str(path)
        if path.startswith(('postgres://', 'postgresql://')):
            return ORIGINAL_STORE_INIT(store, path)
        if path == ':memory:' or path not in self.paths:
            self.paths[path] = self.url()
        return ORIGINAL_STORE_INIT(store, self.paths[path])


class PostgresContractMixin:
    def setUp(self):
        if not TEST_URL:
            self.skipTest('Set SIGNALWATCH_TEST_POSTGRES_URL for real PostgreSQL tests')
        environment = PostgresEnvironment()
        self.addCleanup(environment.cleanup)
        replacement = lambda store, path: environment.initialize_store(store, path)
        swap = patch.object(Store, '__init__', replacement)
        swap.start()
        self.addCleanup(swap.stop)
        super().setUp()


@unittest.skipUnless(TEST_URL, 'Set SIGNALWATCH_TEST_POSTGRES_URL for real PostgreSQL tests')
class PostgresMigrationTests(unittest.TestCase):
    def setUp(self):
        self.environment = PostgresEnvironment()
        self.addCleanup(self.environment.cleanup)
        self.target = self.environment.url()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source_path = Path(self.temp.name) / 'original.sqlite3'
        self.source = Store(self.source_path)

    def fixture(self):
        from test_technographic_store import posting
        from signalwatch.staging import StagingQueue
        from signalwatch.jobs import Jobs
        from signalwatch.access import audit
        self.source.ingest({'entities': [
            {'id': 'company:acme', 'kind': 'company', 'name': 'Acme'},
            {'id': 'company:other', 'kind': 'company', 'name': 'Other'},
            {'id': 'domain:acme.test', 'kind': 'domain', 'value': 'acme.test'}],
            'edges': [{'from_id': 'company:acme', 'to_id': 'domain:acme.test', 'relation': 'official_website'}]})
        self.source.ingest({'entities': [posting('We use PostgreSQL in production.')],
            'advisories': [{'id': 'CVE-2026-12345', 'title': 'PostgreSQL vulnerability',
                            'affected': [{'vendor': 'postgresql', 'product': 'postgresql', 'version': '*'}]}],
            'articles': [{'url': 'https://news.example/report', 'title': 'PostgreSQL vulnerability', 'cves': ['CVE-2026-12345']}],
            'kev': [{'cveID': 'CVE-2026-12345'}]})
        self.source.reconcile()
        self.assertEqual(len(self.source.detail('company:acme')['alerts']), 1)
        raw = StagingQueue(self.source).enqueue(b'\x00\xff\nbinary payload', source='test')
        job = Jobs(self.source).enqueue('collect', {'source': 'cisa'})
        with self.source.connection(write=True) as conn:
            audit(conn, {'id': 'test', 'name': 'Tester'}, 'fixture.created', 'company:acme', after={'raw_id': raw['id']})
        return raw, job

    def test_copy_preserves_ids_links_binary_audit_search_and_sequences(self):
        from signalwatch.staging import StagingQueue
        from signalwatch.jobs import Jobs
        raw, job = self.fixture()
        original = self.source_path.read_bytes()
        report = migrate_sqlite(self.source_path, self.target)
        self.assertTrue(report['verified'])
        self.assertGreater(report['total_rows'], 20)
        self.assertEqual(self.source_path.read_bytes(), original)
        target = Store(self.target)
        self.assertEqual(target.stats(), self.source.stats())
        self.assertEqual(target.detail('company:acme')['alerts'], self.source.detail('company:acme')['alerts'])
        self.assertEqual(target.detail('company:other')['alerts'], [])
        self.assertEqual(StagingQueue(target).get(raw['id'], include_payload=True)['payload'], b'\x00\xff\nbinary payload')
        self.assertEqual(Jobs(target).get(job['id'])['id'], job['id'])
        self.assertEqual(target.search('Postgre')['total'], self.source.search('Postgre')['total'])
        with target.connection() as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM audit_log').fetchone()[0], 1)
            self.assertEqual(conn.execute('SELECT rowid FROM articles').fetchone()[0], 1)
        next_raw = StagingQueue(target).enqueue(b'next', source='test')
        self.assertGreater(next_raw['id'], raw['id'])
        self.assertTrue(migrate_sqlite(self.source_path, self.target)['already_migrated'])
        self.assertEqual(StagingQueue(target).get(next_raw['id'], include_payload=True)['payload'], b'next')

    def test_populated_destination_is_refused_and_original_is_unchanged(self):
        self.fixture()
        target = Store(self.target)
        target.ingest({'entities': [{'id': 'existing', 'kind': 'company', 'name': 'Existing'}]})
        with self.assertRaisesRegex(RuntimeError, 'not empty'):
            migrate_sqlite(self.source_path, self.target)
        self.assertEqual(target.detail('existing')['name'], 'Existing')
        self.assertEqual(self.source.detail('company:acme')['name'], 'Acme')

    def test_read_snapshot_stays_consistent_without_a_temporary_copy(self):
        self.fixture()
        from signalwatch import postgres_migrate
        original_connect = postgres_migrate.connect

        def change_after_source_checks(dsn):
            # A stray WAL writer must not make checksums and copied rows see
            # different database versions. Cutover still requires writers off.
            with sqlite3.connect(self.source_path) as writer:
                self.assertEqual(writer.execute('PRAGMA journal_mode').fetchone()[0], 'wal')
                writer.execute("UPDATE entities SET name='Later name' WHERE id='company:acme'")
            return original_connect(dsn)

        with patch.object(postgres_migrate, 'connect', side_effect=change_after_source_checks), \
                patch('tempfile.TemporaryDirectory', side_effect=AssertionError('No scratch database is allowed')):
            report = migrate_sqlite(self.source_path, self.target)
        self.assertTrue(report['verified'])
        self.assertEqual(Store(self.target).detail('company:acme')['name'], 'Acme')
        self.assertEqual(self.source.detail('company:acme')['name'], 'Later name')

    def test_refusal_and_completed_manifest_never_initialize_destination(self):
        self.fixture()
        target = Store(self.target)
        target.ingest({'entities': [{'id': 'existing', 'kind': 'company', 'name': 'Existing'}]})
        with patch('signalwatch.store.Store', side_effect=AssertionError('must inspect first')):
            with self.assertRaisesRegex(RuntimeError, 'not empty'):
                migrate_sqlite(self.source_path, self.target)
        other_target = self.environment.url()
        migrate_sqlite(self.source_path, other_target)
        with patch('signalwatch.store.Store', side_effect=AssertionError('completed target must not be initialized')):
            self.assertTrue(migrate_sqlite(self.source_path, other_target)['already_migrated'])

    def test_verification_failure_rolls_back_entire_copy_and_can_retry(self):
        self.fixture()
        from signalwatch import postgres_migrate
        real = postgres_migrate._digest
        def corrupted(rows):
            value = real(rows)
            # SQLite source rows are tuples; target psycopg cursor is distinct.
            if type(rows).__module__.startswith('psycopg'):
                return {**value, 'rows': value['rows'] + 1}
            return value
        with patch.object(postgres_migrate, '_digest', corrupted):
            with self.assertRaisesRegex(RuntimeError, 'verification failed'):
                migrate_sqlite(self.source_path, self.target)
        target = Store(self.target)
        self.assertEqual(target.stats()['entities'], 0)
        self.assertTrue(migrate_sqlite(self.source_path, self.target)['verified'])

    def test_legacy_schema_without_new_columns_or_tables_receives_defaults(self):
        self.fixture()
        with self.source.connection(write=True) as conn:
            conn.execute('ALTER TABLE alerts DROP COLUMN assessment')
            conn.execute('ALTER TABLE tech_fingerprints DROP COLUMN evidence_details')
            for name in ('audit_log', 'workspace_credentials', 'analyst_reviews', 'analyst_review_history',
                         'company_technology_events', 'company_technology_snapshots', 'evidence_company_revisions', 'evidence_source_checks'):
                conn.execute('DROP TABLE ' + name)
        report = migrate_sqlite(self.source_path, self.target)
        self.assertTrue(report['verified'])
        target = Store(self.target)
        with target.connection() as conn:
            self.assertEqual(conn.execute('SELECT assessment FROM alerts').fetchone()[0], '{}')
            self.assertEqual(conn.execute('SELECT count(*) FROM workspace_credentials').fetchone()[0], 0)
            self.assertEqual(conn.execute('SELECT evidence_details FROM tech_fingerprints').fetchone()[0], '{}')

    def test_native_scope_triggers_and_foreign_keys_reject_cross_company_documents(self):
        self.fixture()
        migrate_sqlite(self.source_path, self.target)
        target = Store(self.target)
        with target.connection() as conn:
            document_id = conn.execute('SELECT id FROM technographic_documents').fetchone()[0]
        with self.assertRaises(sqlite3.IntegrityError), target.connection(write=True) as conn:
            conn.execute('UPDATE tech_fingerprints SET organization_id=? WHERE document_id=?', ('company:other', document_id))
        with self.assertRaises(sqlite3.IntegrityError), target.connection(write=True) as conn:
            conn.execute("INSERT INTO company_identity_labels(company_id,label) VALUES('missing','label')")
        with target.connection(write=True) as conn:
            conn.execute("DELETE FROM entities WHERE id='company:acme'")
        with target.connection() as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM technographic_documents').fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT count(*) FROM entities WHERE id='company:other'").fetchone()[0], 1)

    def test_advisory_locks_coordinate_distinct_store_connections(self):
        from signalwatch.jobs import database_lock
        first, second = Store(self.target), Store(self.target)
        with database_lock(first, 'integration-lock') as acquired:
            self.assertTrue(acquired)
            with database_lock(second, 'integration-lock') as competing:
                self.assertFalse(competing)
        with database_lock(second, 'integration-lock') as released:
            self.assertTrue(released)

    def test_full_text_and_scope_indexes_are_native_postgres_indexes(self):
        target = Store(self.target)
        target.ingest({'entities': [{'id': 'company:search', 'kind': 'company', 'name': 'Searchable Example'}]})
        with target.connection() as conn:
            conn.raw.execute('SET LOCAL enable_seqscan=off')
            plan = conn.raw.execute("EXPLAIN (FORMAT JSON) SELECT rowid FROM entity_fts WHERE document @@ sw_fts_query(%s)", ('"Search"*',)).fetchone()[0]
            import json
            self.assertIn('entity_fts_search', json.dumps(plan))
            indexes = {row[0] for row in conn.raw.execute("SELECT indexname FROM pg_indexes WHERE schemaname=current_schema()")}
            self.assertIn('technographic_source_single_owner', indexes)
            self.assertIn('company_primary_domain', indexes)


class PostgresConfigurationTests(unittest.TestCase):
    def test_malformed_dsn_cannot_leak_credentials_in_errors(self):
        from signalwatch.postgres import connect
        try:
            import psycopg  # noqa: F401
        except ImportError:
            self.skipTest('PostgreSQL extra is not installed')
        with self.assertRaises(sqlite3.OperationalError) as captured:
            connect('postgresql://user:DO_NOT_LEAK_THIS%oops@localhost/test')
        self.assertNotIn('DO_NOT_LEAK_THIS', str(captured.exception))
        self.assertIsNone(captured.exception.__cause__)


# Reuse real application contracts instead of duplicating their assertions.
# SQLite VM profiling, journal settings and inode-lock mechanics remain tested
# in the SQLite suite; native locking/migration assertions are above.
CONTRACTS = {
    'test_companies': ('CompanyTests',),
    'test_staging': ('StagingTests',),
    'test_technographic_store': ('TechnographicStoreTests',),
    'test_store_matching': ('StoreTests',),
    'test_company_isolation_api': ('CompanyIsolationAPITests',),
    'test_company_graph_isolation': ('CompanyGraphIsolationTests',),
    'test_access_reviews': ('AccessReviewTests',),
    'test_jobs': ('JobsTests',),
    'test_wireless': ('WirelessTests',),
    'test_wireless_attribution': ('WirelessAttributionTests',),
    'test_knowledge_graph': ('GraphTests',),
    'test_evidence': ('EvidenceTests',),
    'test_data_quality': ('QualityTests',),
    'test_applicability': ('AlertAssessmentTests',),
}
SQLITE_ONLY = {
    'test_idempotency_and_indexes',
    'test_recovery_requires_both_collection_and_job_locks_to_be_idle',
    'test_history_and_lock_files_are_bounded_without_pruning_active_jobs',
    'test_pruning_finished_job_does_not_replace_a_still_locked_inode',
    'test_stats_scope_distinct_devices_locations_cache_and_active_company_links',
    'test_manufacturer_rebuild_scans_input_once_and_indexes_each_prefix_lookup',
    'test_incoming_adjacency_uses_early_limit_on_high_degree_nodes',
    'test_common_term_catalog_lookup_is_bounded_before_hydration',
    'test_sqlite_retry_recovers_from_a_real_competing_writer',
    'test_wal_reader_does_not_block_matching_and_facility_delete_is_indexed',
}


def load_tests(loader, tests, pattern):
    for module_name, names in CONTRACTS.items():
        module = importlib.import_module(module_name)
        for name in names:
            cls = type('Postgres' + name, (PostgresContractMixin, getattr(module, name)), {'__module__': __name__})
            for method in loader.getTestCaseNames(cls):
                if method not in SQLITE_ONLY:
                    tests.addTest(cls(method))
    return tests
