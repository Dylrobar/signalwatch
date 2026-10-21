import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
import test_access_reviews as reviews_fixture
from signalwatch.knowledge_graph import KnowledgeGraph
from signalwatch.read_cache import ReadSnapshots


class VerifiedPriorityTests(unittest.TestCase):
    setUp = reviews_fixture.AccessReviewTests.setUp
    fixture = reviews_fixture.AccessReviewTests.fixture

    def payload(self, company, warning):
        return {'subject_id': warning, 'company_id': company, 'state': 'confirmed_exposure',
                'reason': 'Authenticated package inventory and application configuration reviewed', 'expected_revision': 0,
                'verification': {'observed_version': '1.0', 'evidence_url': 'https://evidence.test/review/1',
                    'runtime_verified': True, 'package_affected': True,
                    'expires_at': (datetime.now(timezone.utc) + timedelta(days=7)).isoformat(),
                    'remediation': 'Upgrade the verified Widget deployment to the vendor fixed package documented in the review.'}}

    def test_verification_promotes_owned_asset_and_mutation_invalidates_snapshot(self):
        company, _, warning = self.fixture()
        before = self.client.get('/api/company-risk', params={'id': company}).json()['items'][0]['risk']
        self.assertLess(before['score'], 85)
        response = self.client.post('/api/reviews', json=self.payload(company, warning))
        self.assertEqual(response.status_code, 200, response.text)
        after = self.client.get('/api/company-risk', params={'id': company}).json()['items'][0]['risk']
        self.assertEqual(after['tier'], 'confirmed_exposure')
        graph = KnowledgeGraph(self.store).graph(company, 3)
        self.assertEqual(next(n for n in graph['nodes'] if n['id'] == warning)['risk']['tier'], 'confirmed_exposure')
        self.assertGreaterEqual(after['score'], 85)
        self.assertIn('Upgrade the verified Widget', ' '.join(after['remediation']['steps']))
        self.assertEqual(after['remediation']['verification_evidence_url'], 'https://evidence.test/review/1')

    def test_expiry_changed_version_and_rejected_ownership_remove_confirmation(self):
        company, _, warning = self.fixture()
        self.assertEqual(self.client.post('/api/reviews', json=self.payload(company, warning)).status_code, 200)
        graph = KnowledgeGraph(self.store)
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE exposure_verifications SET expires_at='2000-01-01T00:00:00+00:00'")
        self.assertLess(graph.company_risk(company)['score'], 85)
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE exposure_verifications SET expires_at='2099-01-01T00:00:00+00:00',version='different'")
        self.assertLess(graph.company_risk(company)['score'], 85)
        self.store.set_company_asset(company, 'https://acme.test', status='rejected', evidence='No longer owned', source_url='https://evidence.test/transfer')
        self.assertEqual(graph.company_risk(company)['items'], [])

    def test_confirmation_requires_owned_version_and_evidence_not_just_review_state(self):
        company, _, warning = self.fixture()
        payload = self.payload(company, warning)
        self.assertEqual(self.client.post('/api/reviews', json={**payload, 'verification': None}).status_code, 422)
        self.assertEqual(self.client.post('/api/reviews', json={**payload, 'verification': {**payload['verification'], 'observed_version': '2.0'}}).status_code, 409)
        self.store.set_company_asset(company, 'https://acme.test', status='automatic')
        self.assertNotEqual(self.client.post('/api/reviews', json=payload).status_code, 200)

    def test_reappearing_warning_does_not_reuse_old_confirmation(self):
        company, _, warning = self.fixture()
        self.assertEqual(self.client.post('/api/reviews', json=self.payload(company, warning)).status_code, 200)
        observation = {'asset_id': 'domain:acme.test', 'vendor': 'maker', 'product': 'widget', 'source_url': 'https://acme.test'}
        self.store.ingest({'observations': [{**observation, 'version': '2.0'}]})
        self.store.reconcile()
        self.assertEqual(KnowledgeGraph(self.store).company_risk(company)['items'], [])
        self.store.ingest({'observations': [{**observation, 'version': '1.0'}]})
        self.store.reconcile()
        self.assertLess(KnowledgeGraph(self.store).company_risk(company)['score'], 85)

    def test_review_transition_revokes_verification(self):
        company, _, warning = self.fixture()
        self.assertEqual(self.client.post('/api/reviews', json=self.payload(company, warning)).status_code, 200)
        response = self.client.post('/api/reviews', json={'subject_id': warning, 'company_id': company,
            'state': 'investigating', 'reason': 'New evidence requires another review', 'expected_revision': 1})
        self.assertEqual(response.status_code, 200)
        self.assertLess(KnowledgeGraph(self.store).company_risk(company)['score'], 85)


class ReadSnapshotTests(unittest.TestCase):
    def test_memory_cap_invalidation_and_no_cached_exceptions(self):
        cache = ReadSnapshots(max_entries=2, max_bytes=100)
        calls = []
        def query(value):
            calls.append(value)
            return {'value': value}
        cache.read(query, 1); cache.read(query, 1)
        self.assertEqual(calls, [1])
        for i in range(20): cache.read(query, i)
        self.assertLessEqual(cache.size, 100)
        self.assertLessEqual(len(cache.entries), 2)
        cache.clear()
        self.assertEqual(cache.size, 0)
        def broken(): raise ValueError('failed')
        for _ in range(2):
            with self.assertRaises(ValueError): cache.read(broken)
        self.assertFalse(cache.pending)

    def test_two_expensive_queries_max_and_no_stale_fill_after_mutation(self):
        cache = ReadSnapshots()
        entered = threading.Barrier(3)
        release = threading.Event()
        def query(value):
            entered.wait(timeout=3)
            release.wait(timeout=3)
            return {'value': value}
        with ThreadPoolExecutor(2) as pool:
            a, b = pool.submit(cache.read, query, 1), pool.submit(cache.read, query, 2)
            entered.wait(timeout=3)
            try:
                with self.assertRaises(HTTPException) as error: cache.read(query, 3)
                self.assertEqual(error.exception.status_code, 503)
                cache.clear()
            finally: release.set()
            a.result(); b.result()
        self.assertFalse(cache.entries)
        self.assertFalse(cache.pending)

    def test_sqlite_expensive_read_is_interrupted_without_poisoning_database(self):
        from signalwatch.store import Store
        store = Store(':memory:')
        with self.assertRaises(TimeoutError):
            with store.connection(read_timeout=0.01) as conn:
                conn.execute('WITH RECURSIVE numbers(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM numbers WHERE n<100000000) SELECT sum(n) FROM numbers').fetchone()
        with store.connection() as conn:
            self.assertEqual(conn.execute('SELECT 1').fetchone()[0], 1)

    def test_partial_numeric_version_never_gets_zero_padded_into_affected_range(self):
        from signalwatch.matching import version_match
        self.assertEqual(version_match('2.4', {'versionEndExcluding': '2.4.61'})[1], 'version_unverified')
        self.assertEqual(version_match('2.4.60', {'versionEndExcluding': '2.4.61'})[1], 'affected_range')
