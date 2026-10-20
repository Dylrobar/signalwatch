import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from signalwatch.api import create_app
from signalwatch.config import load_config


class AccessReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / 'config.json')
        self.config.update(api_token='test-master', seed_urls=[])
        with patch.dict(os.environ, {'CELERY_BROKER_URL': ''}):
            self.app = create_app(self.config, auto_collect=False)
        self.store = self.app.state.store
        self.client = TestClient(self.app, headers={'Authorization': 'Bearer test-master'})
        self.addCleanup(self.client.close)

    def credential(self, role):
        response = self.client.post('/api/auth/credentials', json={'name': role + ' test', 'role': role})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def as_token(self, token):
        client = TestClient(self.app, headers={'Authorization': 'Bearer ' + token})
        self.addCleanup(client.close)
        return client

    def fixture(self):
        a = self.client.post('/api/companies/profile', json={'name': 'Acme'}).json()['id']
        b = self.client.post('/api/companies/profile', json={'name': 'Nebula'}).json()['id']
        self.store.ingest({'observations': [{'asset_id': 'domain:acme.test', 'vendor': 'maker', 'product': 'widget', 'version': '1.0', 'source_url': 'https://acme.test'}],
                           'advisories': [{'id': 'CVE-2026-12345', 'source': 'nvd', 'affected': [{'vendor': 'maker', 'product': 'widget', 'version': '1.0'}]}]})
        self.store.set_company_asset(a, 'https://acme.test', evidence='Reviewed owner', source_url='https://acme.test/about')
        self.store.reconcile()
        return a, b, self.store.alerts()['items'][0]['id']

    def test_named_roles_and_secret_storage(self):
        viewer = self.credential('viewer')
        client = self.as_token(viewer['token'])
        result = client.get('/api/capabilities').json()
        self.assertFalse(result['permissions']['write'])
        self.assertEqual(result['user']['role'], 'viewer')
        self.assertEqual(client.post('/api/companies/profile', json={'name': 'Forbidden'}).status_code, 403)
        self.assertEqual(client.post('/api/companies/profile/', json={'name': 'Forbidden'}).status_code, 403)
        self.assertEqual(client.get('/api/auth/credentials').status_code, 403)
        self.assertEqual(client.post('/api/companies/resolve', json={'domain': 'example.com'}).status_code, 200)
        self.assertEqual(client.post('/api/companies/preview', json={'kind': 'profile', 'values': {'name': 'Read-only preview'}}).status_code, 200)
        self.assertNotIn(viewer['token'], self.client.get('/api/auth/credentials').text)
        self.assertNotIn(viewer['token'], self.client.get('/api/audit').text)
        with self.store.connection() as conn:
            stored = dict(conn.execute('SELECT * FROM workspace_credentials').fetchone())
            self.assertNotIn(viewer['token'], str(stored))

    def test_editor_cannot_admin_and_revocation_is_immediate(self):
        credential = self.credential('editor')
        client = self.as_token(credential['token'])
        self.assertEqual(client.post('/api/companies/profile', json={'name': 'Allowed'}).status_code, 200)
        self.assertEqual(client.post('/api/sources/settings', json={}).status_code, 403)
        self.assertEqual(client.post('/api/auth/credentials', json={'name': 'No', 'role': 'admin'}).status_code, 403)
        self.assertEqual(self.client.post('/api/auth/credentials/' + credential['credential']['id'] + '/revoke').status_code, 200)
        self.assertEqual(client.get('/api/status').status_code, 401)
        self.assertEqual(self.client.get('/api/status').status_code, 200)

    def test_bootstrap_cannot_lock_out_or_reenable_anonymous(self):
        self.app.state.access.master_token = ''
        anonymous = TestClient(self.app)
        self.addCleanup(anonymous.close)
        self.assertEqual(anonymous.post('/api/auth/credentials', json={'name': 'Viewer', 'role': 'viewer'}).status_code, 409)
        response = anonymous.post('/api/auth/credentials', json={'name': 'Owner', 'role': 'admin'})
        self.assertEqual(response.status_code, 200, response.text)
        data = response.json()
        self.assertEqual(anonymous.get('/api/status').status_code, 401)
        admin = self.as_token(data['token'])
        self.assertEqual(admin.post('/api/auth/credentials/' + data['credential']['id'] + '/revoke').status_code, 409)
        self.assertTrue(anonymous.get('/health').json()['auth_required'])

    def test_invalid_credentials_and_injected_role_rejected(self):
        self.assertEqual(self.as_token('bogus').get('/api/status').status_code, 401)
        self.assertEqual(self.client.post('/api/auth/credentials', json={'name': 'Bad', 'role': 'superadmin'}).status_code, 422)

    def test_review_scope_revision_audit_and_reconcile_survival(self):
        a, b, warning = self.fixture()
        payload = {'subject_id': warning, 'company_id': a, 'state': 'investigating', 'reason': 'Owner verifying inventory', 'expected_revision': 0}
        wrong = self.client.post('/api/reviews', json={**payload, 'company_id': b})
        self.assertEqual(wrong.status_code, 409, wrong.text)
        response = self.client.post('/api/reviews', json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['revision'], 1)
        self.assertEqual(response.json()['actor']['id'], 'master')
        self.assertEqual(self.client.post('/api/reviews', json=payload).status_code, 409)
        self.assertEqual(self.client.post('/api/reviews', json={**payload, 'state': 'accepted_risk', 'expected_revision': 1}).status_code, 200)
        self.store.reconcile()
        items = self.client.get('/api/reviews/history', params={'subject_id': warning, 'company_id': a}).json()['items']
        self.assertEqual([item['revision'] for item in items], [2, 1])
        self.assertEqual(self.client.get('/api/reviews', params={'company_id': b}).json()['items'], [])
        self.assertEqual(self.client.get('/api/reviews', params={'subject_id': warning, 'company_id': ''}).json()['items'], [])
        global_review = self.client.post('/api/reviews', json={**payload, 'company_id': ''})
        self.assertEqual(global_review.status_code, 200, global_review.text)
        global_items = self.client.get('/api/reviews', params={'subject_id': warning, 'company_id': ''}).json()['items']
        self.assertEqual([item['company_id'] for item in global_items], [''])
        audit = self.client.get('/api/audit', params={'subject_id': warning}).json()['items']
        self.assertEqual(len(audit), 3)
        self.assertEqual(next(item for item in audit if item['before'])['before']['state'], 'investigating')
        with self.store.connection(write=True) as conn:
            conn.execute('DELETE FROM alerts WHERE id=?', (warning,))
        self.assertEqual(len(self.client.get('/api/reviews/history', params={'subject_id': warning, 'company_id': a}).json()['items']), 2)
        self.assertEqual(self.client.post('/api/reviews', json={**payload, 'expected_revision': 2}).status_code, 404)

    def test_review_requires_reason_and_timezone(self):
        a, _, warning = self.fixture()
        body = {'subject_id': warning, 'company_id': a, 'state': 'remediated', 'reason': '  '}
        self.assertEqual(self.client.post('/api/reviews', json=body).status_code, 422)
        body.update(reason='Owner confirmed', review_due_at='2026-12-01T00:00:00')
        self.assertEqual(self.client.post('/api/reviews', json=body).status_code, 422)

    def test_preview_rolls_back_profiles_alerts_and_decisions(self):
        a, _, warning = self.fixture()
        with self.store.connection() as conn:
            tables = ['entities', 'company_profiles', 'company_asset_decisions', 'alerts', 'events', 'audit_log']
            before = {table: [tuple(row) for row in conn.execute('SELECT * FROM ' + table + ' ORDER BY 1')] for table in tables}
        preview = self.client.post('/api/companies/preview', json={'kind': 'asset', 'values': {
            'company_id': a, 'asset_url': 'https://acme.test', 'status': 'rejected', 'role': 'owned',
            'evidence': 'Testing corrected ownership', 'source_url': 'https://acme.test/about'}})
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertIn('domain:acme.test', preview.json()['changes']['included_removed'])
        with self.store.connection() as conn:
            after = {table: [tuple(row) for row in conn.execute('SELECT * FROM ' + table + ' ORDER BY 1')] for table in tables}
        self.assertEqual(before, after)
        preview = self.client.post('/api/companies/preview', json={'kind': 'profile', 'values': {'name': 'Ephemeral'}})
        self.assertEqual(preview.status_code, 200, preview.text)
        self.assertIsNone(self.store.detail(preview.json()['after']['company_id']))


if __name__ == '__main__':
    unittest.main()
