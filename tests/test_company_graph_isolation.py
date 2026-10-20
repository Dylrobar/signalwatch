import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.companies import company_assets
from signalwatch.knowledge_graph import KnowledgeGraph
from signalwatch.network import NETWORK_URL, ingest_network_snapshot, parse_network
from signalwatch.store import Store


class CompanyGraphIsolationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'isolation.db')
        self.graph = KnowledgeGraph(self.store)
        for key, name in [('company:acme', 'Acme'), ('company:nebula', 'Nebula')]:
            self.store.ingest({'entities': [{'id': key, 'kind': 'company', 'name': name}]})
            self.store.save_company_profile(key, name)

    def anchor(self, company_id, domain):
        # Exercise the query contract independently of the profile API writer.
        self.store.ingest({'entities': [{'id': 'domain:' + domain, 'kind': 'domain', 'name': domain}]})
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE company_profiles SET primary_domain=?,primary_domain_evidence='Verified website',primary_domain_source_url=? WHERE company_id=?",
                         (domain, 'https://' + domain, company_id))

    def decision(self, company_id, domain, status='confirmed', role='owned'):
        self.store.set_company_asset(company_id, 'https://' + domain, status, role,
                                     'Operator evidence', 'https://registry.example.com/')

    def assets(self, company_id='company:acme'):
        with self.store.connection() as conn:
            return {item['id']: item for item in company_assets(conn, company_id)[0]}

    def observations(self, *domains):
        self.store.ingest({'observations': [{'asset_id': 'domain:' + domain, 'vendor': 'maker',
                            'product': 'widget', 'version': '1.0', 'source_url': 'https://' + domain}
                           for domain in domains],
                           'advisories': [{'id': 'CVE-2026-12345', 'source': 'nvd', 'severity': 9.8,
                            'affected': [{'vendor': 'maker', 'product': 'widget', 'version': '1.0'}]}]})
        self.store.reconcile()

    def test_primary_namespace_candidates_require_ownership_and_nested_anchor_is_fenced(self):
        self.anchor('company:acme', 'example.com')
        self.anchor('company:nebula', 'division.example.com')
        self.observations('example.com', 'api.example.com', 'division.example.com', 'api.division.example.com')
        assets = self.assets()
        self.assertTrue(assets['domain:example.com']['included'])
        self.assertEqual(assets['domain:example.com']['status'], 'primary')
        self.assertFalse(assets['domain:api.example.com']['included'])
        self.assertNotIn('domain:division.example.com', assets)
        self.assertNotIn('domain:api.division.example.com', assets)
        self.assertEqual({row['asset_id'] for row in self.graph.company_risk('company:acme')['items']}, {'domain:example.com'})
        graph = self.graph.graph('company:acme', 5, 300, 800)
        candidate = next(node for node in graph['nodes'] if node['id'] == 'domain:api.example.com')
        self.assertFalse(candidate['ownership']['included'])
        self.assertFalse(any(node['kind'] == 'alert' and node['metadata']['asset_id'] == candidate['id'] for node in graph['nodes']))
        self.decision('company:acme', 'api.example.com')
        self.assertEqual({row['asset_id'] for row in self.graph.company_risk('company:acme')['items']}, {'domain:example.com', 'domain:api.example.com'})

    def test_conflicting_manual_owners_are_visible_and_neither_company_includes_risk(self):
        self.observations('shared.example.com')
        for company_id in ('company:acme', 'company:nebula'):
            self.decision(company_id, 'shared.example.com')
        for company_id in ('company:acme', 'company:nebula'):
            with self.subTest(company_id=company_id):
                asset = self.assets(company_id)['domain:shared.example.com']
                self.assertFalse(asset['included'])
                self.assertEqual(asset['status'], 'conflict')
                self.assertEqual(asset['decision_status'], 'confirmed')
                self.assertIn('disagree', ' '.join(asset['reasons']))
                self.assertEqual(self.graph.company_risk(company_id)['items'], [])
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM company_asset_decisions WHERE status='confirmed'").fetchone()[0], 2)

    def test_primary_anchor_conflicting_manual_claim_blocks_root_and_child_risk(self):
        self.anchor('company:acme', 'example.com')
        self.observations('example.com', 'api.example.com')
        self.decision('company:nebula', 'example.com')
        self.assertFalse(self.assets()['domain:example.com']['included'])
        self.assertNotIn('domain:api.example.com', self.assets())
        self.assertFalse(self.assets('company:nebula')['domain:example.com']['included'])
        self.decision('company:nebula', 'api.example.com')
        self.assertFalse(self.assets('company:nebula')['domain:api.example.com']['included'])
        self.assertEqual(self.graph.company_risk('company:acme')['items'], [])
        self.assertEqual(self.graph.company_risk('company:nebula')['items'], [])

    def test_manual_root_exclusion_suppresses_namespace_but_confirmed_child_can_stand_alone(self):
        self.anchor('company:acme', 'example.com')
        self.observations('example.com', 'api.example.com', 'www.example.com')
        self.decision('company:acme', 'example.com', role='service')
        self.assertFalse(self.assets()['domain:example.com']['included'])
        self.assertNotIn('domain:api.example.com', self.assets())
        self.decision('company:acme', 'api.example.com')
        self.assertTrue(self.assets()['domain:api.example.com']['included'])
        self.assertEqual({row['asset_id'] for row in self.graph.company_risk('company:acme')['items']}, {'domain:api.example.com'})

    def test_shared_product_cve_and_ip_are_context_without_foreign_company_fanout(self):
        self.anchor('company:acme', 'example.com')
        self.anchor('company:nebula', 'example.org')
        self.observations('example.com', 'example.org')
        self.store.ingest({'entities': [{'id': 'ip:1.1.1.1', 'kind': 'ip', 'name': '1.1.1.1'}],
                           'edges': [{'from_id': 'domain:' + domain, 'to_id': 'ip:1.1.1.1', 'relation': 'resolves_to'}
                                     for domain in ('example.com', 'example.org')]})
        scoped = self.graph.graph('company:acme', 5, 300, 800)
        ids = {node['id'] for node in scoped['nodes']}
        self.assertIn('ip:1.1.1.1', ids)
        self.assertIn('CVE-2026-12345', ids)
        self.assertNotIn('domain:example.org', ids)
        self.assertNotIn('company:nebula', ids)
        self.assertTrue(any(node['kind'] == 'vendor' for node in scoped['nodes']))
        self.assertEqual({node['metadata']['asset_id'] for node in scoped['nodes'] if node['kind'] == 'alert'}, {'domain:example.com'})
        self.assertFalse(scoped['coverage']['shared_context_expansion'])
        self.assertNotIn('https://example.org', str(scoped))
        # Global infrastructure investigations retain both observed neighbors.
        global_graph = self.graph.graph('ip:1.1.1.1', 1, 300, 800)
        self.assertIn('domain:example.org', {node['id'] for node in global_graph['nodes']})

    def test_company_evidence_is_revalidated_and_shared_technology_retains_only_own_vendor_proof(self):
        self.anchor('company:acme', 'example.com')
        self.anchor('company:nebula', 'example.org')
        def article(key, domain, company):
            return {'id': key, 'kind': 'company_article', 'name': 'Engineering',
                    'source_url': 'https://' + domain + '/engineering',
                    'metadata': {'company_context': {'company_id': company, 'domain': domain},
                                 'fields': {'title': 'Our engineering stack', 'description': 'We use PostgreSQL for our database.'}}}
        self.store.ingest({'entities': [article('article:acme', 'example.com', 'company:acme'),
                                        article('article:nebula', 'example.org', 'company:nebula'),
                                        article('article:forged', 'example.org', 'company:acme')]})
        self.store.ingest({'edges': [{'from_id': 'company:acme', 'to_id': 'article:forged', 'relation': 'has_public_evidence'}]})
        scoped = self.graph.graph('company:acme', 5, 300, 800)
        ids = {node['id'] for node in scoped['nodes']}
        self.assertIn('article:acme', ids)
        self.assertNotIn('article:nebula', ids)
        self.assertNotIn('article:forged', ids)
        self.assertTrue(any(row['relation'] == 'vendor_label' for row in scoped['edges']))
        self.assertNotIn('https://example.org', str(scoped))

    def test_verified_asn_retains_evidence_without_importing_other_company_routes(self):
        self.anchor('company:acme', 'example.com')
        self.store.ingest({'entities': [{'id': 'asn:AS64500', 'kind': 'asn', 'name': 'AS64500'},
                                        {'id': 'prefix:1.1.1.0/24', 'kind': 'prefix', 'name': '1.1.1.0/24'}],
                           'edges': [{'from_id': 'company:acme', 'to_id': 'asn:AS64500', 'relation': 'verified_asn'},
                                     {'from_id': 'prefix:1.1.1.0/24', 'to_id': 'asn:AS64500', 'relation': 'announced_by'}]})
        with self.store.connection(write=True) as conn:
            conn.execute("INSERT INTO company_asn_anchors VALUES('company:acme',64500,'Verified registry record','https://registry.example.com/asn','2026-10-20')")
        scoped = self.graph.graph('company:acme', 5, 300, 800)
        ids = {node['id'] for node in scoped['nodes']}
        self.assertIn('asn:AS64500', ids)
        self.assertNotIn('prefix:1.1.1.0/24', ids)
        proof = next(item for item in scoped['edges'] if item['relation'] == 'verified_asn')
        self.assertEqual(proof['evidence']['note'], 'Verified registry record')
        self.assertFalse(proof['evidence']['risk_propagation'])
        self.assertEqual(self.graph.company_risk('company:acme')['items'], [])

    def test_root_company_alert_requires_current_validated_technographic_observation(self):
        self.anchor('company:acme', 'example.com')
        self.anchor('company:nebula', 'example.org')
        self.store.ingest({'entities': [{
            'id': 'article:acme', 'kind': 'company_article', 'name': 'Engineering',
            'source_url': 'https://example.com/engineering',
            'metadata': {'company_context': {'company_id': 'company:acme', 'domain': 'example.com'},
                         'fields': {'title': 'Engineering', 'description': 'We use PostgreSQL in production.'}}
        }], 'advisories': [{'id': 'CVE-2026-12345', 'source': 'nvd',
                           'affected': [{'vendor': 'postgresql', 'product': 'postgresql', 'part': 'a'}]}]})
        self.store.reconcile()
        with self.store.connection() as conn:
            alert = conn.execute("SELECT id FROM alerts WHERE asset_id='company:acme'").fetchone()[0]
        self.assertIn(alert, {node['id'] for node in self.graph.graph('company:acme', 5)['nodes']})
        # A retained alert with mismatched provenance must not regain scope
        # just because its asset_id still points at this company.
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE alerts SET source_url='https://example.org/engineering' WHERE id=?", (alert,))
        self.assertNotIn(alert, {node['id'] for node in self.graph.graph('company:acme', 5)['nodes']})
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE alerts SET source_url='https://example.com/engineering' WHERE id=?", (alert,))
            conn.execute("UPDATE observations SET origin='imported' WHERE asset_id='company:acme'")
        self.assertNotIn(alert, {node['id'] for node in self.graph.graph('company:acme', 5)['nodes']})


class NetworkSnapshotTests(unittest.TestCase):
    def test_refresh_replaces_only_resource_provenance_and_rolls_back_on_ingest_error(self):
        with tempfile.TemporaryDirectory() as folder:
            store = Store(Path(folder) / 'network.db')
            def snapshot(address, prefix, asns):
                target = {'id': 'ip:' + address, 'kind': 'ip', 'name': address, 'value': address}
                url = NETWORK_URL + '?resource=' + address
                batch = parse_network({'status': 'ok', 'data': {'prefix': prefix, 'asns': asns}}, target, url, '2026-10-20')
                return batch, target['id'], url
            original = snapshot('1.1.1.1', '1.1.1.0/24', [64500])
            sibling = snapshot('1.1.1.2', '1.1.1.0/24', [64500])
            ingest_network_snapshot(store, *original)
            ingest_network_snapshot(store, *sibling)
            replacement = snapshot('1.1.1.1', '1.1.0.0/16', [64501])
            with patch.object(store, 'ingest', side_effect=RuntimeError('failed write')):
                with self.assertRaises(RuntimeError):
                    ingest_network_snapshot(store, *replacement)
            with store.connection() as conn:
                self.assertEqual(conn.execute("SELECT to_id FROM edges WHERE from_id='ip:1.1.1.1'").fetchone()[0], 'prefix:1.1.1.0/24')
            ingest_network_snapshot(store, *replacement)
            with store.connection() as conn:
                own = conn.execute('SELECT to_id FROM edges WHERE source_url=? ORDER BY to_id', (original[2],)).fetchall()
                self.assertEqual({row[0] for row in own}, {'prefix:1.1.0.0/16', 'asn:AS64501'})
                self.assertEqual(conn.execute('SELECT count(*) FROM edges WHERE source_url=?', (sibling[2],)).fetchone()[0], 2)
            ingest_network_snapshot(store, *snapshot('1.1.1.1', None, []))
            self.assertEqual({node['id'] for node in KnowledgeGraph(store).graph('ip:1.1.1.1', 2)['nodes']}, {'ip:1.1.1.1'})
            with store.connection() as conn:
                self.assertEqual(conn.execute('SELECT count(*) FROM edges WHERE source_url=?', (sibling[2],)).fetchone()[0], 2)
