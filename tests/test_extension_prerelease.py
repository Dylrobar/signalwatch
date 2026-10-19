import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from fastapi.testclient import TestClient

from signalwatch.api import create_app
from signalwatch.config import DEFAULTS, load_config
from signalwatch.extension_prerelease import FEEDS, _components, collect_prerelease_sources, feed_notes, normalize_prerelease, prereleases
from signalwatch.http import HTTPError
from signalwatch.ingestion import StagingWorker, staging_queue
from signalwatch.normalization import NormalizationError
from signalwatch.sourcehub import stage_payload
from signalwatch.store import Store

FIXTURES = Path(__file__).parent / 'fixtures' / 'prerelease'
STAMP = '2026-10-19T05:00:00+00:00'


def envelope(payload, provider='mikrotik_testing', **metadata):
    return {'id': 1, 'source': 'public:' + provider, 'source_url': 'https://download.mikrotik.com/routeros/7.25rc2/CHANGELOG',
            'payload': payload, 'payload_hash': hashlib.sha256(payload).hexdigest(), 'received_at': STAMP, 'observed_at': STAMP,
            'metadata': {'provider': provider, 'format': 'html', 'vendor': 'MikroTik', 'product': 'RouterOS',
                         'title': 'RouterOS 7.25rc2 [testing]', 'version': '7.25rc2', 'stage': 'rc', 'published': STAMP, **metadata}}


class PrereleaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / 'config.json')
        self.store = Store(self.config['db'])

    def test_defaults_and_saved_operator_disable_are_preserved(self):
        self.assertTrue(self.config['sources']['prerelease'])
        self.assertEqual(self.config['source_intervals']['prerelease'], 60)
        path = Path(self.temp.name) / 'config.json'
        path.write_text(json.dumps({'sources': {'prerelease': False}, 'provider_settings': {'apple_developer': {'enabled': False}}}))
        restored = load_config(path)
        self.assertFalse(restored['sources']['prerelease'])
        self.assertFalse(restored['provider_settings']['apple_developer']['enabled'])
        self.assertTrue(restored['provider_settings']['windows_insider']['enabled'])

    def test_official_windows_hub_becomes_separate_builds_and_channels(self):
        rows = feed_notes((FIXTURES / 'windows-feed.xml').read_bytes(), 'windows_insider')
        self.assertGreaterEqual(len(rows), 6)
        preview = next(row for row in rows if row['stage'] == 'release_preview')
        self.assertEqual(preview['version'], '26200.9807, 26300.9807')
        self.assertTrue(preview['fetch_note'])
        self.assertTrue(preview['source_url'].startswith('https://learn.microsoft.com/'))
        self.assertEqual(rows[0]['stage'], 'beta')
        self.assertEqual(rows[1]['stage'], 'dev')

    def test_official_apple_and_routeros_feeds_keep_beta_rc_and_build(self):
        apple = feed_notes((FIXTURES / 'apple-feed.xml').read_bytes(), 'apple_developer')
        ios = next(row for row in apple if row['product'] == 'iOS')
        self.assertEqual((ios['version'], ios['stage'], ios['build']), ('27.2 beta 4', 'beta', '24B5110a'))
        testing = feed_notes((FIXTURES / 'mikrotik-testing.xml').read_bytes(), 'mikrotik_testing')[0]
        dev = feed_notes((FIXTURES / 'mikrotik-development.xml').read_bytes(), 'mikrotik_testing')[0]
        self.assertEqual((testing['version'], testing['stage']), ('7.25rc2', 'rc'))
        self.assertEqual((dev['version'], dev['stage']), ('7.26beta1', 'beta'))
        self.assertIn('bridge', testing['body'])

    def test_stable_notes_mentioning_old_beta_are_not_prereleases(self):
        for provider, title in [('apple_developer', 'iOS 27.1'), ('mikrotik_testing', 'RouterOS 7.24.1 [stable]')]:
            rss = f'<rss version="2.0"><channel><item><title>{title}</title><link>https://developer.apple.com/news/releases/?id=stable</link><description>Resolved a security bug introduced in beta releases.</description></item></channel></rss>'.encode()
            self.assertEqual(feed_notes(rss, provider), [])

    def test_apple_final_note_suppresses_older_beta_before_classification(self):
        raw = b'''<rss version="2.0"><channel>
          <item><title>Xcode 27.1 beta (27A9269)</title><link>https://developer.apple.com/news/releases/?id=old</link><pubDate>Mon, 05 Oct 2026 17:00:00 GMT</pubDate><description><![CDATA[<a href="https://developer.apple.com/go/?utm_source=rss&amp;id=xcode-27_1-sdk-rn">Notes</a>]]></description></item>
          <item><title>Xcode 27.1 (27A9275)</title><link>https://developer.apple.com/news/releases/?id=final</link><pubDate>Fri, 16 Oct 2026 17:00:00 GMT</pubDate><description><![CDATA[<a href="/go/?id=xcode-27_1-sdk-rn#overview">Notes</a>]]></description></item>
          <item><title>Xcode 27.2 beta 3 (27B5038j)</title><link>https://developer.apple.com/news/releases/?id=current</link><pubDate>Wed, 14 Oct 2026 17:00:00 GMT</pubDate><description><![CDATA[<a href="/go/?id=xcode-27_2-sdk-rn">Notes</a>]]></description></item>
        </channel></rss>'''
        rows = feed_notes(raw, 'apple_developer')
        self.assertEqual([row['version'] for row in rows], ['27.2 beta 3'])

    def test_apple_newest_note_preserves_distinct_products_and_branches(self):
        raw = b'''<rss version="2.0"><channel>
          <item><title>iOS 27.2 beta 3 (24B5100a)</title><link>https://developer.apple.com/news/releases/?id=older-ios</link><pubDate>Mon, 12 Oct 2026 17:00:00 GMT</pubDate><description><![CDATA[<a href="/go/?id=ios-27_2-rn">Notes</a>]]></description></item>
          <item><title>iOS 27.2 beta 4 (24B5110a)</title><link>https://developer.apple.com/news/releases/?id=ios</link><pubDate>Wed, 14 Oct 2026 17:00:00 GMT</pubDate><description><![CDATA[<a href="/go/?id=ios-27_2-rn">Notes</a>]]></description></item>
          <item><title>iPadOS 27.2 beta 4 (24B5110a)</title><link>https://developer.apple.com/news/releases/?id=ipados</link><pubDate>Wed, 14 Oct 2026 17:00:00 GMT</pubDate><description><![CDATA[<a href="/go/?id=ipados-27_2-rn">Notes</a>]]></description></item>
          <item><title>iOS 27.3 beta (24C5001a)</title><link>https://developer.apple.com/news/releases/?id=next-ios</link><pubDate>Thu, 15 Oct 2026 17:00:00 GMT</pubDate><description><![CDATA[<a href="/go/?id=ios-27_3-rn">Notes</a>]]></description></item>
        </channel></rss>'''
        rows = feed_notes(raw, 'apple_developer')
        self.assertEqual({(row['product'], row['version']) for row in rows}, {('iOS', '27.2 beta 4'), ('iPadOS', '27.2 beta 4'), ('iOS', '27.3 beta')})

    def test_invalid_feed_html_and_docc_are_errors(self):
        for raw in (b'<html>Access denied</html>', b'<rss><item>'):
            with self.assertRaises(NormalizationError):
                feed_notes(raw, 'windows_insider')
        with self.assertRaises(NormalizationError):
            normalize_prerelease(envelope(b'{"error":"denied"}', 'apple_developer', format='docc'))
        with self.assertRaises(NormalizationError):
            normalize_prerelease(envelope(b'<html><h1>Access denied</h1><p>Please enable cookies.</p></html>'))

    def test_apple_mutable_note_rejects_older_announcements(self):
        item = envelope((FIXTURES / 'apple-note.json').read_bytes(), 'apple_developer', format='docc', vendor='Apple', product='iOS', title='iOS 27.2 beta 2', version='27.2 beta 2', stage='beta')
        item['source_url'] = 'https://developer.apple.com/tutorials/data/documentation/ios-ipados-release-notes/ios-ipados-27_2-release-notes.json'
        with self.assertRaises(NormalizationError):
            normalize_prerelease(item)

    def test_stage_changes_keep_distinct_release_identity(self):
        raw = b'<p>*) bridge - improved throughput;</p>'
        beta = normalize_prerelease(envelope(raw, stage='beta'))
        rc = normalize_prerelease(envelope(raw, stage='rc'))
        self.assertNotEqual(beta['entities'][0]['id'], rc['entities'][0]['id'])
        rebuilt = normalize_prerelease(envelope(raw, stage='rc', build='reissued'))
        self.assertNotEqual(rebuilt['entities'][0]['id'], rc['entities'][0]['id'])

    def test_apple_codenames_preserve_current_beta_identity(self):
        item = envelope((FIXTURES / 'apple-macos-note.json').read_bytes(), 'apple_developer', format='docc', vendor='Apple', product='macOS', title='macOS 27.2 beta 4', version='27.2 beta 4', stage='beta')
        item['source_url'] = 'https://developer.apple.com/tutorials/data/documentation/macos-release-notes/macos-27_2-release-notes.json'
        current = normalize_prerelease(item)
        self.assertEqual(current['entities'][0]['metadata']['stage'], 'beta')
        item['metadata']['version'] = '27.2 beta 3'
        with self.assertRaises(NormalizationError):
            normalize_prerelease(item)

    def test_ios_ipados_shared_document_preserves_distinct_products(self):
        item = envelope((FIXTURES / 'apple-note.json').read_bytes(), 'apple_developer', format='docc', vendor='Apple', product='iOS', title='iOS 27.2 beta 4', version='27.2 beta 4', stage='beta')
        item['source_url'] = 'https://developer.apple.com/tutorials/data/documentation/ios-ipados-release-notes/ios-ipados-27_2-release-notes.json'
        ios = normalize_prerelease(item)
        item['metadata'].update(product='iPadOS', title='iPadOS 27.2 beta 4')
        ipados = normalize_prerelease(item)
        self.assertNotEqual(ios['entities'][0]['id'], ipados['entities'][0]['id'])
        self.store.ingest(ios)
        self.store.ingest(ipados)
        self.assertEqual(prereleases(self.store)['total'], 2)

    def test_late_cve_reference_node_preserves_authoritative_metadata(self):
        self.store.ingest({'entities': [{'id': 'CVE-2026-90001', 'kind': 'vulnerability', 'name': 'Authoritative advisory title', 'metadata': {'evidence_role': 'verified_advisory'}}]})
        raw = ('<p>*) bridge - fixed net.sys validation;</p>' + '<p>' + 'padding ' * 2000 + '</p><p>*) system - security fix CVE-2026-90001 CVE-2026-90002;</p>').encode()
        self.store.ingest(normalize_prerelease(envelope(raw)))
        self.assertEqual(self.store.detail('CVE-2026-90001')['name'], 'Authoritative advisory title')
        self.assertIsNotNone(self.store.detail('CVE-2026-90002'))

    def test_apple_docc_retains_known_issues_and_resolved_components(self):
        item = envelope((FIXTURES / 'apple-note.json').read_bytes(), 'apple_developer', format='docc', vendor='Apple', product='iOS', title='iOS 27.2 beta 4', version='27.2 beta 4', stage='beta')
        item['source_url'] = 'https://developer.apple.com/tutorials/data/documentation/ios-ipados-release-notes/ios-ipados-27_2-release-notes.json'
        batch = normalize_prerelease(item)
        components = batch['entities'][0]['metadata']['components']
        self.assertTrue(any(x['name'] == 'App Tracking Transparency' and x['kind'] == 'resolved' for x in components))
        self.assertTrue(any(x['name'] == 'Health' and x['kind'] == 'known_issue' for x in components))
        self.assertTrue(any('requestTrackingAuthorization' in x['quote'] for x in components))
        self.assertFalse(batch.get('observations'))
        self.assertFalse(batch.get('advisories'))
        self.assertFalse(batch.get('kev'))

    def test_windows_bracket_sections_map_actual_components(self):
        item = envelope((FIXTURES / 'windows-note.html').read_bytes(), 'windows_insider', vendor='Microsoft', product='Windows', version='26200.9807', stage='release_preview')
        item['source_url'] = 'https://learn.microsoft.com/en-us/windows-insider/release-notes/release-preview-24h2-25h2/build-26200-9807-26300-9807'
        components = normalize_prerelease(item)['entities'][0]['metadata']['components']
        self.assertTrue(any(x['name'] == 'File Explorer' for x in components))
        self.assertFalse(any(x['name'] == 'Gradual rollout' for x in components))

    def test_files_quotes_and_negated_future_changes_are_distinct(self):
        lines = [('Networking', '', 'Fixed a buffer overflow in net.sys (CVE-2026-90001).'),
                 ('Networking', 'Known Issues', 'net.sys may crash when reconnecting.'),
                 ('Networking', '', 'No fix is included for net.sys.'),
                 ('Networking', '', 'We will fix net.sys in a future build.'),
                 ('app', '', 'Added an error when a variable cannot be resolved.')]
        values = _components(lines)
        self.assertEqual([x['kind'] for x in values[:4]], ['resolved', 'known_issue', 'mentioned', 'mentioned'])
        self.assertEqual(values[0]['name'], 'net.sys')
        self.assertEqual(values[-1]['kind'], 'changed')
        self.assertEqual(values[0]['quote'], lines[0][2])

    def test_correction_replaces_latest_and_retains_immutable_history_without_risk(self):
        first = envelope(b'<p>*) bridge - fixed overflow in net.sys CVE-2026-90001;</p>')
        corrected = envelope(b'<p>*) bridge - improved throughput;</p>')
        corrected['received_at'] = corrected['observed_at'] = '2026-10-19T06:00:00+00:00'
        one, two = normalize_prerelease(first), normalize_prerelease(corrected)
        self.store.ingest(one)
        self.store.ingest(one)
        self.store.ingest(two)
        self.store.reconcile()
        rows = prereleases(self.store)
        self.assertEqual(rows['total'], 1)
        latest = rows['items'][0]
        self.assertEqual(latest['first_seen'], STAMP)
        self.assertEqual(latest['observed_at'], corrected['observed_at'])
        self.assertEqual(latest['cves'], [])
        self.assertFalse(latest['security_relevant'])
        self.assertEqual(latest['components'][0]['quote'], '*) bridge - improved throughput;')
        self.assertEqual(self.store.search(kind='prerelease_revision')['total'], 2)
        self.assertEqual(self.store.articles()['items'][0]['cves'], [])
        self.assertNotIn('overflow', self.store.articles()['items'][0]['summary'])
        self.assertEqual(self.store.stats()['observations'], 0)
        self.assertEqual(self.store.stats()['alerts'], 0)
        self.assertEqual(self.store.stats()['advisories'], 0)
        self.assertEqual(self.store.stats()['kev'], 0)

    def test_filter_pagination_literal_search_and_detail(self):
        for version, stage in [('7.25rc2', 'rc'), ('7.26beta1', 'beta')]:
            self.store.ingest(normalize_prerelease(envelope(b'<p>*) bridge - improved throughput;</p>', version=version, stage=stage)))
        self.assertEqual(prereleases(self.store, vendor='mikrotik')['total'], 2)
        self.assertEqual(prereleases(self.store, stage='rc')['total'], 1)
        self.assertEqual(prereleases(self.store, q='%')['total'], 0)
        self.assertEqual(prereleases(self.store, security_only=True)['total'], 0)
        one = prereleases(self.store, limit=1, offset=1)
        self.assertEqual(len(one['items']), 1)
        self.assertIsNotNone(self.store.detail(one['items'][0]['id']))

    def test_authenticated_api_and_bounds(self):
        config = copy.deepcopy(self.config)
        config['api_token'] = 'local-test-token'
        app = create_app(config, auto_collect=False)
        client = TestClient(app)
        self.assertEqual(client.get('/api/prereleases').status_code, 401)
        headers = {'Authorization': 'Bearer local-test-token'}
        for params in ({'limit': 101}, {'offset': 10001}, {'stage': 'stable'}, {'q': 'a' * 301}, {'security_only': 'invalid'}):
            self.assertEqual(client.get('/api/prereleases', params=params, headers=headers).status_code, 422)
        self.assertEqual(client.get('/api/prereleases', headers=headers).status_code, 200)


class PrereleaseCollectorTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.config = load_config(Path(self.temp.name) / 'config.json')
        self.store = Store(self.config['db'])
        self.config['provider_settings'] = {'windows_insider': {'enabled': False}, 'apple_developer': {'enabled': False}, 'mikrotik_testing': {'enabled': True}}
        self.calls = []

    async def fetch(self, url, **kwargs):
        self.calls.append((url, kwargs))
        path = Path(self.temp.name) / hashlib.sha256(url.encode()).hexdigest()
        if url == FEEDS['mikrotik_testing'][0]:
            path.write_bytes((FIXTURES / 'mikrotik-testing.xml').read_bytes())
        elif url == FEEDS['mikrotik_testing'][1]:
            path.write_bytes((FIXTURES / 'mikrotik-development.xml').read_bytes())
        else:
            raise AssertionError('Unexpected request ' + url)
        return SimpleNamespace(path=path, status=200, url=url)

    async def test_raw_staging_duplicate_and_no_binary_requests(self):
        http = SimpleNamespace(get=AsyncMock(side_effect=self.fetch))
        first = await collect_prerelease_sources(self.config, self.store, http)
        self.assertEqual(first['records'], 2, first)
        self.assertEqual(first['staged'], 4)
        report = StagingWorker(self.store, self.config).drain()
        self.assertEqual(report['processed'], 4, report)
        self.assertEqual(prereleases(self.store)['total'], 2)
        second = await collect_prerelease_sources(self.config, self.store, http)
        self.assertEqual(second['provider_health']['mikrotik_testing']['status'], 'unchanged')
        self.assertEqual(second['staged'], 0)
        queue = staging_queue(self.store, self.config)
        for item in queue.list()['items']:
            self.assertTrue(queue.get(item['id'], include_payload=True)['payload'])
        self.assertEqual({url for url, _ in self.calls}, set(FEEDS['mikrotik_testing']))
        self.assertEqual(self.store.stats()['observations'], 0)

    async def test_upstream_failure_sets_cooldown_and_preserves_records(self):
        self.store.ingest(normalize_prerelease(envelope(b'<p>*) bridge - improved throughput;</p>')))
        http = SimpleNamespace(get=AsyncMock(side_effect=HTTPError(403, FEEDS['mikrotik_testing'][0])))
        outcome = await collect_prerelease_sources(self.config, self.store, http)
        self.assertEqual(outcome['provider_health']['mikrotik_testing']['status'], 'error')
        self.assertIn('403', outcome['provider_health']['mikrotik_testing']['error'])
        self.assertTrue(outcome['provider_health']['mikrotik_testing']['retry_at'])
        self.assertEqual(prereleases(self.store)['total'], 1)
        count = http.get.await_count
        again = await collect_prerelease_sources(self.config, self.store, http)
        self.assertEqual(again['provider_health']['mikrotik_testing']['status'], 'deferred')
        self.assertEqual(http.get.await_count, count)

    async def test_dead_letter_duplicate_is_visible_as_collection_failure(self):
        http = SimpleNamespace(get=AsyncMock(side_effect=self.fetch))
        await collect_prerelease_sources(self.config, self.store, http)
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE raw_ingress SET status='dead'")
        again = await collect_prerelease_sources(self.config, self.store, http)
        health = again['provider_health']['mikrotik_testing']
        self.assertEqual(health['status'], 'error')
        self.assertIn('dead-letter', health['error'])

    async def test_private_html_redirect_and_robots_disallow_never_project_notes(self):
        self.config['provider_settings'] = {key: {'enabled': key == 'apple_developer'} for key in FEEDS}
        async def fetch(url, **kwargs):
            path = Path(self.temp.name) / hashlib.sha256(url.encode()).hexdigest()
            if url == FEEDS['apple_developer'][0]:
                path.write_bytes((FIXTURES / 'apple-feed.xml').read_bytes())
            elif url == 'https://developer.apple.com/robots.txt':
                path.write_bytes(b'User-agent: *\nDisallow: /go/\n')
            else:
                raise AssertionError('Robots-blocked note fetched: ' + url)
            return SimpleNamespace(path=path, status=200, url=url)
        result = await collect_prerelease_sources(self.config, self.store, SimpleNamespace(get=AsyncMock(side_effect=fetch)))
        self.assertEqual(result['records'], 0)
        self.assertIn('robots.txt', result['provider_health']['apple_developer']['error'])
        StagingWorker(self.store, self.config).drain()
        self.assertEqual(prereleases(self.store)['total'], 0)
