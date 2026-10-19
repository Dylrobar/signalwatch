import csv
import gzip
import hashlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from signalwatch.staging import StagingQueue
from signalwatch.store import Store
from signalwatch.wireless import datasets, device_detail, devices, iter_wigle_chunks, map_clusters, normalize_wigle, register_dataset, stats, update_dataset_status


HEADER = ['MAC', 'SSID', 'AuthMode', 'FirstSeen', 'Channel', 'Frequency', 'RSSI', 'CurrentLatitude', 'CurrentLongitude', 'AltitudeMeters', 'AccuracyMeters', 'RCOIs', 'MfgrId', 'Type', 'UnknownColumn']


def payload(rows):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream, lineterminator='\r\n')
    writer.writerow(HEADER)
    writer.writerows(rows)
    return stream.getvalue().encode()


def radio(identifier='aa:bb:cc:dd:ee:ff', name='Office', lat='44.5', lon='-73.1', kind='WIFI', **changes):
    row = [identifier, name, '[WPA2]', '2025-01-10 22:14:13', '6', '2437', '-58', lat, lon, '70', '4.5', '', '123', kind, 'keep']
    for key, value in changes.items():
        row[HEADER.index(key)] = value
    return row


class WirelessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / 'wireless.db')

    def batch(self, rows, **metadata):
        return normalize_wigle({'payload': payload(rows), 'source': 'private-upload', 'metadata': metadata})

    def test_preserves_repeats_all_types_unknown_fields_and_naive_timestamp(self):
        rows = [radio(), radio(lat='44.6'), radio('310-260-12345-67890', kind='LTE'), radio('310-260-12345-67890', kind='NR')]
        result = self.store.ingest(self.batch(rows))
        self.assertEqual(result['wireless_observations'], 4)
        self.assertEqual(stats(self.store)['devices'], 3)
        wifi = devices(self.store, radio_type='wifi')['items'][0]
        self.assertEqual(wifi['identifier'], 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(wifi['observation_count'], 2)
        self.assertEqual(wifi['first_seen'], '2025-01-10 22:14:13')
        detail = device_detail(self.store, wifi['id'])
        self.assertEqual(detail['observations_total'], 2)
        self.assertEqual(detail['observations'][0]['raw']['UnknownColumn'], 'keep')
        self.assertEqual(detail['observations'][0]['manufacturer_id'], '123')
        self.assertEqual(detail['location_basis'], 'scan_observation')
        cellular = devices(self.store, radio_type='LTE')['items'][0]
        self.assertEqual(cellular['identifier'], '310-260-12345-67890')
        self.assertEqual(self.store.stats()['observations'], 0)
        self.assertEqual(self.store.stats()['alerts'], 0)
        self.assertEqual(self.store.search(q='Office', kind='wireless_device')['total'], 3)

    def test_invalid_coordinates_and_missing_identity_retained_without_map_point(self):
        rows = [radio(lat='NaN'), radio(identifier='', lat='0', lon='0'), radio(identifier='', lat='95'), radio(identifier='not-a-mac', lat='44.5', AccuracyMeters='-1')]
        self.store.ingest(self.batch(rows))
        self.assertEqual(stats(self.store)['observations'], 4)
        self.assertEqual(stats(self.store)['invalid_coordinates'], 3)
        self.assertEqual(stats(self.store)['devices'], 4)
        points = map_clusters(self.store, [-180, -90, 180, 90])['items']
        self.assertEqual(sum(point['observations'] for point in points), 1)
        with self.store.connection() as conn:
            bad = conn.execute('SELECT raw,validation_errors FROM wireless_observations WHERE source_row=1').fetchone()
            self.assertIn('NaN', bad['raw'])
            self.assertIn('invalid_latitude', bad['validation_errors'])

    def test_gzip_stream_chunks_keep_source_rows_and_multiline_raw_fields(self):
        archive = Path(self.temp.name) / 'export.csv.gz'
        source = b'WigleWifi-1.6,model=device\r\n' + payload([radio(name='one\ntwo'), radio(), radio(kind='BLE')])
        with gzip.open(archive, 'wb') as stream:
            stream.write(source)
        chunks = list(iter_wigle_chunks(archive, rows_per_chunk=2))
        self.assertEqual([chunk['metadata']['row_start'] for chunk in chunks], [1, 3])
        self.assertEqual(chunks[0]['metadata']['source_hash'], hashlib.sha256(archive.read_bytes()).hexdigest())
        self.assertEqual(chunks[0]['metadata']['preamble'], 'WigleWifi-1.6,model=device\r\n')
        self.assertEqual(chunks[0]['payload'] + chunks[1]['payload'].split(b'\r\n', 1)[1], source.split(b'\r\n', 1)[1])
        for chunk in chunks:
            self.store.ingest(normalize_wigle(chunk))
        self.assertEqual(stats(self.store)['observations'], 3)
        self.assertEqual(datasets(self.store)['items'][0]['devices'], 2)

    def test_chunk_reimport_idempotent_and_conflicting_same_dataset_row_rejected(self):
        source_hash = '1' * 64
        first = self.batch([radio(), radio()], source_hash=source_hash, row_start=1)
        second = self.batch([radio(kind='BLE')], source_hash=source_hash, row_start=3)
        self.store.ingest(first)
        self.store.ingest(second)
        duplicate = self.store.ingest(first)
        self.assertEqual(duplicate['wireless_observations'], 0)
        self.assertEqual(duplicate['wireless_duplicates'], 2)
        self.assertEqual(stats(self.store)['observations'], 3)
        with self.assertRaises(ValueError):
            self.store.ingest(self.batch([radio(name='Changed')], source_hash=source_hash, row_start=1))
        self.assertEqual(stats(self.store)['observations'], 3)

    def test_staging_complete_commits_wireless_and_ack_atomically(self):
        queue = StagingQueue(self.store)
        queued = queue.enqueue(payload([radio()]), source='private-upload', adapter='wigle_csv', content_type='text/csv')
        claimed = queue.claim()
        batch = normalize_wigle(claimed)
        batch['entities'] = [{'kind': 'invalid'}]
        with self.assertRaises(KeyError):
            queue.complete(claimed['id'], claimed['lease_token'], batch)
        self.assertEqual(queue.get(queued['id'])['status'], 'processing')
        self.assertEqual(stats(self.store)['observations'], 0)
        queue.complete(claimed['id'], claimed['lease_token'], normalize_wigle(claimed))
        self.assertEqual(queue.get(queued['id'])['status'], 'processed')
        self.assertEqual(stats(self.store)['observations'], 1)

    def test_map_filters_exact_bbox_antimeridian_and_search_escaping(self):
        self.store.ingest(self.batch([radio(name='100%'), radio(identifier='12:34:56:78:90:ab', lat='10', lon='179.9', kind='BLE'), radio(identifier='12:34:56:78:90:ac', lat='10', lon='-179.9', kind='BLE')]))
        result = map_clusters(self.store, [170, 0, -170, 20], radio_type='BLE')
        self.assertEqual(sum(point['observations'] for point in result['items']), 2)
        self.assertEqual(len(map_clusters(self.store, [-74, 44, -73, 45], q='100%')['items']), 1)
        self.assertEqual(devices(self.store, q='100%')['total'], 1)
        self.assertEqual(map_clusters(self.store, [0, 0, 1, 1])['items'], [])
        for bbox in ([0, 0, 400, 5], [0, float('nan'), 4, 6], [1, 2, 3]):
            with self.assertRaises(ValueError):
                map_clusters(self.store, bbox)

    def test_registration_status_and_empty_export(self):
        metadata = {'source_hash': '3' * 64, 'dataset_name': 'Initial'}
        registered = register_dataset(self.store, metadata)
        self.assertEqual(registered['status'], 'queued')
        batch = self.batch([], source_hash=metadata['source_hash'])
        self.store.ingest(batch)
        result = update_dataset_status(self.store, registered['id'], 'complete', queued_rows=0)
        self.assertEqual(result['metadata']['queued_rows'], 0)
        self.assertEqual(result['header'], HEADER)
        self.assertIsNone(datasets(self.store)['items'][0]['bounds'])
        self.assertIsNone(update_dataset_status(self.store, 'missing', 'failed'))
        with self.assertRaises(ValueError):
            update_dataset_status(self.store, registered['id'], 'unsupported')

    def test_bad_header_source_identity_and_chunk_limit_rejected(self):
        for item in ({'payload': b'hello\n'}, {'payload': payload([radio()]), 'metadata': {'source_hash': 'bad'}},
                     {'payload': payload([radio()]), 'metadata': {'row_start': 0}},
                     {'payload': payload([radio()]), 'metadata': {'row_count': 2}},
                     {'payload': payload([radio()]), 'metadata': {'source_hash': '4' * 64, 'dataset_id': 'mismatch'}}):
            with self.assertRaises(ValueError):
                normalize_wigle(item)
        with self.assertRaises(ValueError):
            normalize_wigle({'payload': payload([radio(), radio()])}, max_records=1)
        path = Path(self.temp.name) / 'bad.csv'
        path.write_text('')
        with self.assertRaises(ValueError):
            list(iter_wigle_chunks(path))

    def test_old_chunk_does_not_replace_newer_representative_scan_or_label(self):
        newer = self.batch([radio(name='Current', lat='45', FirstSeen='2026-01-01 10:00:00')], source_hash='5' * 64)
        older = self.batch([radio(name='Historic', lat='42', FirstSeen='2025-01-01 10:00:00')], source_hash='6' * 64)
        self.store.ingest(newer)
        self.store.ingest(older)
        device = devices(self.store)['items'][0]
        self.assertEqual(device['latitude'], 45)
        self.assertEqual(device['ssid'], 'Current')
        self.assertEqual(device['last_seen'], '2026-01-01 10:00:00')
        self.assertEqual(device['metadata']['representative_observation']['dataset_id'], newer['wireless_batch']['dataset_id'])
        self.assertEqual(self.store.search(q='Current', kind='wireless_device')['total'], 1)
        self.assertEqual(self.store.search(q='Historic', kind='wireless_device')['total'], 0)
        self.assertEqual(device['observation_count'], 2)

    def test_native_wigle_utc_epoch_and_frequency_interpretation(self):
        source = b'WigleWifi-1.6,model=phone\n' + payload([radio(kind='BLE'), radio(identifier='12:34:56:78:90:ac', kind='BT', FirstSeen='1970-01-01 00:00:00')])
        batch = normalize_wigle({'payload': source})
        self.assertEqual(batch['wireless_batch']['metadata']['timestamp_timezone'], 'UTC')
        self.store.ingest(batch)
        ble = devices(self.store, radio_type='BLE')['items'][0]
        self.assertEqual(ble['last_seen'], '2025-01-10T22:14:13+00:00')
        self.assertEqual(ble['metadata']['frequency_semantics'], 'device_class')
        bt = devices(self.store, radio_type='BT')['items'][0]
        self.assertIsNone(bt['last_seen'])
        observation = device_detail(self.store, bt['id'])['observations'][0]
        self.assertIn('unknown_epoch_timestamp', observation['validation_errors'])
        self.assertEqual(observation['raw']['FirstSeen'], '1970-01-01 00:00:00')

    def test_rejected_company_attribution_is_excluded_from_filters_and_profile(self):
        self.store.ingest(self.batch([radio()]))
        identity = devices(self.store)['items'][0]['id']
        company = self.store.save_company_profile(name='Company')
        with self.store.connection(write=True) as conn:
            conn.execute("INSERT INTO wireless_company_links(device_id,company_id,role,status,origin,source_url,observed_at,updated_at) VALUES(?,?,'candidate_business','candidate','facility_match','https://example.test','2026-01-01','2026-01-01')", (identity, company['id']))
        self.assertEqual(devices(self.store, company_id=company['id'])['total'], 1)
        self.assertEqual(map_clusters(self.store, [-180, -90, 180, 90], company_id=company['id'])['total'], 1)
        self.assertEqual(self.store.detail(company['id'])['wireless_summary']['counts_by_role']['candidate_business'], 1)
        with self.store.connection(write=True) as conn:
            conn.execute("INSERT INTO wireless_company_links(device_id,company_id,role,status,origin,source_url,observed_at,updated_at) VALUES(?,?,'rejected','rejected','manual','https://example.test','2026-01-01','2026-01-01')", (identity, company['id']))
        self.assertEqual(devices(self.store, company_id=company['id'])['total'], 0)
        self.assertEqual(map_clusters(self.store, [-180, -90, 180, 90], company_id=company['id'])['total'], 0)
        self.assertEqual(self.store.detail(company['id'])['wireless_summary']['counts_by_role'], {})

    def test_cluster_total_survives_limit_and_complete_summary_cache_invalidates(self):
        batch = self.batch([radio(), radio(identifier='12:34:56:78:90:ab', lat='10', lon='179.9')], source_hash='7' * 64)
        self.store.ingest(batch)
        result = map_clusters(self.store, [-180, -90, 180, 90], zoom=20, limit=1)
        self.assertEqual(result['total'], 2)
        self.assertTrue(result['truncated'])
        self.assertEqual(len(result['items']), 1)
        update_dataset_status(self.store, batch['wireless_batch']['dataset_id'], 'complete')
        self.assertEqual(datasets(self.store)['items'][0]['metadata']['_summary']['observations'], 2)
        self.store.ingest(self.batch([radio(kind='BLE')], source_hash='7' * 64, row_start=3))
        self.assertEqual(datasets(self.store)['items'][0]['devices'], 3)

    def test_stats_scope_distinct_devices_locations_cache_and_active_company_links(self):
        first = self.batch([radio(), radio(kind='BLE')], source_hash='8' * 64)
        second = self.batch([radio(lat='NaN'), radio(identifier='310_123_456', kind='LTE')], source_hash='9' * 64)
        self.store.ingest(first)
        self.store.ingest(second)
        first_id, second_id = first['wireless_batch']['dataset_id'], second['wireless_batch']['dataset_id']
        wifi_id = devices(self.store, radio_type='WIFI')['items'][0]['id']
        ble_id = devices(self.store, radio_type='BLE')['items'][0]['id']
        with self.store.connection(write=True) as conn:
            conn.executemany("INSERT INTO wireless_company_links(device_id,company_id,role,status,origin,source_url,observed_at,updated_at) VALUES(?,?,?,'candidate','registry','https://example.test','2026-01-01','2026-01-01')",
                             [(wifi_id, 'company:a', 'manufacturer'), (wifi_id, 'company:a', 'candidate_business'), (ble_id, 'company:b', 'manufacturer')])
        global_stats = stats(self.store)
        self.assertEqual((global_stats['datasets'], global_stats['devices'], global_stats['observations'], global_stats['located_devices']), (2, 3, 4, 3))
        self.assertEqual(global_stats['company_links'], 3)
        scoped = stats(self.store, second_id)
        self.assertEqual((scoped['datasets'], scoped['devices'], scoped['observations'], scoped['located_devices'], scoped['invalid_coordinates']), (1, 2, 2, 1, 1))
        self.assertEqual(scoped['radio_types'], {'LTE': 1, 'WIFI': 1})
        self.assertEqual(scoped['rawradio_types'], scoped['signal_types'])
        self.assertEqual(scoped['company_links'], 2)
        update_dataset_status(self.store, first_id, 'complete')
        with patch('signalwatch.wireless._dataset_summary', side_effect=AssertionError('fresh cache must avoid scanning observations')):
            cached = stats(self.store, first_id)
        self.assertEqual(cached['located_devices'], 2)
        self.assertEqual(cached['signal_types'], {'BLE': 1, 'WIFI': 1})
        with self.store.connection(write=True) as conn:
            conn.execute("INSERT INTO wireless_company_links(device_id,company_id,role,status,origin,source_url,observed_at,updated_at) VALUES(?,'company:a','rejected','rejected','manual','https://example.test','2026-01-01','2026-01-01')", (wifi_id,))
        self.assertEqual(stats(self.store)['company_links'], 1)
        self.assertEqual(stats(self.store, first_id)['company_links'], 1)
        self.assertEqual(stats(self.store, second_id)['company_links'], 0)
        missing = stats(self.store, 'missing')
        self.assertEqual((missing['datasets'], missing['devices'], missing['observations'], missing['located_devices'], missing['company_links']), (0, 0, 0, 0, 0))
        self.assertEqual(missing['signal_types'], {})

    def test_missing_extra_columns_retained_as_row_validation(self):
        short = radio()[:-3]
        long = radio() + ['extra-value']
        self.store.ingest(self.batch([short, long]))
        with self.store.connection() as conn:
            rows = conn.execute('SELECT raw,validation_errors FROM wireless_observations ORDER BY source_row').fetchall()
        self.assertIn('column_count_mismatch', rows[0]['validation_errors'])
        self.assertIn('__extra__', rows[1]['raw'])
        self.assertIn('extra-value', rows[1]['raw'])
