import csv
import gzip
import hashlib
import io
import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path


WIRELESS_SCHEMA = """
CREATE TABLE IF NOT EXISTS wireless_datasets (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, source_hash TEXT NOT NULL, source_url TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'queued',
 header TEXT NOT NULL, preamble TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}',
 observation_count INTEGER NOT NULL DEFAULT 0, invalid_coordinate_count INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS wireless_devices (
 id TEXT PRIMARY KEY, radio_type TEXT NOT NULL, identifier TEXT NOT NULL, ssid TEXT NOT NULL DEFAULT '',
 manufacturer_id TEXT NOT NULL DEFAULT '', first_seen TEXT, last_seen TEXT, observation_count INTEGER NOT NULL DEFAULT 0,
 latitude REAL, longitude REAL, rssi REAL, accuracy_meters REAL, metadata TEXT NOT NULL DEFAULT '{}', updated_at TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS wireless_identifier ON wireless_devices(radio_type,identifier) WHERE identifier!='';
CREATE INDEX IF NOT EXISTS wireless_type ON wireless_devices(radio_type,id);
CREATE INDEX IF NOT EXISTS wireless_device_order ON wireless_devices(observation_count DESC,id);
CREATE INDEX IF NOT EXISTS wireless_located_devices ON wireless_devices(id)
 WHERE latitude IS NOT NULL AND longitude IS NOT NULL;
CREATE TABLE IF NOT EXISTS wireless_observations (
 id INTEGER PRIMARY KEY, dataset_id TEXT NOT NULL, source_row INTEGER NOT NULL, device_id TEXT NOT NULL,
 radio_type TEXT NOT NULL, identifier TEXT NOT NULL, ssid TEXT NOT NULL DEFAULT '', auth_mode TEXT NOT NULL DEFAULT '',
 observed_at TEXT, channel REAL, frequency REAL, rssi REAL, latitude REAL, longitude REAL,
 altitude_meters REAL, accuracy_meters REAL, rcois TEXT NOT NULL DEFAULT '', manufacturer_id TEXT NOT NULL DEFAULT '',
 raw TEXT NOT NULL, validation_errors TEXT NOT NULL DEFAULT '[]', UNIQUE(dataset_id,source_row)
);
CREATE INDEX IF NOT EXISTS wireless_observation_device ON wireless_observations(device_id,id DESC);
CREATE INDEX IF NOT EXISTS wireless_observation_dataset_device ON wireless_observations(dataset_id,device_id);
CREATE VIRTUAL TABLE IF NOT EXISTS wireless_observation_geo USING rtree(observation_id,min_lat,max_lat,min_lon,max_lon);
CREATE TRIGGER IF NOT EXISTS wireless_observation_geo_insert AFTER INSERT ON wireless_observations
 WHEN new.latitude IS NOT NULL AND new.longitude IS NOT NULL BEGIN
 INSERT INTO wireless_observation_geo VALUES(new.id,new.latitude,new.latitude,new.longitude,new.longitude);
END;
CREATE TRIGGER IF NOT EXISTS wireless_observation_geo_delete AFTER DELETE ON wireless_observations BEGIN
 DELETE FROM wireless_observation_geo WHERE observation_id=old.id;
END;
"""


def _json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':'), allow_nan=False)


def _now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def device_id(radio_type, identifier, dataset_id='', source_row=0):
    identity = [radio_type, identifier] if identifier else [radio_type, dataset_id, source_row]
    return 'wireless:' + hashlib.sha256(_json(identity).encode()).hexdigest()[:32]


class _CapturedLines:
    def __init__(self, stream):
        self.stream = stream
        self.lines = []

    def __iter__(self):
        return self

    def __next__(self):
        line = next(self.stream)
        self.lines.append(line)
        return line

    def take(self):
        text = ''.join(self.lines)
        self.lines.clear()
        return text


def iter_wigle_chunks(path, rows_per_chunk=5000):
    if not 1 <= int(rows_per_chunk) <= 5000:
        raise ValueError('rows_per_chunk must be between 1 and 5000')
    path = Path(path)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    source_hash = digest.hexdigest()
    with path.open('rb') as probe:
        compressed = probe.read(2) == b'\x1f\x8b'
    opener = gzip.open if compressed else open
    with opener(path, 'rt', encoding='utf-8-sig', errors='strict', newline='') as stream:
        lines = _CapturedLines(stream)
        reader = csv.reader(lines)
        try:
            first = next(reader)
        except StopIteration:
            raise ValueError('WiGLE export is empty') from None
        first_raw = lines.take()
        if first and first[0].strip().lower().startswith('wiglewifi-'):
            preamble = first_raw
            try:
                header = next(reader)
            except StopIteration:
                raise ValueError('WiGLE export has no column header') from None
            header_raw = lines.take()
        else:
            preamble, header, header_raw = '', first, first_raw
        if 'MAC' not in header or 'Type' not in header:
            raise ValueError('Expected WiGLE MAC and Type columns')
        start, count, pieces = 1, 0, []
        for _ in reader:
            pieces.append(lines.take())
            count += 1
            if count >= rows_per_chunk:
                yield _chunk(path.name, source_hash, header, header_raw, preamble, start, count, pieces)
                start += count
                count, pieces = 0, []
        if count:
            yield _chunk(path.name, source_hash, header, header_raw, preamble, start, count, pieces)
        elif start == 1:
            yield _chunk(path.name, source_hash, header, header_raw, preamble, 1, 0, [])


def _chunk(name, source_hash, header, header_raw, preamble, start, count, pieces):
    return {'payload': (header_raw + ''.join(pieces)).encode('utf-8'), 'adapter': 'wigle_csv', 'content_type': 'text/csv',
            'metadata': {'dataset_id': 'wireless:' + source_hash, 'dataset_name': name, 'source_hash': source_hash,
                         'header': header, 'preamble': preamble, 'row_start': start, 'row_count': count,
                         'dataset_format': 'wigle_csv', 'location_basis': 'scan_observation', 'timestamp_timezone': 'UTC' if preamble.strip().lower().startswith('wiglewifi-') else 'unspecified'}}


def normalize_wigle(item, max_records=5000):
    payload = item.get('payload') or b''
    if not isinstance(payload, bytes):
        raise ValueError('WiGLE payload must be bytes')
    metadata = item.get('metadata') or {}
    source_hash = str(metadata.get('source_hash') or hashlib.sha256(payload).hexdigest()).lower()
    if not re.fullmatch('[0-9a-f]{64}', source_hash):
        raise ValueError('source_hash must be a SHA-256 digest')
    dataset = 'wireless:' + source_hash
    if metadata.get('dataset_id') and metadata['dataset_id'] != dataset:
        raise ValueError('dataset_id must match source_hash')
    start = metadata.get('row_start', 1)
    if isinstance(start, bool) or not isinstance(start, int) or start < 1:
        raise ValueError('row_start must be a positive integer')
    text = payload.decode('utf-8-sig')
    reader = csv.reader(io.StringIO(text, newline=''))
    try:
        header = next(reader)
    except StopIteration:
        raise ValueError('WiGLE payload is empty') from None
    preamble = str(metadata.get('preamble') or '')
    if header and header[0].strip().lower().startswith('wiglewifi-'):
        preamble = _json(header)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError('WiGLE payload has no column header') from None
    if 'MAC' not in header or 'Type' not in header or len(header) != len(set(header)):
        raise ValueError('Expected unique WiGLE columns including MAC and Type')
    native_wigle = preamble.strip().lower().startswith(('wiglewifi-', '["wiglewifi-'))
    rows = []
    for index, fields in enumerate(reader):
        if index >= max_records:
            raise ValueError('WiGLE chunk exceeds normalized record limit')
        raw = {name: fields[position] if position < len(fields) else '' for position, name in enumerate(header)}
        if len(fields) > len(header):
            raw['__extra__'] = fields[len(header):]
        errors = []
        if len(fields) != len(header):
            errors.append('column_count_mismatch')
        radio_type = raw.get('Type', '').strip().upper() or 'UNKNOWN'
        identifier = raw.get('MAC', '').strip()
        if not identifier:
            errors.append('missing_identifier')
        elif radio_type in ('WIFI', 'BT', 'BLE'):
            compact = re.sub('[:-]', '', identifier)
            if re.fullmatch('[0-9a-fA-F]{12}', compact):
                identifier = ':'.join(compact[i:i + 2] for i in range(0, 12, 2)).upper()
            else:
                errors.append('invalid_mac_identifier')
        values = {}
        for source, target in [('Channel', 'channel'), ('Frequency', 'frequency'), ('RSSI', 'rssi'),
                               ('CurrentLatitude', 'latitude'), ('CurrentLongitude', 'longitude'),
                               ('AltitudeMeters', 'altitude_meters'), ('AccuracyMeters', 'accuracy_meters')]:
            value = raw.get(source, '').strip()
            try:
                number = float(value) if value else None
                if number is not None and not math.isfinite(number):
                    raise ValueError
            except ValueError:
                number = None
                errors.append('invalid_' + target)
            values[target] = number
        lat, lon = values['latitude'], values['longitude']
        if lat is None or lon is None or not -90 <= lat <= 90 or not -180 <= lon <= 180 or (lat == 0 and lon == 0):
            errors.append('invalid_coordinates' if lat is None or lon is None or not -90 <= lat <= 90 or not -180 <= lon <= 180 else 'zero_coordinates')
            values['latitude'] = values['longitude'] = None
        if values['accuracy_meters'] is not None and values['accuracy_meters'] < 0:
            values['accuracy_meters'] = None
            errors.append('invalid_accuracy_meters')
        observed_at = raw.get('FirstSeen', '')
        if observed_at:
            try:
                instant = datetime.fromisoformat(observed_at)
                if instant.year == 1970:
                    observed_at = None
                    errors.append('unknown_epoch_timestamp')
                elif native_wigle:
                    observed_at = (instant.replace(tzinfo=timezone.utc) if instant.tzinfo is None else instant.astimezone(timezone.utc)).isoformat(timespec='seconds')
            except ValueError:
                errors.append('invalid_observed_at')
                observed_at = None
        row = {'source_row': start + index, 'raw': raw, 'identifier': identifier, 'radio_type': radio_type,
               'ssid': raw.get('SSID', ''), 'auth_mode': raw.get('AuthMode', ''), 'observed_at': observed_at,
               'manufacturer_id': raw.get('MfgrId', ''), 'rcois': raw.get('RCOIs', ''), 'validation_errors': errors, **values}
        row['device_id'] = device_id(radio_type, identifier, dataset, row['source_row'])
        rows.append(row)
    expected = metadata.get('row_count')
    if expected is not None and (isinstance(expected, bool) or not isinstance(expected, int) or expected != len(rows)):
        raise ValueError('WiGLE row_count does not match payload')
    return {'wireless_batch': {'dataset_id': dataset, 'name': str(metadata.get('dataset_name') or item.get('source') or 'WiGLE export'),
                               'source_hash': source_hash, 'header': header, 'preamble': preamble,
                               'source_url': str(item.get('source_url') or ''), 'metadata': {'location_basis': 'scan_observation', 'timestamp_timezone': 'UTC' if native_wigle else 'unspecified', 'frequency_semantics': {'WIFI': 'MHz', 'BT': 'device_class', 'BLE': 'device_class', 'GSM': 'ARFCN', 'LTE': 'EARFCN', 'NR': 'NR_ARFCN'}},
                               'rows': rows}}


def ingest_wireless(store, conn, batch, timestamp=None):
    timestamp = timestamp or _now()
    dataset = batch['dataset_id']
    if dataset != 'wireless:' + batch['source_hash']:
        raise ValueError('Wireless dataset identity must match source hash')
    rows = batch.get('rows') or []
    if len(rows) > 5000:
        raise ValueError('Wireless batch exceeds 5000 rows')
    existing = conn.execute('SELECT source_hash,header FROM wireless_datasets WHERE id=?', (dataset,)).fetchone()
    if existing and (existing['source_hash'] != batch['source_hash'] or (existing['header'] != '[]' and existing['header'] != _json(batch['header']))):
        raise ValueError('Wireless dataset metadata conflicts with existing dataset')
    conn.execute('''INSERT INTO wireless_datasets(id,name,source_hash,source_url,header,preamble,metadata,created_at,updated_at)
     VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING''',
     (dataset, batch['name'], batch['source_hash'], batch.get('source_url', ''), _json(batch['header']), batch.get('preamble', ''), _json(batch.get('metadata') or {}), timestamp, timestamp))
    if existing and existing['header'] == '[]':
        conn.execute('UPDATE wireless_datasets SET header=?,preamble=? WHERE id=?', (_json(batch['header']), batch.get('preamble', ''), dataset))
    seen = set()
    for row in rows:
        source_row = row['source_row']
        if isinstance(source_row, bool) or not isinstance(source_row, int) or source_row < 1 or source_row in seen:
            raise ValueError('Wireless source rows must be unique positive integers')
        seen.add(source_row)
        if row['device_id'] != device_id(row['radio_type'], row['identifier'], dataset, source_row):
            raise ValueError('Wireless device identity is inconsistent')
    existing_rows = {}
    if seen:
        existing_rows = {row['source_row']: row['raw'] for row in conn.execute('SELECT source_row,raw FROM wireless_observations WHERE dataset_id=? AND source_row BETWEEN ? AND ?', (dataset, min(seen), max(seen)))}
    fresh = []
    for row in rows:
        raw = _json(row['raw'])
        if row['source_row'] in existing_rows:
            if existing_rows[row['source_row']] != raw:
                raise ValueError('Wireless source row conflicts with retained raw record')
        else:
            fresh.append(row)
    columns = ['source_row', 'device_id', 'radio_type', 'identifier', 'ssid', 'auth_mode', 'observed_at', 'channel', 'frequency', 'rssi', 'latitude', 'longitude', 'altitude_meters', 'accuracy_meters', 'rcois', 'manufacturer_id']
    conn.executemany('INSERT INTO wireless_observations(dataset_id,' + ','.join(columns) + ',raw,validation_errors) VALUES(' + ','.join('?' for _ in range(len(columns) + 3)) + ')',
                     [(dataset, *(row.get(key) for key in columns), _json(row['raw']), _json(row['validation_errors'])) for row in fresh])
    groups = defaultdict(list)
    for row in fresh:
        groups[row['device_id']].append(row)
    device_values = []
    for identity, observations in groups.items():
        last = max(enumerate(observations), key=lambda value: (bool(value[1].get('observed_at')), value[1].get('observed_at') or '', value[0]))[1]
        locations = [value for value in observations if value['latitude'] is not None]
        located = max(enumerate(locations), key=lambda value: (bool(value[1].get('observed_at')), value[1].get('observed_at') or '', value[0]))[1] if locations else last
        times = [value['observed_at'] for value in observations if value.get('observed_at')]
        meta = {'location_basis': 'scan_observation', 'timestamp_timezone': (batch.get('metadata') or {}).get('timestamp_timezone', 'unspecified'), 'radio_type': last['radio_type'], 'frequency_semantics': {'WIFI': 'MHz', 'BT': 'device_class', 'BLE': 'device_class', 'GSM': 'ARFCN', 'LTE': 'EARFCN', 'NR': 'NR_ARFCN'}.get(last['radio_type'], 'source_defined')}
        if located['latitude'] is not None:
            meta['representative_observation'] = {'dataset_id': dataset, 'source_row': located['source_row'], 'observed_at': located['observed_at'], 'timestamp_timezone': meta['timestamp_timezone'], 'selection_basis': 'latest_reported_scan_time' if located['observed_at'] else 'last_ingested_scan_without_time'}
        if re.fullmatch('(?:[0-9A-F]{2}:){5}[0-9A-F]{2}', last['identifier']):
            octet = int(last['identifier'][:2], 16)
            meta.update({'locally_administered': bool(octet & 2), 'multicast': bool(octet & 1)})
        device_values.append((identity, last['radio_type'], last['identifier'], last['ssid'], last['manufacturer_id'], min(times) if times else None, max(times) if times else None, len(observations), located['latitude'], located['longitude'], located['rssi'], located['accuracy_meters'], _json(meta), timestamp))
    choose_location = "(excluded.latitude IS NOT NULL AND (wireless_devices.latitude IS NULL OR json_extract(wireless_devices.metadata,'$.representative_observation.observed_at') IS NULL OR julianday(json_extract(excluded.metadata,'$.representative_observation.observed_at'))>=julianday(json_extract(wireless_devices.metadata,'$.representative_observation.observed_at'))))"
    choose_label = "(wireless_devices.last_seen IS NULL OR (excluded.last_seen IS NOT NULL AND julianday(excluded.last_seen)>=julianday(wireless_devices.last_seen)))"
    conn.executemany('''INSERT INTO wireless_devices(id,radio_type,identifier,ssid,manufacturer_id,first_seen,last_seen,observation_count,latitude,longitude,rssi,accuracy_meters,metadata,updated_at)
     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET
     ssid=CASE WHEN excluded.ssid!='' AND (wireless_devices.ssid='' OR CHOOSE_LABEL) THEN excluded.ssid ELSE wireless_devices.ssid END,
     manufacturer_id=CASE WHEN excluded.manufacturer_id!='' AND (wireless_devices.manufacturer_id='' OR CHOOSE_LABEL) THEN excluded.manufacturer_id ELSE wireless_devices.manufacturer_id END,
     first_seen=CASE WHEN wireless_devices.first_seen IS NULL THEN excluded.first_seen WHEN excluded.first_seen IS NULL THEN wireless_devices.first_seen ELSE min(wireless_devices.first_seen,excluded.first_seen) END,
     last_seen=CASE WHEN wireless_devices.last_seen IS NULL THEN excluded.last_seen WHEN excluded.last_seen IS NULL THEN wireless_devices.last_seen ELSE max(wireless_devices.last_seen,excluded.last_seen) END,
     observation_count=wireless_devices.observation_count+excluded.observation_count,
     latitude=CASE WHEN CHOOSE_LOCATION THEN excluded.latitude ELSE wireless_devices.latitude END,
     longitude=CASE WHEN CHOOSE_LOCATION THEN excluded.longitude ELSE wireless_devices.longitude END,
     rssi=CASE WHEN CHOOSE_LOCATION THEN excluded.rssi ELSE wireless_devices.rssi END,
     accuracy_meters=CASE WHEN CHOOSE_LOCATION THEN excluded.accuracy_meters ELSE wireless_devices.accuracy_meters END,
     metadata=CASE WHEN CHOOSE_LOCATION THEN json_patch(wireless_devices.metadata,excluded.metadata) ELSE json_patch(wireless_devices.metadata,json_remove(excluded.metadata,'$.representative_observation')) END,updated_at=excluded.updated_at'''.replace('CHOOSE_LOCATION', choose_location).replace('CHOOSE_LABEL', choose_label), device_values)
    if groups:
        conn.execute('''INSERT INTO entities(id,kind,name,value,metadata,observed_at,source_url,confidence,updated_at)
         SELECT id,'wireless_device',coalesce(nullif(ssid,''),nullif(identifier,''),id),coalesce(nullif(identifier,''),id),
         metadata,coalesce(last_seen,?),?,1.0,? FROM wireless_devices WHERE id IN (''' + ','.join('?' for _ in groups) + ''')
         ON CONFLICT(id) DO UPDATE SET name=excluded.name,metadata=json_patch(entities.metadata,excluded.metadata),
         observed_at=excluded.observed_at,updated_at=excluded.updated_at''', (timestamp, batch.get('source_url', ''), timestamp, *groups))
    conn.execute('UPDATE wireless_datasets SET metadata=json_patch(metadata,?) WHERE id=?', (_json(batch.get('metadata') or {}), dataset))
    invalid = sum(row['latitude'] is None for row in fresh)
    conn.execute('UPDATE wireless_datasets SET observation_count=observation_count+?,invalid_coordinate_count=invalid_coordinate_count+?,updated_at=? WHERE id=?', (len(fresh), invalid, timestamp, dataset))
    return {'wireless_observations': len(fresh), 'wireless_devices': len(groups), 'wireless_duplicates': len(rows) - len(fresh), 'wireless_invalid_coordinates': invalid}


def _decoded(row):
    result = dict(row)
    for key in ('raw', 'metadata', 'header', 'validation_errors'):
        if key in result and isinstance(result[key], str):
            result[key] = json.loads(result[key])
    return result


def register_dataset(store, metadata, status='queued'):
    source_hash = str(metadata.get('source_hash') or '').lower()
    if not re.fullmatch('[0-9a-f]{64}', source_hash):
        raise ValueError('source_hash must be a SHA-256 digest')
    dataset = 'wireless:' + source_hash
    if metadata.get('dataset_id') and metadata['dataset_id'] != dataset:
        raise ValueError('dataset_id must match source_hash')
    if status not in ('queued', 'importing', 'complete', 'failed'):
        raise ValueError('Invalid wireless dataset status')
    timestamp = _now()
    with store.connection(write=True) as conn:
        conn.execute('''INSERT INTO wireless_datasets(id,name,source_hash,source_url,status,header,preamble,metadata,created_at,updated_at)
         VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING''',
         (dataset, str(metadata.get('dataset_name') or 'WiGLE export'), source_hash, str(metadata.get('source_url') or ''), status,
          _json(metadata.get('header') or []), str(metadata.get('preamble') or ''),
          _json({'location_basis': 'scan_observation', 'timestamp_timezone': 'UTC' if str(metadata.get('preamble') or '').strip().lower().startswith('wiglewifi-') else metadata.get('timestamp_timezone', 'unspecified')}), timestamp, timestamp))
        return _decoded(conn.execute('SELECT * FROM wireless_datasets WHERE id=?', (dataset,)).fetchone())


def update_dataset_status(store, dataset_id, status, **progress):
    if status not in ('queued', 'importing', 'complete', 'failed'):
        raise ValueError('Invalid wireless dataset status')
    with store.connection(write=True) as conn:
        if status == 'complete':
            progress['_summary'] = _dataset_summary(conn, dataset_id)
        changed = conn.execute('UPDATE wireless_datasets SET status=?,metadata=json_patch(metadata,?),updated_at=? WHERE id=?',
                               (status, _json(progress), _now(), dataset_id)).rowcount
        return _decoded(conn.execute('SELECT * FROM wireless_datasets WHERE id=?', (dataset_id,)).fetchone()) if changed else None


def _dataset_summary(conn, dataset_id):
    row = conn.execute('SELECT count(*) AS observations,count(DISTINCT device_id) AS devices,count(DISTINCT CASE WHEN latitude IS NOT NULL AND longitude IS NOT NULL THEN device_id END) AS located_devices,min(longitude) AS west,min(latitude) AS south,max(longitude) AS east,max(latitude) AS north FROM wireless_observations WHERE dataset_id=?', (dataset_id,)).fetchone()
    radio_types = {value[0]: value[1] for value in conn.execute('SELECT radio_type,count(DISTINCT device_id) FROM wireless_observations WHERE dataset_id=? GROUP BY radio_type ORDER BY radio_type', (dataset_id,))}
    return {'observations': row['observations'], 'devices': row['devices'], 'located_devices': row['located_devices'], 'radio_types': radio_types,
            'bounds': [row[key] for key in ('west', 'south', 'east', 'north')] if row['west'] is not None else None,
            'signal_types': list(radio_types)}


def datasets(store, limit=50, offset=0):
    limit, offset = min(500, max(1, int(limit))), max(0, int(offset))
    with store.connection() as conn:
        items = [_decoded(row) for row in conn.execute('SELECT * FROM wireless_datasets ORDER BY created_at DESC,id LIMIT ? OFFSET ?', (limit, offset))]
        for item in items:
            summary = item['metadata'].get('_summary') or {}
            if summary.get('observations') != item['observation_count'] or not all(key in summary for key in ('devices', 'bounds', 'signal_types')):
                summary = _dataset_summary(conn, item['id'])
            item.update({key: summary[key] for key in ('devices', 'bounds', 'signal_types')})
        return {'items': items, 'total': conn.execute('SELECT count(*) FROM wireless_datasets').fetchone()[0]}


def _device_filters(q='', radio_type='', dataset_id='', company_id=''):
    filters, values = [], []
    if q:
        filters.append("(d.identifier LIKE ? ESCAPE '\\' OR d.ssid LIKE ? ESCAPE '\\')")
        pattern = '%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        values.extend((pattern, pattern))
    if radio_type:
        filters.append('d.radio_type=?')
        values.append(radio_type.upper())
    if dataset_id:
        filters.append('EXISTS(SELECT 1 FROM wireless_observations wo WHERE wo.device_id=d.id AND wo.dataset_id=?)')
        values.append(dataset_id)
    if company_id:
        filters.append("EXISTS(SELECT 1 FROM wireless_company_links wl WHERE wl.device_id=d.id AND wl.company_id=? AND wl.status!='rejected' AND NOT EXISTS(SELECT 1 FROM wireless_company_links deny WHERE deny.device_id=wl.device_id AND deny.company_id=wl.company_id AND deny.origin='manual' AND deny.status='rejected'))")
        values.append(company_id)
    return filters, values


def devices(store, q='', radio_type='', dataset_id='', company_id='', limit=50, offset=0):
    limit, offset = min(500, max(1, int(limit))), max(0, int(offset))
    filters, values = _device_filters(q, radio_type, dataset_id, company_id)
    where = ' WHERE ' + ' AND '.join(filters) if filters else ''
    with store.connection() as conn:
        total = conn.execute('SELECT count(*) FROM wireless_devices d' + where, values).fetchone()[0]
        items = [_decoded(row) for row in conn.execute('SELECT d.* FROM wireless_devices d' + where + ' ORDER BY d.observation_count DESC,d.id LIMIT ? OFFSET ?', (*values, limit, offset))]
    return {'items': items, 'total': total, 'location_basis': 'scan_observation'}


def device_detail(store, identity, limit=100, offset=0):
    limit, offset = min(500, max(1, int(limit))), max(0, int(offset))
    with store.connection() as conn:
        row = conn.execute('SELECT * FROM wireless_devices WHERE id=?', (identity,)).fetchone()
        if row is None:
            return None
        item = _decoded(row)
        item['observations'] = [_decoded(value) for value in conn.execute('SELECT o.*,d.name AS dataset_name,d.source_url FROM wireless_observations o JOIN wireless_datasets d ON d.id=o.dataset_id WHERE device_id=? ORDER BY o.id DESC LIMIT ? OFFSET ?', (identity, limit, offset))]
        item['observations_total'] = item['observation_count']
        item['location_basis'] = 'scan_observation'
        return item


def _bbox(bbox):
    if isinstance(bbox, str):
        bbox = bbox.split(',')
    if not isinstance(bbox, (tuple, list)) or len(bbox) != 4:
        raise ValueError('bbox must contain west,south,east,north')
    west, south, east, north = [float(value) for value in bbox]
    if not all(math.isfinite(value) for value in (west, south, east, north)) or not -180 <= west <= 180 or not -180 <= east <= 180 or not -90 <= south <= north <= 90:
        raise ValueError('Invalid bounding box')
    return west, south, east, north


def map_clusters(store, bbox, zoom=8, dataset_id='', radio_type='', company_id='', q='', limit=2000):
    west, south, east, north = _bbox(bbox)
    zoom = min(20, max(0, int(zoom)))
    limit = min(5000, max(1, int(limit)))
    cell = 360 / (2 ** zoom * 8)
    filters = ['g.max_lat>=?', 'g.min_lat<=?']
    values = [south, north]
    if west <= east:
        filters.extend(('g.max_lon>=?', 'g.min_lon<=?'))
        values.extend((west, east))
    else:
        filters.append('(g.max_lon>=? OR g.min_lon<=?)')
        values.extend((west, east))
    filters.extend(('o.latitude>=?', 'o.latitude<=?'))
    values.extend((south, north))
    if west <= east:
        filters.extend(('o.longitude>=?', 'o.longitude<=?'))
        values.extend((west, east))
    else:
        filters.append('(o.longitude>=? OR o.longitude<=?)')
        values.extend((west, east))
    if dataset_id:
        filters.append('o.dataset_id=?')
        values.append(dataset_id)
    if radio_type:
        filters.append('o.radio_type=?')
        values.append(radio_type.upper())
    if q:
        filters.append("(o.identifier LIKE ? ESCAPE '\\' OR o.ssid LIKE ? ESCAPE '\\')")
        pattern = '%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        values.extend((pattern, pattern))
    if company_id:
        filters.append("EXISTS(SELECT 1 FROM wireless_company_links wl WHERE wl.device_id=o.device_id AND wl.company_id=? AND wl.status!='rejected' AND NOT EXISTS(SELECT 1 FROM wireless_company_links deny WHERE deny.device_id=wl.device_id AND deny.company_id=wl.company_id AND deny.origin='manual' AND deny.status='rejected'))")
        values.append(company_id)
    sql = '''SELECT cast((o.longitude+180)/? AS INTEGER) AS cell_x,cast((o.latitude+90)/? AS INTEGER) AS cell_y,
     avg(o.latitude) AS latitude,avg(o.longitude) AS longitude,count(*) AS observations,count(DISTINCT o.device_id) AS devices,
     sum(count(*)) OVER () AS total,CASE WHEN count(DISTINCT o.radio_type)=1 THEN min(o.radio_type) ELSE 'mixed' END AS type,
     CASE WHEN count(DISTINCT o.device_id)=1 THEN max(o.ssid) END AS name,
     min(o.rssi) AS min_rssi,max(o.rssi) AS max_rssi,min(o.accuracy_meters) AS min_accuracy_meters,
     CASE WHEN count(DISTINCT o.device_id)=1 THEN min(o.device_id) END AS device_id
     FROM wireless_observation_geo g JOIN wireless_observations o ON o.id=g.observation_id WHERE ''' + ' AND '.join(filters) + ' GROUP BY cell_x,cell_y ORDER BY observations DESC,cell_x,cell_y LIMIT ?'
    with store.connection() as conn:
        points = [dict(row) for row in conn.execute(sql, (cell, cell, *values, limit + 1))]
    return {'items': points[:limit], 'total': points[0]['total'] if points else 0, 'truncated': len(points) > limit, 'zoom': zoom, 'bbox': [west, south, east, north], 'location_basis': 'scan_observation'}


def stats(store, dataset_id=''):
    with store.connection() as conn:
        parameters = (dataset_id,) if dataset_id else ()
        where = ' WHERE id=?' if dataset_id else ''
        records = [_decoded(row) for row in conn.execute('SELECT * FROM wireless_datasets' + where, parameters)]
        timezones = sorted({record['metadata'].get('timestamp_timezone', 'unspecified') for record in records})
        if dataset_id:
            summary = records[0]['metadata'].get('_summary') or {} if records else {}
            if records and (summary.get('observations') != records[0]['observation_count'] or not all(key in summary for key in ('devices', 'located_devices', 'radio_types'))):
                summary = _dataset_summary(conn, dataset_id)
            device_count = summary.get('devices', 0)
            located_devices = summary.get('located_devices', 0)
            radio_types = summary.get('radio_types', {})
        else:
            device_count = conn.execute('SELECT count(*) FROM wireless_devices').fetchone()[0]
            located_devices = conn.execute('SELECT count(*) FROM wireless_devices WHERE latitude IS NOT NULL AND longitude IS NOT NULL').fetchone()[0]
            radio_types = {row[0]: row[1] for row in conn.execute('SELECT radio_type,count(*) FROM wireless_devices GROUP BY radio_type')}
        link_scope = ' AND EXISTS(SELECT 1 FROM wireless_observations o WHERE o.device_id=l.device_id AND o.dataset_id=?)' if dataset_id else ''
        company_links = conn.execute("""SELECT count(*) FROM wireless_company_links l WHERE l.status!='rejected'
         AND NOT EXISTS(SELECT 1 FROM wireless_company_links deny WHERE deny.device_id=l.device_id AND deny.company_id=l.company_id
          AND deny.origin='manual' AND deny.status='rejected')""" + link_scope, parameters).fetchone()[0]
        return {'datasets': len(records), 'devices': device_count, 'located_devices': located_devices,
                'observations': sum(record['observation_count'] for record in records),
                'invalid_coordinates': sum(record['invalid_coordinate_count'] for record in records),
                'radio_types': radio_types, 'rawradio_types': radio_types, 'signal_types': radio_types,
                'company_links': company_links, 'location_basis': 'scan_observation',
                'timestamp_timezone': timezones[0] if len(timezones) == 1 else 'mixed' if timezones else 'unspecified',
                'dataset_timezones': timezones, 'dataset_id': dataset_id}
