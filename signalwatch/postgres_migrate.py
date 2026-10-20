"""Verified, atomic SQLite-to-PostgreSQL migration.

Run with writers stopped. SQLite's backup API captures a consistent source
snapshot without changing the original database. The destination must be empty
(or have the matching completed manifest). Copy, byte-for-byte logical content
verification, sequence repair and the activation manifest commit together.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from .postgres import MIGRATION_LOCK, ROWID_TABLES, WRITER_LOCK, connect

SEED_TABLES = frozenset({'company_identity_migrations', 'technographic_integrity_migrations', 'evidence_resolution_migrations'})
MANIFEST_TABLE = 'postgres_migration_manifest'
log = logging.getLogger(__name__)


def _quote(name):
    return '"' + name.replace('"', '""') + '"'


def _digest(rows):
    """Order-independent multiset checksum, bounded memory even for raw payloads."""
    count, total, xor = 0, 0, 0
    for row in rows:
        values = [({'bytes': bytes(v).hex()} if isinstance(v, (bytes, memoryview)) else v) for v in row]
        encoded = json.dumps(values, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode()
        value = int.from_bytes(hashlib.sha256(encoded).digest(), 'big')
        total = (total + value) % (1 << 256)
        xor ^= value
        count += 1
    return {'rows': count, 'sha256_sum': f'{total:064x}', 'sha256_xor': f'{xor:064x}'}


def _source_inventory(source):
    types = {row[1]: row[2] for row in source.execute('PRAGMA table_list')}
    tables = []
    for name, ddl in source.execute("SELECT name,sql FROM sqlite_master WHERE type='table' ORDER BY name"):
        if name.startswith('sqlite_') or types.get(name) in {'shadow', 'virtual'}:
            continue
        columns = [row[1] for row in source.execute(f'PRAGMA table_info({_quote(name)})')]
        if name in ROWID_TABLES:
            columns.append('rowid')
        tables.append({'name': name, 'ddl': ddl, 'columns': columns})
    return tables


def _select(table):
    return 'SELECT ' + ','.join(map(_quote, table['columns'])) + ' FROM ' + _quote(table['name'])


def _order(tables, conn):
    names = {table['name'] for table in tables}
    dependencies = {name: set() for name in names}
    for child, parent in conn.raw.execute("SELECT c.relname,p.relname FROM pg_constraint f JOIN pg_class c ON c.oid=f.conrelid JOIN pg_class p ON p.oid=f.confrelid WHERE f.contype='f' AND c.relnamespace=current_schema()::regnamespace"):
        if child in names and parent in names and child != parent:
            dependencies[child].add(parent)
    for name in ('company_profiles','company_asset_decisions','company_identity_labels','company_asn_anchors','technographic_documents','technographic_sources','tech_fingerprints','evidence_resolution'):
        if name in names and 'entities' in names:
            dependencies[name].add('entities')
    for name in ('technographic_sources','tech_fingerprints'):
        if name in names and 'technographic_documents' in names:
            dependencies[name].add('technographic_documents')
    pending, result = dict(dependencies), []
    while pending:
        ready = sorted(name for name, deps in pending.items() if not deps.intersection(pending))
        if not ready:
            raise RuntimeError('Migration cannot order cyclic table dependencies: ' + ', '.join(sorted(pending)))
        result.extend(ready)
        for name in ready:
            pending.pop(name)
    by_name = {table['name']: table for table in tables}
    return [by_name[name] for name in result]


def migrate_sqlite(source_path, target_dsn):
    """Return a committed verification manifest; leave both DBs safe on failure.

    The source is never removed or modified. A retry after an interrupted copy
    starts from the empty target; a retry after a successful commit returns the
    matching manifest. A different source or populated target fails closed.
    """
    from .store import Store
    source_path = Path(source_path).expanduser().resolve()
    if not source_path.is_file():
        raise ValueError('SQLite migration source does not exist')
    if not str(target_dsn).startswith(('postgres://', 'postgresql://')):
        raise ValueError('Migration target must be a PostgreSQL connection URL')
    with tempfile.TemporaryDirectory(prefix='signalwatch-migration-') as directory:
        snapshot_path = Path(directory) / 'snapshot.sqlite3'
        original = sqlite3.connect(source_path.as_uri() + '?mode=ro', uri=True)
        snapshot = sqlite3.connect(snapshot_path)
        last_progress = 0

        def progress(_status, remaining, total):
            nonlocal last_progress
            now = time.monotonic()
            if not remaining or now - last_progress >= 30:
                log.info('SQLite migration snapshot: %s of %s pages copied', total - remaining, total)
                last_progress = now

        try:
            log.info('Creating consistent SQLite migration snapshot')
            original.backup(snapshot, pages=8192, progress=progress)
        finally:
            original.close()
        try:
            log.info('Checking SQLite snapshot integrity and foreign keys')
            if snapshot.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
                raise RuntimeError('Source SQLite integrity check failed')
            foreign_keys = snapshot.execute('PRAGMA foreign_key_check').fetchall()
            if foreign_keys:
                raise RuntimeError('Source SQLite has foreign-key violations; repair before migration')
            tables = _source_inventory(snapshot)
            checks = {}
            for table in tables:
                name = table['name']
                log.info('Checking source table %s', name)
                checks[name] = {'columns': table['columns'], **_digest(snapshot.execute(_select(table)))}
            source_fingerprint = hashlib.sha256(json.dumps(checks, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
            log.info('Source snapshot verified; connecting to PostgreSQL')
            conn = connect(target_dsn)
            try:
                # Inspect and lock the destination before Store can install or
                # repair any schema. Even schema setup belongs to this same
                # transaction, so a rejected copy changes nothing there.
                conn.advisory_lock(MIGRATION_LOCK)
                conn.raw.execute('SELECT pg_advisory_xact_lock(%s)', (WRITER_LOCK,))
                target_tables = [row[0] for row in conn.raw.execute("SELECT tablename FROM pg_tables WHERE schemaname=current_schema()")]
                if MANIFEST_TABLE in target_tables:
                    existing = conn.raw.execute(f'SELECT source_fingerprint,manifest FROM {MANIFEST_TABLE} WHERE id=1').fetchone()
                    if existing:
                        if not isinstance(existing[1], dict) or existing[1].get('verified') is not True or existing[1].get('version') != 1:
                            raise RuntimeError('PostgreSQL migration manifest is incomplete or unsupported')
                        if existing[0] != source_fingerprint:
                            raise RuntimeError('PostgreSQL already migrated from a different source snapshot; refusing to overwrite')
                        conn.commit()
                        return {**existing[1], 'already_migrated': True}
                for name in target_tables:
                    if name not in SEED_TABLES | {MANIFEST_TABLE} and conn.raw.execute(f'SELECT 1 FROM {_quote(name)} LIMIT 1').fetchone():
                        raise RuntimeError('PostgreSQL destination is not empty; refusing to overwrite table ' + name)
                # Install current native schema/helpers/triggers only after the
                # empty-target guard, using the already locked transaction.
                Store(target_dsn, _connection=conn)
                from .jobs import SCHEMA as JOB_SCHEMA
                from .operations import ensure_schema as ensure_operations
                conn.executescript(JOB_SCHEMA)
                ensure_operations(conn)
                conn.raw.execute(f'CREATE TABLE IF NOT EXISTS {MANIFEST_TABLE} (id integer PRIMARY KEY CHECK(id=1), source_fingerprint text NOT NULL, manifest jsonb NOT NULL)')
                target_tables = [row[0] for row in conn.raw.execute("SELECT tablename FROM pg_tables WHERE schemaname=current_schema()")]
                for table in tables:
                    if table['name'] not in target_tables:
                        conn.execute(table['ddl'])
                    if table['name'] in SEED_TABLES:
                        conn.raw.execute('DELETE FROM ' + _quote(table['name']))
                for table in _order(tables, conn):
                    name = table['name']
                    log.info('Copying table %s (%s rows)', name, checks[name]['rows'])
                    columns = ','.join(map(_quote, table['columns']))
                    with conn.raw.cursor().copy(f'COPY {_quote(name)} ({columns}) FROM STDIN') as copy:
                        for row in snapshot.execute(_select(table)):
                            copy.write_row(tuple(row))
                # Verify the final state, after every insertion trigger has run.
                # A server-side cursor bounds memory for large BYTEA queues and
                # wireless inventories; ordinary psycopg cursors buffer results.
                for index, table in enumerate(tables):
                    name = table['name']
                    log.info('Verifying PostgreSQL table %s', name)
                    with conn.raw.cursor(name='verify_' + str(index)) as cursor:
                        cursor.itersize = 100
                        cursor.execute(_select(table))
                        actual = {'columns': table['columns'], **_digest(cursor)}
                    if actual != checks[name]:
                        raise RuntimeError('PostgreSQL migration verification failed for table ' + name)
                # Explicit copied IDs must not collide with the next insert.
                for table, column in conn.raw.execute("SELECT table_name,column_name FROM information_schema.columns WHERE table_schema=current_schema() AND is_identity='YES'").fetchall():
                    sequence = conn.raw.execute('SELECT pg_get_serial_sequence(%s,%s)', (table, column)).fetchone()[0]
                    maximum = conn.raw.execute(f'SELECT max({_quote(column)}) FROM {_quote(table)}').fetchone()[0]
                    conn.raw.execute('SELECT setval(%s,%s,%s)', (sequence, max(1, maximum or 1), maximum is not None))
                manifest = {'version': 1, 'source_fingerprint': source_fingerprint,
                            'completed_at': datetime.now(timezone.utc).isoformat(),
                            'tables': checks, 'total_rows': sum(value['rows'] for value in checks.values()),
                            'verified': True, 'already_migrated': False}
                conn.raw.execute(f'INSERT INTO {MANIFEST_TABLE}(id,source_fingerprint,manifest) VALUES(1,%s,%s::jsonb)',
                                 (source_fingerprint, json.dumps(manifest, sort_keys=True)))
                conn.commit()
                return manifest
            except BaseException:
                conn.rollback()
                raise
            finally:
                conn.close()
        finally:
            snapshot.close()
