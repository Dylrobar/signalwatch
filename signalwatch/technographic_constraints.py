"""Additive SQLite invariants for legacy company-scoped evidence tables.

Legacy tables are not rebuilt: triggers enforce their company/document links.
The one-time repair retains invalid projection rows in an audit quarantine and
never deletes their original entities or shared advisory data.
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timezone


VERSION = "technographic-integrity-v1"
logger = logging.getLogger(__name__)


def _quarantine(conn, table, selection, key, reason):
    columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
    rows = conn.execute(f"SELECT * FROM {table} WHERE {selection}")
    timestamp = datetime.now(timezone.utc).isoformat()
    for row in rows:
        value = dict(zip(columns, row))
        row_key = json.dumps([value[column] for column in key], separators=(",", ":"))
        conn.execute("""INSERT OR IGNORE INTO technographic_integrity_quarantine
         (table_name,row_key,reason,row_json,quarantined_at) VALUES(?,?,?,?,?)""",
                     (table, row_key, reason, json.dumps(value, ensure_ascii=False), timestamp))


def _repair(conn):
    conn.execute("CREATE TEMP TABLE tech_bad_documents(id TEXT PRIMARY KEY)")
    conn.execute("""INSERT INTO tech_bad_documents SELECT d.id FROM technographic_documents d
     WHERE NOT EXISTS (SELECT 1 FROM entities e WHERE e.id=d.organization_id AND e.kind='company')""")
    conn.execute("CREATE TEMP TABLE tech_bad_sources(organization_id TEXT,source_entity_id TEXT,PRIMARY KEY(organization_id,source_entity_id))")
    conn.execute("""INSERT INTO tech_bad_sources SELECT s.organization_id,s.source_entity_id FROM technographic_sources s
     WHERE NOT EXISTS (SELECT 1 FROM technographic_documents d JOIN entities e ON e.id=d.organization_id AND e.kind='company'
      WHERE d.id=s.document_id AND d.organization_id=s.organization_id)
     OR NOT EXISTS (SELECT 1 FROM entities e WHERE e.id=s.source_entity_id)
     OR s.source_entity_id IN (SELECT source_entity_id FROM technographic_sources GROUP BY source_entity_id HAVING count(*)>1)""")
    conn.execute("CREATE TEMP TABLE tech_bad_fingerprints(id TEXT PRIMARY KEY)")
    conn.execute("""INSERT INTO tech_bad_fingerprints SELECT f.id FROM tech_fingerprints f
     WHERE NOT EXISTS (SELECT 1 FROM technographic_documents d JOIN entities e ON e.id=d.organization_id AND e.kind='company'
      WHERE d.id=f.document_id AND d.organization_id=f.organization_id)""")
    conn.execute("CREATE TEMP TABLE tech_changed_sources(id TEXT PRIMARY KEY)")
    conn.execute("INSERT OR IGNORE INTO tech_changed_sources SELECT source_entity_id FROM tech_bad_sources")
    conn.execute("""INSERT OR IGNORE INTO tech_changed_sources SELECT s.source_entity_id FROM technographic_sources s
     JOIN tech_fingerprints f ON f.document_id=s.document_id WHERE f.id IN (SELECT id FROM tech_bad_fingerprints)""")
    affected = {row[0] for row in conn.execute("""SELECT organization_id FROM technographic_documents WHERE id IN (SELECT id FROM tech_bad_documents)
     UNION SELECT organization_id FROM tech_bad_sources
     UNION SELECT organization_id FROM tech_fingerprints WHERE id IN (SELECT id FROM tech_bad_fingerprints)""")}
    _quarantine(conn, "technographic_documents", "id IN (SELECT id FROM tech_bad_documents)", ("id",), "Organization does not identify a company")
    _quarantine(conn, "technographic_sources", "(organization_id,source_entity_id) IN (SELECT organization_id,source_entity_id FROM tech_bad_sources)",
                ("organization_id", "source_entity_id"), "Invalid organization/document/source link or ambiguous source owner")
    _quarantine(conn, "tech_fingerprints", "id IN (SELECT id FROM tech_bad_fingerprints)", ("id",), "Fingerprint organization does not match its company document")
    conn.execute("DELETE FROM technographic_sources WHERE (organization_id,source_entity_id) IN (SELECT organization_id,source_entity_id FROM tech_bad_sources)")
    conn.execute("DELETE FROM tech_fingerprints WHERE id IN (SELECT id FROM tech_bad_fingerprints)")
    conn.execute("DELETE FROM technographic_documents WHERE id IN (SELECT id FROM tech_bad_documents)")
    # An observation is a projection only while a same-company asserted finding
    # and an active same-company source still support its document/product.
    # Extract the document key so each observation uses a primary-key lookup.
    # The exact origin comparison remains necessary: LIKE is case insensitive.
    invalid = """origin LIKE 'technographic:%' AND NOT EXISTS (
     SELECT 1 FROM technographic_documents d JOIN tech_fingerprints f
      ON f.document_id=d.id AND f.organization_id=d.organization_id
     JOIN entities e ON e.id=d.organization_id AND e.kind='company'
     WHERE d.id=substr(observations.origin,length('technographic:')+1)
      AND observations.asset_id=d.organization_id AND observations.origin='technographic:'||d.id
      AND f.status='asserted_use' AND f.vendor=observations.vendor AND f.product=observations.product
      AND f.part=observations.part AND f.version=observations.version
      AND EXISTS (SELECT 1 FROM technographic_sources s WHERE s.document_id=d.id AND s.organization_id=d.organization_id
       AND s.source_url=observations.source_url))"""
    affected.update(row[0] for row in conn.execute("SELECT DISTINCT asset_id FROM observations WHERE " + invalid))
    _quarantine(conn, "observations", invalid, ("id",), "Company observation has no valid active company evidence")
    conn.execute("DELETE FROM observations WHERE " + invalid)
    conn.execute("""DELETE FROM edges WHERE relation='has_public_evidence'
     AND to_id IN (SELECT id FROM tech_changed_sources)
     AND NOT EXISTS (SELECT 1 FROM technographic_sources s WHERE s.source_entity_id=edges.to_id AND s.organization_id=edges.from_id)
     AND (from_id IN (SELECT organization_id FROM tech_bad_sources) OR from_id IN (SELECT id FROM entities WHERE kind='company'))""")
    # Remove only graph labels invalidated by this repair, retaining labels that
    # still have a valid fingerprint and every unrelated/global relationship.
    conn.execute("CREATE TEMP TABLE tech_valid_edges(source_id TEXT,target_id TEXT,relation TEXT,PRIMARY KEY(source_id,target_id,relation))")
    for source, vendor, product, status in conn.execute("""SELECT s.source_entity_id,f.vendor,f.product,f.status
     FROM technographic_sources s JOIN tech_fingerprints f ON f.document_id=s.document_id AND f.organization_id=s.organization_id
     WHERE s.source_entity_id IN (SELECT id FROM tech_changed_sources)""").fetchall():
        target = "technographic_product:" + hashlib.sha256((vendor + "\0" + product).encode()).hexdigest()
        conn.execute("INSERT OR IGNORE INTO tech_valid_edges VALUES(?,?,?)", (source, target, "technology_" + status))
    conn.execute("""DELETE FROM edges WHERE relation LIKE 'technology_%' AND from_id IN (SELECT id FROM tech_changed_sources)
     AND NOT EXISTS (SELECT 1 FROM tech_valid_edges v WHERE v.source_id=edges.from_id AND v.target_id=edges.to_id AND v.relation=edges.relation)""")
    if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='evidence_resolution'").fetchone():
        bad = """NOT EXISTS (SELECT 1 FROM entities e WHERE e.id=source_entity_id)
         OR (organization_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM entities e WHERE e.id=organization_id AND e.kind='company'))"""
        _quarantine(conn, "evidence_resolution", bad, ("source_entity_id",), "Invalid source or company in resolution")
        conn.execute("DELETE FROM evidence_resolution WHERE " + bad)
    for table in ("tech_bad_documents", "tech_bad_sources", "tech_bad_fingerprints", "tech_changed_sources", "tech_valid_edges"):
        conn.execute("DROP TABLE " + table)
    return affected


def _triggers(conn):
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS technographic_source_single_owner ON technographic_sources(source_entity_id)")
    company = "NOT EXISTS (SELECT 1 FROM entities e WHERE e.id=NEW.organization_id AND e.kind='company')"
    for action in ("INSERT", "UPDATE"):
        suffix = action.lower()
        conn.execute(f"""CREATE TRIGGER technographic_document_company_{suffix} BEFORE {action} ON technographic_documents
         WHEN {company} BEGIN SELECT RAISE(ABORT,'Technographic organization must identify a company'); END""")
        for table, label in (("technographic_sources", "source"), ("tech_fingerprints", "fingerprint")):
            source = " OR NOT EXISTS (SELECT 1 FROM entities e WHERE e.id=NEW.source_entity_id)" if label == "source" else ""
            conn.execute(f"""CREATE TRIGGER technographic_{label}_scope_{suffix} BEFORE {action} ON {table}
             WHEN {company} OR NOT EXISTS (SELECT 1 FROM technographic_documents d
              WHERE d.id=NEW.document_id AND d.organization_id=NEW.organization_id){source}
             BEGIN SELECT RAISE(ABORT,'Technographic document and organization must match'); END""")
    for table, label, fields in (("technographic_documents", "document", ("id", "organization_id")),
                                 ("technographic_sources", "source", ("organization_id", "source_entity_id", "document_id")),
                                 ("tech_fingerprints", "fingerprint", ("id", "organization_id", "document_id"))):
        changed = " OR ".join(f"NEW.{field} IS NOT OLD.{field}" for field in fields)
        conn.execute(f"""CREATE TRIGGER technographic_{label}_immutable BEFORE UPDATE ON {table}
         WHEN {changed} BEGIN SELECT RAISE(ABORT,'Technographic ownership is immutable; replace the projection'); END""")
    conn.execute("""CREATE TRIGGER technographic_source_delete AFTER DELETE ON technographic_sources BEGIN
     DELETE FROM observations WHERE asset_id=OLD.organization_id AND origin='technographic:'||OLD.document_id
      AND NOT EXISTS (SELECT 1 FROM technographic_sources s WHERE s.organization_id=OLD.organization_id AND s.document_id=OLD.document_id);
     DELETE FROM edges WHERE from_id=OLD.organization_id AND to_id=OLD.source_entity_id AND relation='has_public_evidence';
     DELETE FROM edges WHERE from_id=OLD.source_entity_id AND relation LIKE 'technology_%'
      AND NOT EXISTS (SELECT 1 FROM technographic_sources s WHERE s.source_entity_id=OLD.source_entity_id);
    END""")
    conn.execute("""CREATE TRIGGER technographic_document_delete BEFORE DELETE ON technographic_documents BEGIN
     DELETE FROM technographic_sources WHERE document_id=OLD.id;
     DELETE FROM tech_fingerprints WHERE document_id=OLD.id;
     DELETE FROM observations WHERE asset_id=OLD.organization_id AND origin='technographic:'||OLD.id;
    END""")
    conn.execute("""CREATE TRIGGER technographic_company_identity BEFORE UPDATE OF id,kind ON entities
     WHEN OLD.kind='company' AND (NEW.kind IS NOT 'company' OR NEW.id IS NOT OLD.id)
      AND (EXISTS (SELECT 1 FROM technographic_documents d WHERE d.organization_id=OLD.id)
       OR EXISTS (SELECT 1 FROM evidence_resolution r WHERE r.organization_id=OLD.id))
     BEGIN SELECT RAISE(ABORT,'Company identity has scoped technographic evidence'); END""")
    conn.execute("""CREATE TRIGGER technographic_company_delete BEFORE DELETE ON entities WHEN OLD.kind='company' BEGIN
     DELETE FROM technographic_documents WHERE organization_id=OLD.id;
     DELETE FROM tech_fingerprints WHERE organization_id=OLD.id;
     DELETE FROM technographic_sources WHERE organization_id=OLD.id;
     DELETE FROM observations WHERE asset_id=OLD.id;
     DELETE FROM alerts WHERE asset_id=OLD.id;
     DELETE FROM edges WHERE from_id=OLD.id OR to_id=OLD.id;
     DELETE FROM evidence_resolution WHERE organization_id=OLD.id
      OR (json_valid(candidates) AND EXISTS (SELECT 1 FROM json_each(candidates) WHERE value=OLD.id));
    END""")
    conn.execute("""CREATE TRIGGER technographic_entity_delete BEFORE DELETE ON entities BEGIN
     DELETE FROM technographic_sources WHERE source_entity_id=OLD.id;
     DELETE FROM evidence_resolution WHERE source_entity_id=OLD.id;
    END""")
    conn.execute("""CREATE TRIGGER technographic_source_entity_identity BEFORE UPDATE OF id ON entities
     WHEN NEW.id IS NOT OLD.id AND EXISTS (SELECT 1 FROM technographic_sources s WHERE s.source_entity_id=OLD.id)
     BEGIN SELECT RAISE(ABORT,'Source identity has scoped technographic evidence'); END""")
    for action in ("INSERT", "UPDATE"):
        conn.execute(f"""CREATE TRIGGER technographic_resolution_scope_{action.lower()} BEFORE {action} ON evidence_resolution
         WHEN NOT EXISTS (SELECT 1 FROM entities e WHERE e.id=NEW.source_entity_id)
          OR (NEW.organization_id IS NOT NULL AND {company})
         BEGIN SELECT RAISE(ABORT,'Resolution must reference an existing source and company'); END""")


def ensure_constraints(conn):
    """Install once; return assets requiring scoped reconciliation in this transaction."""
    if not conn.in_transaction:
        conn.execute("BEGIN")
    conn.execute("CREATE TABLE IF NOT EXISTS technographic_integrity_migrations(version TEXT PRIMARY KEY,applied_at TEXT NOT NULL)")
    if conn.execute("SELECT 1 FROM technographic_integrity_migrations WHERE version=?", (VERSION,)).fetchone():
        return set()
    started = time.monotonic()
    logger.info("Technographic integrity migration %s started", VERSION)
    conn.execute("SAVEPOINT technographic_integrity_install")
    try:
        conn.execute("""CREATE TABLE IF NOT EXISTS technographic_integrity_quarantine(
         table_name TEXT NOT NULL,row_key TEXT NOT NULL,reason TEXT NOT NULL,row_json TEXT NOT NULL,
         quarantined_at TEXT NOT NULL,PRIMARY KEY(table_name,row_key))""")
        affected = _repair(conn)
        _triggers(conn)
        conn.execute("INSERT INTO technographic_integrity_migrations VALUES(?,?)", (VERSION, datetime.now(timezone.utc).isoformat()))
        conn.execute("RELEASE technographic_integrity_install")
        logger.info("Technographic integrity migration %s finished in %.3fs; affected assets=%d",
                    VERSION, time.monotonic() - started, len(affected))
        return affected
    except BaseException:
        conn.execute("ROLLBACK TO technographic_integrity_install")
        conn.execute("RELEASE technographic_integrity_install")
        raise
