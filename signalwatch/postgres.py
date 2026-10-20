"""PostgreSQL relational backend for the Store SQL contract.

The application keeps one schema definition for local SQLite and PostgreSQL.
Only its small, explicit SQLite dialect surface is adapted here: bind markers,
JSON helpers, FTS, generated ids and integrity triggers. Data live in ordinary
PostgreSQL tables, with native constraints, transactions and indexed search.
"""
from __future__ import annotations

import re
import sqlite3
import ipaddress
from decimal import Decimal

WRITER_LOCK = 0x5349474E414C01
MIGRATION_LOCK = 0x5349474E414C02
ROWID_TABLES = frozenset({"entities", "advisories", "articles", "company_profiles", "company_identity_labels", "wireless_facilities"})
IDENTITY_TABLES = frozenset({"events", "raw_ingress", "wireless_observations", "access_audit", "audit_events"})

HELPERS = r"""
CREATE OR REPLACE FUNCTION sw_text_hash(v text) RETURNS bytea LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT sha256(convert_to(v,'UTF8')) $$;
CREATE OR REPLACE FUNCTION json_valid(v text) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$
BEGIN PERFORM v::jsonb; RETURN v IS NOT NULL; EXCEPTION WHEN others THEN RETURN false; END $$;
CREATE OR REPLACE FUNCTION json_extract(v text,p text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT CASE WHEN jsonb_typeof(v::jsonb #> string_to_array(substr(p,3),'.'))='boolean'
 THEN CASE WHEN (v::jsonb #>> string_to_array(substr(p,3),'.'))='true' THEN '1' ELSE '0' END
 ELSE v::jsonb #>> string_to_array(substr(p,3),'.') END $$;
CREATE OR REPLACE FUNCTION json_type(v text,p text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT jsonb_typeof(v::jsonb #> string_to_array(substr(p,3),'.')) $$;
CREATE OR REPLACE FUNCTION json(v text) RETURNS jsonb LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT v::jsonb $$;
CREATE OR REPLACE FUNCTION json_set(v text,p text,x jsonb) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT jsonb_set(v::jsonb,string_to_array(substr(p,3),'.'),x,true)::text $$;
CREATE OR REPLACE FUNCTION printf(fmt text,v bigint) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT CASE WHEN fmt='%04X' THEN lpad(upper(to_hex(v)),4,'0') ELSE v::text END $$;
CREATE OR REPLACE FUNCTION sw_integer(v text) RETURNS bigint LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN RETURN coalesce(substring(ltrim(v) FROM '^[+-]?[0-9]+')::bigint,0);
 EXCEPTION WHEN numeric_value_out_of_range THEN RETURN CASE WHEN left(ltrim(v),1)='-' THEN '-9223372036854775808'::bigint ELSE '9223372036854775807'::bigint END; END $$;
CREATE OR REPLACE FUNCTION sw_integer(v double precision) RETURNS bigint LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT trunc(v)::bigint $$;
CREATE OR REPLACE FUNCTION sw_integer(v bigint) RETURNS bigint LANGUAGE sql IMMUTABLE STRICT AS $$ SELECT v $$;
CREATE OR REPLACE FUNCTION json_remove(v text,p text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT (v::jsonb #- string_to_array(substr(p,3),'.'))::text $$;
CREATE OR REPLACE FUNCTION sw_json_patch(a jsonb,b jsonb) RETURNS jsonb LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE k text; v jsonb; result jsonb;
BEGIN
 IF jsonb_typeof(b) != 'object' THEN RETURN b; END IF;
 result := CASE WHEN jsonb_typeof(a)='object' THEN a ELSE '{}'::jsonb END;
 FOR k,v IN SELECT * FROM jsonb_each(b) LOOP
  IF v='null'::jsonb THEN result := result-k;
  ELSE result := jsonb_set(result,ARRAY[k],sw_json_patch(result->k,v),true); END IF;
 END LOOP; RETURN result;
END $$;
CREATE OR REPLACE FUNCTION json_patch(a text,b text) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT sw_json_patch(a::jsonb,b::jsonb)::text $$;
CREATE OR REPLACE FUNCTION json_each(v text) RETURNS TABLE(key text,value text) LANGUAGE plpgsql IMMUTABLE STRICT AS $$
BEGIN
 IF jsonb_typeof(v::jsonb)='array' THEN
 RETURN QUERY SELECT (n-1)::text,CASE WHEN jsonb_typeof(x)='string' THEN x#>>'{}' ELSE x::text END FROM jsonb_array_elements(v::jsonb) WITH ORDINALITY AS t(x,n);
 ELSIF jsonb_typeof(v::jsonb)='object' THEN
 RETURN QUERY SELECT k,CASE WHEN jsonb_typeof(x)='string' THEN x#>>'{}' ELSE x::text END FROM jsonb_each(v::jsonb) AS t(k,x);
 END IF;
END $$;
CREATE OR REPLACE FUNCTION julianday(v text) RETURNS double precision LANGUAGE plpgsql STABLE STRICT AS $$
BEGIN RETURN extract(epoch FROM v::timestamptz)/86400.0+2440587.5; EXCEPTION WHEN others THEN RETURN NULL; END $$;
CREATE OR REPLACE FUNCTION sw_substr(v text,s integer) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT substr(v,CASE WHEN s<0 THEN greatest(length(v)+s+1,1) ELSE greatest(s,1) END) $$;
CREATE OR REPLACE FUNCTION sw_substr(v text,s integer,n integer) RETURNS text LANGUAGE sql IMMUTABLE STRICT AS $$
 SELECT substr(v,CASE WHEN s<0 THEN greatest(length(v)+s+1,1) ELSE greatest(s,1) END,greatest(n,0)) $$;
CREATE OR REPLACE FUNCTION sw_fts_query(v text) RETURNS tsquery LANGUAGE plpgsql IMMUTABLE STRICT AS $$
DECLARE term text[]; result text := ''; piece text; op text;
BEGIN
 -- Application FTS expressions are quoted word tokens joined by AND/OR.
 op := CASE WHEN v ~ '\mOR\M' THEN ' | ' ELSE ' & ' END;
 FOR term IN SELECT regexp_matches(v,'"([^"]+)"(\*)?','g') LOOP
  piece := plainto_tsquery('simple',term[1])::text;
  IF piece != '' THEN
   IF term[2]='*' THEN piece := regexp_replace(piece,'''(?=($|[ &|]))',''':*','g'); END IF;
   IF result!='' THEN result:=result||op; END IF;
   result:=result||'('||piece||')';
  END IF;
 END LOOP;
 IF result='' THEN RETURN plainto_tsquery('simple',v); END IF;
 RETURN result::tsquery;
END $$;
CREATE OR REPLACE VIEW sqlite_master AS
 SELECT CASE WHEN c.relkind IN ('r','p') THEN 'table' ELSE 'view' END AS type,c.relname::text AS name,c.relname::text AS tbl_name,NULL::text AS sql
 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind IN ('r','p','v')
 UNION ALL SELECT 'trigger',t.tgname::text,c.relname::text,pg_get_triggerdef(t.oid) FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid
 JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND NOT t.tgisinternal;
"""


class Row:
    """sqlite3.Row compatible result, including integer and named access."""
    def __init__(self, names, values):
        self._names = names
        self._values = tuple((int(v) if v == v.to_integral_value() else float(v)) if isinstance(v, Decimal) else v for v in values)
    def keys(self):
        return self._names
    def __getitem__(self, key):
        return self._values[self._names.index(key)] if isinstance(key, str) else self._values[key]
    def __iter__(self):
        return iter(self._values)
    def __len__(self):
        return len(self._values)


class Cursor:
    def __init__(self, cursor=None, rows=None, names=(), hide_rowid=False, lastrowid=None):
        self.cursor = cursor
        self._rows = iter(rows) if rows is not None else None
        self._names = tuple(column.name for column in cursor.description) if cursor and cursor.description else tuple(names)
        self._keep = [i for i, name in enumerate(self._names) if not (hide_rowid and name == 'rowid')]
        self.lastrowid = lastrowid
        self.rowcount = cursor.rowcount if cursor else 0
    def _row(self, value):
        if value is None:
            return None
        return Row(tuple(self._names[i] for i in self._keep), tuple(value[i] for i in self._keep))
    def fetchone(self):
        value = next(self._rows, None) if self._rows is not None else self.cursor.fetchone()
        return self._row(value)
    def fetchall(self):
        return list(self)
    def __iter__(self):
        return self
    def __next__(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row


def _split(script):
    pending = ''
    for char in script:
        pending += char
        if char == ';' and sqlite3.complete_statement(pending):
            if pending.strip():
                yield pending.strip()
            pending = ''
    if pending.strip():
        yield pending.strip()


def _code_transform(sql, function):
    # Never rewrite quoted values or identifiers. Escaped single quotes remain
    # within their string, and SQL values continue to use bound parameters.
    parts = re.split(r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")", sql)
    return ''.join(part if i % 2 else function(part) for i, part in enumerate(parts))


def _mask_strings(sql):
    parts = re.split(r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")", sql)
    return ''.join(' ' * len(part) if i % 2 else part for i, part in enumerate(parts))


def _functions(sql):
    """Rewrite scalar min/max while leaving aggregate min/max untouched."""
    pattern = re.compile(r'\b(min|max)\s*\(', re.I)
    offset = 0
    while match := pattern.search(_mask_strings(sql), offset):
        start = match.end()
        depth, quote, comma, index = 1, None, False, start
        while index < len(sql) and depth:
            char = sql[index]
            if quote:
                if char == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 1
                    else:
                        quote = None
            elif char in "'\"":
                quote = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            elif char == ',' and depth == 1:
                comma = True
            index += 1
        if comma:
            replacement = 'LEAST' if match[1].lower() == 'min' else 'GREATEST'
            sql = sql[:match.start()] + replacement + '(' + sql[start:]
            offset = match.start() + len(replacement) + 1
        else:
            offset = start
    return sql


def _value_functions(sql):
    """Balanced call rewrites for JSON construction and SQLite integer casts."""
    pattern = re.compile(r"\b(json_object|cast)\s*\(", re.I)
    offset = 0
    while match := pattern.search(_mask_strings(sql), offset):
        depth, quote, index = 1, None, match.end()
        while index < len(sql) and depth:
            char = sql[index]
            if quote:
                if char == quote:
                    if index + 1 < len(sql) and sql[index + 1] == quote:
                        index += 1
                    else:
                        quote = None
            elif char in "'\"":
                quote = char
            elif char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
            index += 1
        body = _value_functions(sql[match.end():index - 1])
        if match[1].lower() == 'json_object':
            result = '(jsonb_build_object(' + body + ')::text)'
        elif re.search(r'\s+AS\s+INTEGER\s*$', body, re.I):
            result = 'sw_integer(' + re.sub(r'\s+AS\s+INTEGER\s*$', '', body, flags=re.I) + ')'
        elif re.search(r'\s+AS\s+REAL\s*$', body, re.I):
            result = 'CAST(' + re.sub(r'\s+AS\s+REAL\s*$', ' AS DOUBLE PRECISION', body, flags=re.I) + ')'
        else:
            result = match[1] + '(' + body + ')'
        sql = sql[:match.start()] + result + sql[index:]
        offset = match.start() + len(result)
    return sql


def _glob(match):
    value = match[2][1:-1].replace("''", "'")
    pattern = '^' + ''.join('.*' if c == '*' else '.' if c == '?' else c if c in '[]^-0123456789ABCDEF' else re.escape(c) for c in value) + '$'
    return ('!~ ' if match[1] else '~ ') + "'" + pattern.replace("'", "''") + "'"


def translate(sql):
    sql = sql.strip().rstrip(';')
    ignore = bool(re.match(r'INSERT\s+OR\s+IGNORE\b', sql, re.I))
    replace = bool(re.match(r'INSERT\s+OR\s+REPLACE\b', sql, re.I))
    sql = re.sub(r'^INSERT\s+OR\s+(IGNORE|REPLACE)\b', 'INSERT', sql, flags=re.I)
    ddl = bool(re.match(r'(CREATE\s+(?:TEMP\s+)?TABLE|ALTER\s+TABLE)', sql, re.I))
    if ddl:
        sql = re.sub(r'\bINTEGER\s+PRIMARY\s+KEY(?:\s+AUTOINCREMENT)?\b', 'BIGINT GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY', sql, flags=re.I)
        sql = _code_transform(sql, lambda part: re.sub(r'\b(INTEGER|REAL|BLOB)\b', lambda m: {'INTEGER':'BIGINT', 'REAL':'DOUBLE PRECISION', 'BLOB':'BYTEA'}[m[0].upper()], part, flags=re.I))
        match = re.match(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s*\(', sql, re.I)
        if match and match[1] in ROWID_TABLES:
            last = sql.rfind(')')
            sql = sql[:last] + ', rowid BIGINT GENERATED BY DEFAULT AS IDENTITY UNIQUE' + sql[last:]
    if re.match(r'INSERT\s+INTO\s+edges\b', sql, re.I):
        sql = re.sub(r'ON\s+CONFLICT\s*\(from_id\s*,\s*to_id\s*,\s*relation\s*,\s*source_url\s*\)',
                     'ON CONFLICT (sw_text_hash(from_id),sw_text_hash(to_id),sw_text_hash(relation),sw_text_hash(source_url))', sql, flags=re.I)
    if re.match(r'CREATE\s+INDEX\s+IF\s+NOT\s+EXISTS\s+edges_target_graph\b', sql, re.I):
        sql = 'CREATE INDEX IF NOT EXISTS edges_target_graph_hash ON edges(to_id,from_id,relation,sw_text_hash(source_url))'
    sql = _functions(sql)
    sql = _value_functions(sql)
    sql = re.sub(r"\b(NOT\s+)?GLOB\s+('(?:''|[^'])*')", _glob, sql, flags=re.I)
    sql = re.sub(r'\?(?=\s+IS\s+(?:NOT\s+)?NULL\b)', 'CAST(? AS text)', sql, flags=re.I)
    sql = re.sub(r'\b(\w+_fts)\s+MATCH\s+\?', lambda m: _fts_predicate(sql, m[1]), sql, flags=re.I)
    sql = re.sub(r"\bIS\s+NOT\s+(?!NULL\b|TRUE\b|FALSE\b|DISTINCT\b)(OLD\.\w+|NEW\.\w+|'[^']*')", r'IS DISTINCT FROM \1', sql, flags=re.I)
    sql = re.sub(r'(\b[\w.]+)\s+COLLATE\s+NOCASE', r'lower(\1)', sql, flags=re.I)
    sql = re.sub(r"(json_extract\([^\n]+?\))\s*=\?\s+COLLATE\s+NOCASE", r'lower(\1)=lower(?)', sql, flags=re.I)
    sql = re.sub(r"(json_extract\([^\n]+?\))\s*=\s*1\b", r"\1='1'", sql)
    def code(part):
        part = re.sub(r'\bsubstr\s*\(', 'sw_substr(', part, flags=re.I)
        part = re.sub(r'\bLIKE\b', 'ILIKE', part, flags=re.I)
        part = re.sub(r'\b(WHERE|AND|OR|WHEN)\s+([01])(?=\s|\)|$)', lambda m: m[1]+' '+('TRUE' if m[2]=='1' else 'FALSE'), part, flags=re.I)
        part = re.sub(r'\(\s*([01])(?=\s+(?:OR|AND)\b)', lambda m: '(' + ('TRUE' if m[1]=='1' else 'FALSE'), part, flags=re.I)
        part = re.sub(r'\bBEGIN\s+IMMEDIATE\b', 'BEGIN', part, flags=re.I)
        part = re.sub(r'\s+NOT\s+INDEXED\b|\s+INDEXED\s+BY\s+\w+\b', '', part, flags=re.I)
        # SQLite accepts CROSS JOIN ... ON; PostgreSQL calls this INNER JOIN.
        part = re.sub(r'\bCROSS\s+JOIN\s+(\w+(?:\s+(?!ON\b)\w+)?)\s+ON\b', r'JOIN \1 ON', part, flags=re.I)
        return part
    sql = _code_transform(sql, code)
    if ignore:
        sql += ' ON CONFLICT DO NOTHING'
    elif replace:
        match = re.match(r'INSERT\s+INTO\s+kev_incoming\b', sql, re.I)
        if not match:
            raise ValueError('Unsupported replacement statement; use an explicit upsert')
        sql += ' ON CONFLICT(cve) DO UPDATE SET raw=excluded.raw'
    return sql


def _fts_predicate(sql, table):
    match = re.search(r'\b(?:JOIN|FROM)\s+'+table+r'\s+(?:AS\s+)?(\w+)', sql, re.I)
    alias = match[1] if match and match[1].upper() not in {'WHERE','JOIN','CROSS','LEFT','RIGHT','INNER','ON','ORDER','GROUP'} else table
    return alias + '.document @@ sw_fts_query(?)'


def _ip_helpers():
    """Use the same Python IANA tables as collector-side address validation."""
    clauses = []
    for family, cls in ((4, ipaddress.IPv4Address), (6, ipaddress.IPv6Address)):
        constants = cls._constants
        denied = list(constants._private_networks)
        if family == 4:
            denied.append(constants._public_network)
        expression = ' OR '.join(f"address <<= inet '{network}'" for network in denied)
        exceptions = list(getattr(constants, '_private_networks_exceptions', ()))
        if exceptions:
            expression = '(' + expression + ') AND NOT (' + ' OR '.join(f"address <<= inet '{network}'" for network in exceptions) + ')'
        clauses.append(f'IF family(address)={family} AND ({expression}) THEN RETURN 0; END IF;')
    return """CREATE OR REPLACE FUNCTION sw_public_address(v text) RETURNS integer LANGUAGE plpgsql IMMUTABLE STRICT AS $$
 DECLARE address inet; BEGIN
 address:=v::inet;
 IF masklen(address) != (CASE WHEN family(address)=4 THEN 32 ELSE 128 END) THEN RETURN 0; END IF;
 IF family(address)=6 AND address <<= inet '::ffff:0:0/96' THEN
  address:=inet '0.0.0.0' + (address-inet '::ffff:0:0');
 END IF;
 """ + ' '.join(clauses) + """ RETURN 1;
 EXCEPTION WHEN invalid_text_representation THEN RETURN 0; END $$;
 CREATE OR REPLACE FUNCTION public_ip(v text) RETURNS integer LANGUAGE plpgsql IMMUTABLE STRICT AS $$
 BEGIN IF sw_public_address(v)!=1 OR v::inet <<= inet '224.0.0.0/4' OR v::inet <<= inet 'ff00::/8' THEN RETURN 0; END IF;
 RETURN 1; EXCEPTION WHEN invalid_text_representation THEN RETURN 0; END $$;
 CREATE OR REPLACE FUNCTION public_ipv4(v text) RETURNS integer LANGUAGE plpgsql IMMUTABLE STRICT AS $$
 BEGIN RETURN CASE WHEN family(v::inet)=4 THEN sw_public_address(v) ELSE 0 END;
 EXCEPTION WHEN invalid_text_representation THEN RETURN 0; END $$;"""


class Connection:
    dialect = 'postgresql'
    def __init__(self, raw):
        self.raw = raw
    @property
    def in_transaction(self):
        from psycopg.pq import TransactionStatus
        return self.raw.info.transaction_status != TransactionStatus.IDLE
    def initialize(self):
        self.raw.execute(HELPERS)
        self.raw.execute(_ip_helpers())
    def create_function(self, name, arguments, function, **kwargs):
        # These address predicates are installed natively during schema setup.
        # Arbitrary Python execution in PostgreSQL is deliberately unsupported.
        if (name, arguments) not in {('public_ip', 1), ('public_ipv4', 1)}:
            raise ValueError('Unsupported database function registration: ' + name)
    def advisory_lock(self, key, wait=True):
        fn = 'pg_advisory_lock' if wait else 'pg_try_advisory_lock'
        result = self.raw.execute(f'SELECT {fn}(%s)', (key,)).fetchone()[0]
        return True if wait else result
    def advisory_unlock(self, key):
        return self.raw.execute('SELECT pg_advisory_unlock(%s)', (key,)).fetchone()[0]
    def execute(self, sql, parameters=None):
        import psycopg
        sql = sql.strip().rstrip(';')
        pragma = re.fullmatch(r'PRAGMA\s+table_info\((\w+)\)', sql, re.I)
        if pragma:
            rows = self.raw.execute("SELECT ordinal_position-1,column_name,data_type,CASE WHEN is_nullable='NO' THEN 1 ELSE 0 END,column_default,0 FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=%s AND column_name!='rowid' ORDER BY ordinal_position", (pragma[1],)).fetchall()
            return Cursor(rows=rows, names=('cid','name','type','notnull','dflt_value','pk'))
        if sql.upper().startswith('PRAGMA '):
            return Cursor(rows=[])
        if re.match(r'CREATE\s+VIRTUAL\s+TABLE', sql, re.I):
            return self._virtual(sql)
        if re.match(r'CREATE\s+TRIGGER', sql, re.I):
            return self._trigger(sql)
        if re.match(r'DROP\s+TRIGGER', sql, re.I):
            name = sql.split()[-1]
            row = self.raw.execute('SELECT c.relname FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid WHERE t.tgname=%s', (name,)).fetchone()
            if row:
                self.raw.execute(f'DROP TRIGGER IF EXISTS "{name}" ON "{row[0]}"')
            return Cursor(rows=[])
        sql = translate(sql)
        # SQLite sorts nulls first for ASC and last for DESC; PostgreSQL's
        # default is reversed. Explicit ordering preserves cursor pagination.
        if not sql.upper().startswith('CREATE '):
            sql = _code_transform(sql, lambda part: re.sub(r'\b(DESC|ASC)\b(?!\s+NULLS)', lambda m: m[0]+(' NULLS LAST' if m[0].upper()=='DESC' else ' NULLS FIRST'), part, flags=re.I))
        insert = re.match(r'INSERT\s+INTO\s+(\w+)', sql, re.I)
        identity = insert and insert[1] in IDENTITY_TABLES and not re.search(r'\bRETURNING\b', sql, re.I)
        if identity:
            sql += ' RETURNING id'
        if parameters is not None:
            sql = sql.replace('%', '%%')
            sql = _code_transform(sql, lambda part: part.replace('?', '%s'))
        try:
            cursor = self.raw.execute(sql, parameters)
            if re.match(r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?edges\s*\(', sql, re.I):
                # Preserve full evidence URLs while keeping uniqueness indexes bounded.
                # Install the replacement before removing the old constraint.
                self.raw.execute('CREATE UNIQUE INDEX IF NOT EXISTS edges_identity_hash ON edges (sw_text_hash(from_id),sw_text_hash(to_id),sw_text_hash(relation),sw_text_hash(source_url))')
                self.raw.execute('ALTER TABLE edges DROP CONSTRAINT IF EXISTS edges_pkey')
                self.raw.execute('DROP INDEX IF EXISTS edges_target_graph')
            lastrowid = cursor.fetchone()[0] if identity and cursor.rowcount else None
            return Cursor(cursor, hide_rowid=bool(re.search(r'(?:SELECT\s+(?:DISTINCT\s+)?|,\s*)(?:\w+\.)?\*', sql, re.I)), lastrowid=lastrowid)
        except psycopg.IntegrityError as error:
            raise sqlite3.IntegrityError(str(error)) from error
        except psycopg.Error as error:
            raise sqlite3.OperationalError(str(error)) from error
    def executemany(self, sql, parameters):
        import psycopg
        statement = translate(sql).replace('%', '%%')
        statement = _code_transform(statement, lambda part: part.replace('?', '%s'))
        try:
            cursor = self.raw.cursor()
            cursor.executemany(statement, (tuple(values) for values in parameters))
            return Cursor(cursor)
        except psycopg.IntegrityError as error:
            raise sqlite3.IntegrityError(str(error)) from error
        except psycopg.Error as error:
            raise sqlite3.OperationalError(str(error)) from error
    def executescript(self, script):
        for statement in _split(script):
            self.execute(statement)
        return self
    def _virtual(self, sql):
        match = re.search(r'TABLE\s+(?:IF NOT EXISTS\s+)?(\w+)\s+USING\s+(fts5|rtree)\s*\((.*)\)', sql, re.I|re.S)
        if not match:
            raise ValueError('Unsupported virtual table')
        name, kind, spec = match.groups()
        fields = [v.strip() for v in spec.split(',')]
        columns = [v for v in fields if '=' not in v]
        if kind.lower() == 'rtree':
            self.raw.execute(f'CREATE TABLE IF NOT EXISTS {name} ({columns[0]} BIGINT PRIMARY KEY, '+','.join(v+' DOUBLE PRECISION NOT NULL' for v in columns[1:])+')')
            self.raw.execute(f'CREATE INDEX IF NOT EXISTS {name}_bounds ON {name}(min_lat,max_lat,min_lon,max_lon)')
        else:
            source = next(v.split('=',1)[1].strip() for v in fields if v.startswith('content='))
            expression = "to_tsvector('simple'," + "||' '||".join(f"coalesce({v},'')" for v in columns) + ')'
            self.raw.execute(f'CREATE OR REPLACE VIEW {name} AS SELECT rowid,'+','.join(columns)+','+expression+f' AS document FROM {source}')
            self.raw.execute(f'CREATE INDEX IF NOT EXISTS {name}_search ON {source} USING GIN ({expression})')
        return Cursor(rows=[])
    def _trigger(self, sql):
        if re.search(r'INSERT\s+INTO\s+\w+_fts\b', sql, re.I):
            return Cursor(rows=[])
        match = re.match(r'CREATE\s+TRIGGER\s+(?:IF\s+NOT\s+EXISTS\s+)?(\w+)\s+(BEFORE|AFTER)\s+(.+?)\s+ON\s+(\w+)\s*(?:WHEN\s+(.+?)\s+)?BEGIN\s+(.*?)\s*END$', sql, re.I|re.S)
        if not match:
            raise ValueError('Unsupported integrity trigger syntax')
        name, timing, operation, table, condition, body = match.groups()
        body = translate(body)
        body = re.sub(r"SELECT\s+RAISE\(ABORT\s*,\s*('(?:''|[^'])*')\)", r"RAISE EXCEPTION \1 USING ERRCODE='23514'", body, flags=re.I)
        body = body.rstrip(';')+';'
        if condition:
            body = 'IF '+translate(condition)+' THEN '+body+' END IF;'
        result = 'OLD' if operation.upper()=='DELETE' else 'NEW'
        self.raw.execute(f'CREATE OR REPLACE FUNCTION sw_trigger_{name}() RETURNS trigger LANGUAGE plpgsql AS $sw$ BEGIN {body} RETURN {result}; END $sw$')
        self.raw.execute(f'DROP TRIGGER IF EXISTS {name} ON {table}')
        self.raw.execute(f'CREATE TRIGGER {name} {timing} {operation} ON {table} FOR EACH ROW EXECUTE FUNCTION sw_trigger_{name}()')
        return Cursor(rows=[])
    def commit(self):
        self.raw.commit()
    def rollback(self):
        self.raw.rollback()
    def close(self):
        self.raw.close()


def connect(dsn):
    try:
        import psycopg
    except ImportError as error:
        raise RuntimeError('PostgreSQL requires the signalwatch[postgres] installation extra') from error
    # UTC makes date conversion and migration validation independent of host TZ.
    from psycopg.conninfo import conninfo_to_dict
    try:
        options = conninfo_to_dict(dsn).get('options', '') + ' -c timezone=UTC'
        return Connection(psycopg.connect(dsn, connect_timeout=15, options=options, application_name='signalwatch'))
    except psycopg.Error as error:
        # Connection diagnostics can include credentials from malformed URLs.
        # Keep secrets out of API errors and startup logs.
        state = error.sqlstate or 'unavailable'
        raise sqlite3.OperationalError('PostgreSQL connection failed (SQLSTATE ' + state + ')') from None
