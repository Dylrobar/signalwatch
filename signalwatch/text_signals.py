import hashlib
import json
import re

METHOD = 'deterministic-catalog-v1'
SCHEMA = '''
CREATE TABLE IF NOT EXISTS text_signals (
 article_id TEXT PRIMARY KEY, text_hash TEXT NOT NULL, method TEXT NOT NULL,
 extraction TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS signal_mentions (
 article_id TEXT NOT NULL, entity_id TEXT NOT NULL, status TEXT NOT NULL,
 quote TEXT NOT NULL, confidence REAL NOT NULL, source_url TEXT NOT NULL,
 PRIMARY KEY(article_id,entity_id)
);
CREATE INDEX IF NOT EXISTS signal_mentions_target ON signal_mentions(entity_id,article_id);
CREATE INDEX IF NOT EXISTS alerts_advisory_graph ON alerts(advisory_id,asset_id);
CREATE INDEX IF NOT EXISTS entities_recent_graph ON entities(updated_at DESC,id);
CREATE INDEX IF NOT EXISTS edges_target_graph ON edges(to_id,from_id,relation,source_url);
CREATE INDEX IF NOT EXISTS alerts_asset_order_graph ON alerts(asset_id,id);
CREATE INDEX IF NOT EXISTS alerts_advisory_order_graph ON alerts(advisory_id,id);
CREATE INDEX IF NOT EXISTS observations_asset_order_graph ON observations(asset_id,id);
'''


def extract(conn, article):
    original = str(article.get('title') or '') + '\n' + str(article.get('summary') or '')
    text = original[:16000]
    all_tokens = list(dict.fromkeys(re.findall(r'[\w.-]{3,}', text)))
    tokens = all_tokens[:128]
    expression = ' OR '.join('"' + token.replace('"', '""') + '"' for token in tokens)
    catalog = {}
    truncation = []
    if len(original)>16000:
        truncation.append('text')
    if len(all_tokens)>128:
        truncation.append('tokens')
    truncated = False
    if expression:
        rows = conn.execute('''SELECT e.id,e.kind,e.name,e.value,e.metadata,p.name AS profile_name,p.legal_name,p.aliases,p.brands
         FROM entities e LEFT JOIN company_profiles p ON p.company_id=e.id
         WHERE e.kind IN ('company','technology','device','package','os') AND
         (e.rowid IN (SELECT rowid FROM entity_fts WHERE entity_fts MATCH ?) OR
          p.rowid IN (SELECT rowid FROM company_profile_fts WHERE company_profile_fts MATCH ?))
         ORDER BY e.id LIMIT 201''', (expression, expression)).fetchall()
        truncated = len(rows) > 200
        if truncated:
            truncation.append('catalog')
        for row in rows[:200]:
            labels = [row['name'], row['profile_name'], row['legal_name']]
            if row['kind'] == 'company':
                labels += json.loads(row['aliases'] or '[]') + json.loads(row['brands'] or '[]')
            else:
                meta = json.loads(row['metadata'])
                labels += [meta.get('product'), meta.get('package')]
            for label in labels:
                if isinstance(label, str) and len(label.strip()) >= 3:
                    catalog.setdefault(label.strip().casefold(), set()).add(row['id'])
    mentions = {}
    for label, ids in sorted(catalog.items()):
        match = re.search(r'(?<!\w)' + re.escape(label) + r'(?!\w)', text, re.I)
        if not match:
            continue
        quote = text[max(0, match.start()-80):match.end()+120]
        for entity_id in sorted(ids):
            if entity_id in mentions and mentions[entity_id]['status'] == 'resolved':
                continue
            mentions[entity_id] = {'entity_id': entity_id, 'status': 'resolved' if len(ids) == 1 and not truncated else 'candidate',
                                   'quote': quote, 'confidence': 0.85 if len(ids) == 1 and not truncated else 0.35}
    all_cves = sorted(set(c.upper() for c in re.findall(r'\bCVE-\d{4}-\d{4,}\b', text, re.I)))
    cves = all_cves[:32]
    if len(all_cves)>32:
        truncation.append('cves')
    for cve in cves:
        cve = cve.upper()
        canonical = conn.execute('SELECT canonical_id FROM advisory_aliases WHERE alias=?', (cve,)).fetchone()
        entity_id = canonical[0] if canonical else cve
        mentions[entity_id] = {'entity_id': entity_id, 'status': 'identifier', 'quote': cve, 'confidence': 1.0}
    claims = []
    for sentence in re.split(r'(?<=[.!?])\s+|\n+|;|,|\b(?:but|however)\b', text, flags=re.I):
        for kind, pattern in [('exploit', r'\bexploit(?:ation|ed|s)?\b'), ('zero_day', r'\bzero[ -]day\b'), ('patch', r'\bpatch(?:ed|es)?\b')]:
            match = re.search(pattern, sentence, re.I)
            if match:
                # Negation is local to the claim clause; all affirmative text remains a claim, not a fact.
                before, after = sentence[:match.start()], sentence[match.end():]
                negated = bool(re.search(r'\b(?:no|without|never|denies|denied)\s+(?:\w+\s+){0,3}$|\bnot\s+(?!only\b)(?:\w+\s+){0,2}$', before, re.I)
                               or re.match(r'\s+(?:code\s+)?(?:(?:is|was|are|were|has|have|remains)\s+)?(?:not\s+(?:(?:yet|been|being|publicly|actively)\s+){0,2}(?:available|possible|observed|required|released)|unavailable|impossible|denied)\b', after, re.I)
                               or re.search(r'\b(?:only\s+in\s+(?:a\s+)?denial|quoted\s+(?:in\s+)?(?:a\s+)?denial)\b', sentence, re.I))
                if len(sentence)>400 and 'claim_quotes' not in truncation:
                    truncation.append('claim_quotes')
                claims.append({'kind': kind, 'status': 'negated' if negated else 'claimed', 'quote': sentence[:400], 'confidence': 0.7})
        if len(claims) > 32:
            break
    all_versions = sorted(set(re.findall(r'\b(?:v(?:ersion)?\s*)?(\d+\.\d+(?:\.[\w-]+){0,3})\b', text, re.I)))
    versions = all_versions[:32]
    if len(claims)>32:
        truncation.append('claims')
    if len(all_versions)>32:
        truncation.append('versions')
    if len(mentions)>100:
        truncation.append('mentions')
    ordered_mentions=sorted(mentions.values(),key=lambda m:m['status']!='identifier')
    return {'method': METHOD, 'text_hash': hashlib.sha256(text.encode()).hexdigest(), 'mentions': ordered_mentions[:100],
            'claims': claims[:32], 'versions': versions, 'truncated': bool(truncation),
            'coverage': {'text_char_limit': 16000, 'catalog_candidate_limit': 200, 'token_limit': 128, 'truncation_reasons': truncation},
            'source_url': article['url'], 'published': article.get('published')}


def project(store, conn, article, article_id, timestamp):
    result = extract(conn, article)
    conn.execute('INSERT INTO text_signals VALUES(?,?,?,?,?) ON CONFLICT(article_id) DO UPDATE SET text_hash=excluded.text_hash,method=excluded.method,extraction=excluded.extraction,updated_at=excluded.updated_at',
                 (article_id, result['text_hash'], METHOD, json.dumps(result), timestamp))
    conn.execute('DELETE FROM signal_mentions WHERE article_id=?', (article_id,))
    conn.execute("DELETE FROM edges WHERE from_id=? AND relation IN ('text_mentions','candidate_mention')", (article_id,))
    for mention in result['mentions']:
        entity_id = mention['entity_id']
        if mention['status'] == 'identifier' and not conn.execute('SELECT 1 FROM entities WHERE id=?', (entity_id,)).fetchone():
            store._entity(conn, {'id': entity_id, 'kind': 'vulnerability', 'name': entity_id, 'metadata': {'evidence_role': 'text_identifier_only'}, 'source_url': article['url']}, timestamp)
        conn.execute('INSERT INTO signal_mentions VALUES(?,?,?,?,?,?)', (article_id, entity_id, mention['status'], mention['quote'], mention['confidence'], article['url']))
        store._edge(conn, {'from_id': article_id, 'to_id': entity_id, 'relation': 'candidate_mention' if mention['status']=='candidate' else 'text_mentions',
                          'source_url': article['url'], 'observed_at': article.get('published') or timestamp, 'confidence': mention['confidence']}, timestamp)
    return result


def backfill(store, after=0, limit=25):
    from .store import now
    with store.connection(write=True) as conn:
        rows = conn.execute('SELECT rowid AS cursor,id,url,title,summary,published FROM articles WHERE rowid>? ORDER BY rowid LIMIT ?', (after, limit+1)).fetchall()
        for row in rows[:limit]:
            project(store, conn, dict(row), row['id'], now())
        return {'processed': min(limit,len(rows)), 'next_cursor': rows[min(limit,len(rows))-1]['cursor'] if rows else after,
                'has_more': len(rows)>limit, 'method': METHOD}
