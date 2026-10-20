import hashlib
import json
import re

METHOD = 'deterministic-catalog-v2'
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
    from .entity_resolution import resolve
    original = str(article.get('title') or '') + '\n' + str(article.get('summary') or '')
    text = original[:16000]
    all_tokens = list(dict.fromkeys(re.findall(r'[\w.-]{3,}', text)))
    tokens = all_tokens[:128]
    expression = ' OR '.join('"' + token.replace('"', '""') + '"' for token in tokens)
    catalog = {}
    company_ids = set()
    # Reuse the bounded FTS candidate set below for names instead of scanning
    # the full company catalogue for every article.
    resolution = resolve(conn, source_url=article.get('url') or '')
    truncation = []
    if len(original)>16000:
        truncation.append('text')
    if len(all_tokens)>128:
        truncation.append('tokens')
    truncated = False
    if expression:
        entity_expression = '('+expression+') AND kind:(company OR technology OR device OR package OR os)'
        entity_ids = [row[0] for row in conn.execute('''SELECT e.id FROM entity_fts
         CROSS JOIN entities e ON e.rowid=entity_fts.rowid
         WHERE entity_fts MATCH ? AND e.kind IN ('company','technology','device','package','os')
         ORDER BY entity_fts.rowid LIMIT 201''', (entity_expression,))]
        profile_ids = [row[0] for row in conn.execute('''SELECT p.company_id FROM company_profile_fts
         CROSS JOIN company_profiles p ON p.rowid=company_profile_fts.rowid
         CROSS JOIN entities e ON e.id=p.company_id
         WHERE company_profile_fts MATCH ? AND e.kind='company'
         ORDER BY company_profile_fts.rowid LIMIT 201''', (expression,))]
        candidates = sorted(set(entity_ids)|set(profile_ids))
        truncated = len(entity_ids)>200 or len(profile_ids)>200 or len(candidates)>200
        if truncated:
            truncation.append('catalog')
        identities = candidates[:200]
        slots = ','.join('?' for _ in identities)
        rows = conn.execute('''SELECT e.id,e.kind,e.name,e.value,e.metadata,p.name AS profile_name,p.legal_name,p.aliases,p.brands
         FROM entities e LEFT JOIN company_profiles p ON p.company_id=e.id
         WHERE e.id IN ('''+slots+') ORDER BY e.id', identities) if identities else []
        for row in rows:
            labels = [row['name'], row['profile_name'], row['legal_name']]
            if row['kind'] == 'company':
                company_ids.add(row['id'])
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
            resolved = len(ids) == 1 and not truncated
            if entity_id in company_ids:
                resolved = resolved and resolution.get('organization_id') == entity_id
            mentions[entity_id] = {'entity_id': entity_id, 'status': 'resolved' if resolved else 'candidate',
                                   'quote': quote, 'confidence': 0.85 if resolved else 0.35}
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
    company_candidates = sorted(company_ids.intersection(mentions))
    if not resolution.get('organization_id') and company_candidates and resolution['status'] != 'conflict':
        resolution.update(status='candidate', method='name_candidate', candidates=company_candidates,
                          reason='Company names in text require supporting domain evidence')
    return {'method': METHOD, 'text_hash': hashlib.sha256(text.encode()).hexdigest(), 'mentions': ordered_mentions[:100],
            'claims': claims[:32], 'versions': versions, 'truncated': bool(truncation),
            'coverage': {'text_char_limit': 16000, 'catalog_candidate_limit': 200, 'token_limit': 128, 'truncation_reasons': truncation},
            'source_url': article['url'], 'published': article.get('published'), 'resolution': resolution}


def project(store, conn, article, article_id, timestamp):
    result = extract(conn, article)
    from .technographic_store import persist_resolution
    persist_resolution(conn, article_id, result['resolution'], article['url'], {}, timestamp)
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


def refresh_company_resolution(store, conn, company_id=''):
    """Withdraw legacy name-only resolution cheaply; refresh bounded alias matches.

    The normal paged text backfill discovers remaining new alias mentions.
    Existing mentions are downgraded immediately even beyond the refresh budget.
    """
    from .entity_resolution import resolve
    from .store import now
    from .technographic_store import persist_resolution

    timestamp = now()
    ids = set()
    if company_id:
        ids.update(row[0] for row in conn.execute('SELECT article_id FROM signal_mentions WHERE entity_id=?', (company_id,)))
        profile = conn.execute('''SELECT e.name,p.name AS profile_name,p.legal_name,p.aliases,p.brands FROM entities e
         LEFT JOIN company_profiles p ON p.company_id=e.id WHERE e.id=?''', (company_id,)).fetchone()
        if profile:
            labels = [profile['name'], profile['profile_name'], profile['legal_name']]
            labels += json.loads(profile['aliases'] or '[]') + json.loads(profile['brands'] or '[]')
            terms = ['"' + label.replace('"', '""') + '"' for label in labels if isinstance(label, str) and label.strip()]
            if terms:
                ids.update(row[0] for row in conn.execute('''SELECT a.id FROM article_fts JOIN articles a ON a.rowid=article_fts.rowid
                 WHERE article_fts MATCH ?''', (' OR '.join(terms),)))
        rows = (conn.execute('''SELECT a.id,a.url,a.title,a.summary,a.published,t.extraction FROM articles a
                LEFT JOIN text_signals t ON t.article_id=a.id WHERE a.id=?''', (key,)).fetchone() for key in sorted(ids))
    else:
        rows = conn.execute('''SELECT a.id,a.url,a.title,a.summary,a.published,t.extraction FROM articles a
         JOIN text_signals t ON t.article_id=a.id WHERE EXISTS(SELECT 1 FROM signal_mentions m
          JOIN entities e ON e.id=m.entity_id AND e.kind='company' WHERE m.article_id=a.id)''')
    refreshed = 0
    for row in rows:
        if row is None:
            continue
        if company_id and refreshed < 500:
            project(store, conn, dict(row), row['id'], timestamp)
            refreshed += 1
            continue
        if not row['extraction']:
            continue
        result = json.loads(row['extraction'])
        companies = {item[0] for item in conn.execute("SELECT m.entity_id FROM signal_mentions m JOIN entities e ON e.id=m.entity_id AND e.kind='company' WHERE m.article_id=?", (row['id'],))}
        resolution = resolve(conn, source_url=row['url'])
        if not resolution.get('organization_id') and companies and resolution['status'] != 'conflict':
            resolution.update(status='candidate', method='name_candidate', candidates=sorted(companies),
                              reason='Company names in retained text require domain evidence')
        for mention in result.get('mentions', []):
            if mention['entity_id'] in companies:
                mention.update(status='candidate', confidence=0.35)
        result.update(method=METHOD, resolution=resolution)
        conn.execute('UPDATE text_signals SET method=?,extraction=?,updated_at=? WHERE article_id=?', (METHOD, json.dumps(result), timestamp, row['id']))
        conn.execute("UPDATE signal_mentions SET status='candidate',confidence=0.35 WHERE article_id=? AND entity_id IN (SELECT id FROM entities WHERE kind='company')", (row['id'],))
        conn.execute("DELETE FROM edges WHERE from_id=? AND relation='text_mentions' AND to_id IN (SELECT id FROM entities WHERE kind='company')", (row['id'],))
        for key in companies:
            store._edge(conn, {'from_id': row['id'], 'to_id': key, 'relation': 'candidate_mention', 'source_url': row['url'], 'confidence': 0.35}, timestamp)
        persist_resolution(conn, row['id'], resolution, row['url'], {}, timestamp)
