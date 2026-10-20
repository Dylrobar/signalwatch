import hashlib
import json
import re
from collections import deque
from datetime import datetime, timedelta, timezone

from .companies import company, company_assets

SOFTWARE_LABEL_KINDS = {'technology', 'product', 'device', 'os', 'package'}


def edge(from_id, to_id, relation, source_url='', confidence=None, observed_at=None, status='context', evidence=None):
    key = '\0'.join((from_id,to_id,relation,source_url or ''))
    return {'id': 'edge:' + hashlib.sha256(key.encode()).hexdigest()[:32], 'from_id': from_id, 'to_id': to_id,
            'relation': relation, 'source_url': source_url, 'confidence': confidence, 'observed_at': observed_at,
            'status': status, 'evidence_role': 'matched_potential' if relation=='matched_advisory' else 'catalog_only' if relation=='affected_by' else status,
            'evidence': evidence}


class KnowledgeGraph:
    def __init__(self, store):
        self.store = store

    def canonical(self, conn, key):
        row = conn.execute('SELECT canonical_id FROM advisory_aliases WHERE alias=?', (key,)).fetchone()
        return row[0] if row else key

    def aliases(self, conn, key, coverage, cap=64):
        rows = conn.execute('SELECT alias FROM advisory_aliases WHERE canonical_id=? ORDER BY alias LIMIT ?', (key,cap+1)).fetchall()
        coverage['truncated'] |= len(rows)>cap
        return list(dict.fromkeys([key]+[r[0] for r in rows[:cap]]))

    def active_alert_filter(self):
        from .store import ACTIVE_CVE_STATE
        return 'EXISTS (SELECT 1 FROM advisories a WHERE a.canonical_id=alerts.advisory_id AND a.rejected=0 AND '+ACTIVE_CVE_STATE+')'

    def node(self, conn, key):
        key = self.canonical(conn,key)
        row = conn.execute('SELECT e.*,p.name AS profile_name FROM entities e LEFT JOIN company_profiles p ON p.company_id=e.id WHERE e.id=?', (key,)).fetchone()
        if row:
            meta = json.loads(row['metadata'])
            light = {k: meta[k] for k in ('vendor','product','version','ecosystem','package','evidence_role','provider','origin') if k in meta}
            result = {'id': key, 'kind': row['kind'], 'label': row['profile_name'] or row['name'], 'metadata': light,
                      'confidence': row['confidence'], 'observed_at': row['observed_at'], 'source_url': row['source_url'], 'risk': None}
            if row['kind']=='article':
                extraction = conn.execute('SELECT extraction FROM text_signals WHERE article_id=?', (key,)).fetchone()
                if extraction:
                    full=json.loads(extraction[0])
                    result['metadata']['extraction']={k:full[k] for k in ('method','versions','truncated','coverage','source_url','published')}
                    result['metadata']['extraction']['claims']=[{**c,'quote':c['quote'][:160]} for c in full['claims'][:4]]
                    result['metadata']['extraction']['preview_truncated']=len(full['claims'])>4 or len(full['mentions'])>10 or any(len(c['quote'])>160 for c in full['claims'][:4])
                    result['metadata']['extraction']['mentions']=[{k:m[k] for k in ('entity_id','status','confidence')} for m in full['mentions'][:10]]
            return result
        row = conn.execute('SELECT * FROM alerts WHERE id=? AND '+self.active_alert_filter(), (key,)).fetchone()
        if row:
            return {'id': key, 'kind': 'alert', 'label': row['advisory_id']+' · potential match', 'metadata': {k: row[k] for k in ('asset_id','advisory_id','version_state','version')},
                    'confidence': row['confidence'], 'observed_at': row['observed_at'], 'source_url': row['source_url'], 'risk': self.driver(conn,dict(row)), 'alert': dict(row)}
        wireless=conn.execute('SELECT id,radio_type,identifier,ssid,last_seen FROM wireless_devices WHERE id=?',(key,)).fetchone()
        if wireless:
            return {'id':key,'kind':'wireless_device','label':wireless['ssid'] or wireless['identifier'],
                    'metadata':{'radio_type':wireless['radio_type'],'location_basis':'scan_observation; not exact device position'},
                    'confidence':None,'observed_at':wireless['last_seen'],'source_url':None,'risk':None}
        if key.startswith('observation:'):
            row = conn.execute('SELECT * FROM observations WHERE id=?', (key[12:],)).fetchone()
            if row:
                return {'id': key, 'kind': 'software_version', 'label': row['product_name']+' '+(row['version'] or '(version unknown)'),
                        'metadata': {k: row[k] for k in ('vendor','product','version','cpe','origin')}, 'confidence': row['confidence'],
                        'observed_at': row['observed_at'], 'source_url': row['source_url'], 'risk': None}
        return None

    def neighbors(self, conn, node, cap, coverage, scope=None):
        key = node['id']
        if scope and node.get('scope') == 'shared_context':
            # Apply company provenance before the cap: a widely used product
            # can have thousands of other companies' vendor-label edges. Those
            # must not crowd this company's own vendor evidence out of the view.
            sources = sorted(scope['technology_sources'].get(key, set()))
            if not sources:
                return []
            slots = ','.join('?' for _ in sources)
            rows = conn.execute("""SELECT e.* FROM edges e WHERE
             ((e.from_id=? AND e.relation='vendor_label' AND EXISTS
               (SELECT 1 FROM entities v WHERE v.id=e.to_id AND v.kind='vendor'))
              OR (e.to_id=? AND e.relation='publishes' AND EXISTS
               (SELECT 1 FROM entities v WHERE v.id=e.from_id AND v.kind='vendor')))
             AND e.source_url IN (""" + slots + ") ORDER BY e.from_id,e.to_id,e.relation,e.source_url LIMIT ?",
                                (key, key, *sources, cap + 1)).fetchall()
            coverage['truncated'] |= len(rows) > cap
            return [edge(row['from_id'], row['to_id'], row['relation'], row['source_url'],
                         row['confidence'], row['observed_at']) for row in rows[:cap]]
        result = []
        identities = self.aliases(conn,key,coverage) if node['kind']=='vulnerability' else [key]
        for direction in ('from_id','to_id'):
            rows=[]
            for identity in identities:
                remaining=cap+1-len(rows)
                if remaining<=0:
                    coverage['truncated']=True
                    break
                rows.extend(conn.execute('SELECT * FROM edges WHERE '+direction+'=? ORDER BY from_id,to_id,relation,source_url LIMIT ?', (identity,remaining)).fetchall())
            coverage['truncated'] |= len(rows)>cap
            for row in rows[:cap]:
                relation = row['relation']
                status = 'candidate' if relation=='candidate_mention' else 'claim' if relation in ('mentions','text_mentions') else 'context'
                source,target=self.canonical(conn,row['from_id']),self.canonical(conn,row['to_id'])
                if source==target:
                    continue
                result.append(edge(source,target,relation,row['source_url'],row['confidence'],row['observed_at'],status,
                                   {'source_from_id':row['from_id'],'source_to_id':row['to_id']} if (source,target)!=(row['from_id'],row['to_id']) else None))
        hierarchy = []
        if node['kind']=='company':
            hierarchy = conn.execute('SELECT company_id,parent_company_id,source_url,updated_at FROM company_profiles WHERE company_id=? AND parent_company_id!=\'\'', (key,)).fetchall()
            hierarchy += conn.execute('SELECT company_id,parent_company_id,source_url,updated_at FROM company_profiles WHERE parent_company_id=? ORDER BY company_id LIMIT ?', (key,cap+1)).fetchall()
        coverage['truncated'] |= len(hierarchy)>cap
        for row in hierarchy[:cap]:
            result.append(edge(row['parent_company_id'],row['company_id'],'subsidiary',row['source_url'],None,row['updated_at'],'curated_group'))
        if node['kind']=='company':
            if coverage['companies_expanded']>=20:
                coverage['truncated']=True
            else:
                coverage['companies_expanded']+=1
                assets, truncated = company_assets(conn,key)
                coverage['truncated'] |= truncated or len(assets)>cap
                for asset in assets[:cap]:
                    proof=asset['evidence']
                    result.append(edge(key,asset['id'],'company_asset',source_url=proof[0].get('source_url','') if proof else '',confidence=asset['confidence'],observed_at=proof[0].get('observed_at') if proof else None,status='accepted' if asset['included'] else 'service' if asset['role']=='service' else asset['status'], evidence={'role':asset['role'],'reasons':asset['reasons'],'path':proof}))
        if node['kind']=='domain' or key.startswith('domain:'):
            decisions=conn.execute('SELECT * FROM company_asset_decisions WHERE asset_id=? ORDER BY company_id LIMIT ?', (key,cap+1)).fetchall()
            coverage['truncated'] |= len(decisions)>cap
            for decision in decisions[:cap]:
                status='accepted' if decision['status']=='confirmed' and decision['role']=='owned' else 'service' if decision['role']=='service' else decision['status']
                result.append(edge(decision['company_id'],key,'company_asset',decision['source_url'],observed_at=decision['updated_at'],status=status,
                                   evidence={'role':decision['role'],'manual_note':decision['evidence']}))
        rows = conn.execute('SELECT * FROM observations WHERE asset_id=? ORDER BY id LIMIT ?', (key,cap+1)).fetchall()
        coverage['truncated'] |= len(rows)>cap
        for row in rows[:cap]:
            result.append(edge(key,'observation:'+row['id'],'observed_version',row['source_url'],row['confidence'],row['observed_at'],'observation',row['evidence']))
        selector='id' if node['kind']=='alert' else 'advisory_id' if node['kind']=='vulnerability' else 'asset_id'
        alerts = conn.execute('SELECT * FROM alerts WHERE '+selector+'=? AND '+self.active_alert_filter()+' ORDER BY id LIMIT ?', (key,cap+1)).fetchall()
        coverage['truncated'] |= len(alerts)>cap
        for row in alerts[:cap]:
            result += [edge(row['asset_id'],row['id'],'potential_match',row['source_url'],row['confidence'],row['observed_at'],'potential'),
                       edge(row['id'],row['advisory_id'],'matched_advisory',row['url'],row['confidence'],row['last_seen'],'potential',{'version_state':row['version_state'],'reasons':json.loads(row['reasons'])})]
        if node['kind']=='software_version':
            row = conn.execute('SELECT asset_id,source_url,confidence,observed_at FROM observations WHERE id=?',(key[12:],)).fetchone()
            if row:
                result.append(edge(row['asset_id'],key,'observed_version',row['source_url'],row['confidence'],row['observed_at'],'observation'))
        return sorted({e['id']:e for e in result}.values(), key=lambda e:(e['from_id'],e['to_id'],e['relation'],e['id']))

    def company_scope(self, conn, company_id, coverage):
        """Build a bounded company view without traversing shared infrastructure."""
        from .entity_resolution import resolve
        from .technographic_store import document_input, _resolve_document

        assets, truncated = company_assets(conn, company_id)
        coverage['truncated'] |= truncated
        evidence, documents = set(), set()
        rows = conn.execute("""SELECT DISTINCT e.* FROM entities e WHERE e.id IN (
         SELECT source_entity_id FROM technographic_sources WHERE organization_id=?
         UNION SELECT to_id FROM edges WHERE from_id=? AND relation IN ('has_public_evidence','candidate_evidence','registry_candidate'))
         ORDER BY e.id LIMIT 1001""", (company_id, company_id)).fetchall()
        coverage['truncated'] |= len(rows) > 1000
        for row in rows[:1000]:
            entity = dict(row)
            entity['metadata'] = json.loads(entity['metadata'])
            doc = document_input(entity)
            if doc is not None:
                resolution = _resolve_document(conn, entity, doc)
            else:
                context = entity['metadata'].get('company_context') or {}
                resolution = resolve(conn, context=context, source_url=entity.get('source_url') or '')
            if resolution.get('organization_id') != company_id:
                continue
            evidence.add(entity['id'])
            documents.update(item[0] for item in conn.execute(
                'SELECT document_id FROM technographic_sources WHERE source_entity_id=? AND organization_id=?',
                (entity['id'], company_id)))
        return {'root': company_id, 'assets': {item['id']: item for item in assets},
                'included': {item['id'] for item in assets if item['included']},
                'evidence': evidence, 'documents': documents, 'technology_sources': {}}

    def company_node_scope(self, conn, node, scope):
        key = node['id']
        if key == scope['root']:
            return 'company'
        if key in scope['assets']:
            return 'company_asset'
        if key in scope['evidence']:
            return 'company_evidence'
        if node['kind'] == 'software_version':
            row = conn.execute('SELECT asset_id,origin FROM observations WHERE id=?', (key[12:],)).fetchone()
            if row and (row['asset_id'] in scope['included'] or row['asset_id'] == scope['root']
                        and row['origin'].removeprefix('technographic:') in scope['documents']):
                return 'company_evidence'
        if node['kind'] == 'alert':
            if node['metadata']['asset_id'] in scope['included']:
                return 'company_evidence'
            if node['metadata']['asset_id'] == scope['root']:
                # A company-level match must retain the same validated source
                # as its reconciled observation. The root ID alone cannot make
                # an old or incorrectly attributed match company evidence.
                alert = node['alert']
                rows = conn.execute("""SELECT origin FROM observations WHERE asset_id=?
                 AND vendor=? AND product=? AND version=? AND source_url=?""",
                                    (scope['root'], alert['vendor'], alert['product'],
                                     alert['version'], alert['source_url']))
                if any(row['origin'].startswith('technographic:') and
                       row['origin'][14:] in scope['documents'] for row in rows):
                    return 'company_evidence'
        return 'shared_context'

    def company_edge_allowed(self, conn, source, target, item, scope):
        key, other, relation = source['id'], target['id'], item['relation']
        target_scope = self.company_node_scope(conn, target, scope)
        if source['scope'] == 'shared_context':
            # A technology's vendor is useful context. Its other observations,
            # advisories and customers are outside this company's evidence.
            return (source['kind'] in SOFTWARE_LABEL_KINDS and target['kind'] == 'vendor'
                    and (relation == 'vendor_label' and item['from_id'] == key
                         or relation == 'publishes' and item['to_id'] == key)
                    and item['source_url'] in scope['technology_sources'].get(key, set()))
        if key == scope['root']:
            if relation in {'company_asset', 'official_website', 'primary_domain_anchor'}:
                return other in scope['assets']
            if relation == 'verified_asn':
                return bool(conn.execute("SELECT 1 FROM company_asn_anchors WHERE company_id=? AND 'asn:AS'||asn=?",
                                         (key, other)).fetchone())
            if relation == 'subsidiary':
                return target['kind'] == 'company'
            return target_scope == 'company_evidence'
        if target['kind'] == 'company':
            return other == scope['root'] and relation in {'company_asset', 'has_public_evidence'}
        if target_scope != 'shared_context':
            return True
        # Never introduce another host, source or match through a generic edge.
        # Shared infrastructure and software labels are retained as leaves.
        return target['kind'] in SOFTWARE_LABEL_KINDS | {'ip', 'prefix', 'asn', 'vendor', 'vulnerability'}

    def graph(self, root_id, depth=2, max_nodes=120, max_edges=300, include_wireless=False):
        if not root_id or not 1<=depth<=5 or not 1<=max_nodes<=300 or not 1<=max_edges<=800:
            raise ValueError('Invalid graph limits')
        with self.store.connection() as conn:
            root = self.node(conn,root_id)
            if root is None:
                raise LookupError('Graph root not found')
            requested_root_id,root_id=root_id,root['id']
            nodes, edges, visited = {root_id:root}, {}, set()
            queue = deque([(root_id,0)])
            coverage = {'truncated':False,'companies_expanded':0,'wireless':'not_requested','risk_basis':'reconciled alerts only','extraction_method':'deterministic-catalog-v1'}
            scope = self.company_scope(conn, root_id, coverage) if root['kind'] == 'company' else None
            if scope:
                root['scope'] = 'company'
                coverage.update(scope='company', shared_context_expansion=False,
                                vendor_context='technology-to-vendor labels only; no legal-company ownership inferred')
            while queue:
                key, level = queue.popleft()
                if key in visited:
                    continue
                visited.add(key)
                if scope and (key in scope['assets'] and key not in scope['included']
                              or nodes[key]['scope'] == 'shared_context' and nodes[key]['kind'] not in SOFTWARE_LABEL_KINDS):
                    continue
                if level>=depth:
                    if conn.execute('SELECT 1 FROM edges WHERE from_id=? OR to_id=? LIMIT 1',(key,key)).fetchone() or nodes[key]['kind'] in ('company','alert','software_version'):
                        coverage['truncated']=True
                    continue
                for item in self.neighbors(conn,nodes[key],max_edges,coverage,scope):
                    # Alert pairs are emitted together; only attach edges incident to this frontier.
                    if key not in (item['from_id'],item['to_id']):
                        continue
                    other = item['to_id'] if item['from_id']==key else item['from_id']
                    if item['id'] in edges:
                        continue
                    target = nodes.get(other) or self.node(conn,other)
                    if target is None:
                        coverage['missing_endpoints'] = coverage.get('missing_endpoints',0)+1
                        continue
                    if scope:
                        if not self.company_edge_allowed(conn, nodes[key], target, item, scope):
                            continue
                        target['scope'] = self.company_node_scope(conn, target, scope)
                        if target['scope'] == 'shared_context':
                            # Shared nodes can retain another company's latest
                            # provenance and detection method. Keep intrinsic
                            # identity here; this view's edges carry evidence.
                            target['source_url'] = ''
                            target['observed_at'] = None
                            target['confidence'] = None
                            target['metadata'] = {field: target['metadata'][field]
                                                  for field in ('vendor', 'product', 'ecosystem', 'package')
                                                  if field in target['metadata']}
                            target['metadata']['evidence_role'] = 'shared_context'
                        if item['relation'] == 'verified_asn' and item['from_id'] == root_id:
                            anchor = conn.execute("SELECT evidence,source_url,verified_at FROM company_asn_anchors WHERE company_id=? AND 'asn:AS'||asn=?",
                                                  (root_id, item['to_id'])).fetchone()
                            if anchor:
                                item.update(status='verified_affiliation', evidence_role='verified_affiliation',
                                            evidence={'note': anchor['evidence'], 'risk_propagation': False},
                                            source_url=anchor['source_url'], observed_at=anchor['verified_at'])
                        if other in scope['assets']:
                            asset = scope['assets'][other]
                            target['ownership'] = {field: asset[field] for field in ('included', 'status', 'role', 'reasons')}
                        if target['kind'] in SOFTWARE_LABEL_KINDS:
                            scope['technology_sources'].setdefault(other, set()).add(item['source_url'])
                    if len(edges)>=max_edges or other not in nodes and len(nodes)>=max_nodes:
                        coverage['truncated']=True
                        continue
                    edges[item['id']]=item
                    if other not in nodes:
                        nodes[other]=target
                        queue.append((other,level+1))
            if include_wireless:
                from .wireless_attribution import company_wireless_summary
                for node in nodes.values():
                    if node['kind']=='company' and (not scope or node['id'] == root_id):
                        summary=company_wireless_summary(conn,node['id'],limit=3)
                        node['metadata']['wireless_summary']={k:v for k,v in summary.items() if k!='devices'}
                        node['metadata']['wireless_summary']['links']=[{k:d[k] for k in ('id','role','status','attribution_source_url') if k in d} for d in summary['devices']]
                coverage['wireless']='company summaries only; scan locations are not device positions; no wireless risk propagation'
            return {'root_id':root_id,'requested_root_id':requested_root_id,'nodes':list(nodes.values()),'edges':list(edges.values()),'truncated':coverage['truncated'],
                    'limits':{'depth':depth,'max_nodes':max_nodes,'max_edges':max_edges},'coverage':coverage}

    def driver(self, conn, alert):
        since = (datetime.now(timezone.utc)-timedelta(days=30)).isoformat()
        chatter = conn.execute('SELECT count(DISTINCT a.url) FROM article_links l JOIN articles a ON a.id=l.article_id WHERE l.advisory_id IN (SELECT alias FROM advisory_aliases WHERE canonical_id=? UNION SELECT ?) AND julianday(a.published)>=julianday(?)', (alert['advisory_id'],alert['advisory_id'],since)).fetchone()[0]
        severity, epss = alert['severity'], alert['epss']
        score = min(100, max(0,severity or 0)*5 + (40 if alert['kev'] else 0) + max(0,min(1,epss or 0))*10 + min(5,chatter))
        if alert['kev']:
            score=max(85,score)
        return {'score':round(score,2),'status':'potential','drivers':{'cvss':severity,'kev':bool(alert['kev']),'epss':epss,
                'version_state':alert['version_state'],'version_uncertain':alert['version_state'] not in ('exact','affected_range'),
                'recent_distinct_reporting':chatter},'method':'heuristic-alert-v1; KEV floor 85; reporting is context, not proof'}

    def company_risk(self, company_id, include_subsidiaries=False, limit=50):
        if not 1<=limit<=100:
            raise ValueError('Invalid risk limit')
        with self.store.connection() as conn:
            company(conn,company_id)
            groups = [(company_id,[])]
            visited = {company_id}
            truncated=False
            if include_subsidiaries:
                for cid,path in groups:
                    children=conn.execute('SELECT company_id,source_url,updated_at FROM company_profiles WHERE parent_company_id=? ORDER BY company_id LIMIT 51',(cid,)).fetchall()
                    truncated |= len(children)>50
                    for child in children[:50]:
                        if child['company_id'] in visited:
                            continue
                        if len(groups)>=50 or len(path)>=5:
                            truncated=True
                            continue
                        visited.add(child['company_id'])
                        groups.append((child['company_id'],path+[edge(cid,child['company_id'],'subsidiary',child['source_url'],observed_at=child['updated_at'],status='curated_group')]))
            results, contexts = {}, []
            total=0
            for cid,group_path in groups:
                assets, incomplete=company_assets(conn,cid)
                truncated |= incomplete
                included = [a for a in assets if a['included']]
                contexts.extend({'company_id':cid,**a} for a in assets if not a['included'])
                if not included:
                    continue
                ids=[a['id'] for a in included]
                slots=','.join('?' for _ in ids)
                total+=conn.execute('SELECT count(*) FROM alerts WHERE asset_id IN ('+slots+') AND '+self.active_alert_filter(),ids).fetchone()[0]
                rows=conn.execute('SELECT * FROM alerts WHERE asset_id IN ('+slots+') AND '+self.active_alert_filter()+' ORDER BY kev DESC,rank DESC,id LIMIT ?',(*ids,limit+1)).fetchall()
                truncated |= len(rows)>limit
                by_id={a['id']:a for a in included}
                for row in rows[:limit]:
                    alert=dict(row)
                    asset=by_id[row['asset_id']]
                    result={'id':row['id'],'company_id':cid,'asset_id':row['asset_id'],'advisory_id':row['advisory_id'],
                            'risk':self.driver(conn,alert),'version_state':row['version_state'],'version':row['version'],
                            'observed_at':row['observed_at'],'last_matched':row['last_seen'],'reasons':json.loads(row['reasons']),
                            'paths':[group_path+asset['evidence']+[edge(row['asset_id'],row['id'],'potential_match',row['source_url'],row['confidence'],row['observed_at'],'potential',row['evidence']),
                            edge(row['id'],row['advisory_id'],'matched_advisory',row['url'],status='potential',evidence={'version_state':row['version_state']})]]}
                    if row['id'] in results:
                        results[row['id']]['paths']+=result['paths']
                    else:
                        results[row['id']]=result
            ordered=sorted(results.values(),key=lambda r:(-r['risk']['score'],r['id']))
            return {'company_id':company_id,'group':include_subsidiaries,'items':ordered[:limit], 'score':max((r['risk']['score'] for r in ordered),default=None),
                    'total':len(results) if not truncated else None,'truncated':truncated or len(ordered)>limit or len(contexts)>limit,
                    'context_assets':contexts[:limit],'coverage':{'companies':len(groups),'company_limit':50,'hierarchy_depth':5,'matches_considered':total,'per_company_alert_limit':limit,'selection':'bounded per-company KEV/rank shortlist, then heuristic score; not a global exhaustive ranking',
                    'risk_basis':'included company assets + existing reconciled alerts; no network, catalog or claim propagation'}}

    def intelligence(self, q='', limit=25, offset=0):
        from .store import fts_query
        if len(q)>300 or not 1<=limit<=100 or not 0<=offset<=10000:
            raise ValueError('Invalid intelligence bounds')
        candidate_limit, expansion_limit, company_limit = 1000, 3000, 20
        with self.store.connection() as conn:
            results, entities, assets = {}, {}, set()
            partial = False

            def add_entity(key):
                nonlocal partial
                key=self.canonical(conn,key)
                if key in entities:
                    return entities[key]
                if len(results)>=expansion_limit:
                    partial=True
                    return None
                row=conn.execute('SELECT e.*,p.name AS profile_name FROM entities e LEFT JOIN company_profiles p ON p.company_id=e.id WHERE e.id=?',(key,)).fetchone()
                if row is None:
                    return None
                item=dict(row)
                entities[key]=item
                results[key]={'id':key,'canonical_id':key,'root_id':key,'kind':item['kind'],'name':item['profile_name'] or item['name'],
                              'route':'graph','detail_kind':'entity','updated_at':item['updated_at']}
                return item

            exact=re.fullmatch(r'CVE-\d{4}-\d{4,}|GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}',q.strip(),re.I)
            direct=q.strip().upper() if exact else q
            alias=conn.execute('SELECT canonical_id FROM advisory_aliases WHERE alias=?',(direct,)).fetchone()
            direct_entity=conn.execute('SELECT 1 FROM entities WHERE id=?',(direct,)).fetchone()
            pinned_id=self.canonical(conn,direct) if exact or alias or direct_entity else None
            if pinned_id is not None:
                seeds=[direct]
            else:
                expression=fts_query(q)
                where=''
                args=[]
                if expression:
                    where='''WHERE e.rowid IN (SELECT rowid FROM entity_fts WHERE entity_fts MATCH ?) OR
                     e.id IN (SELECT p.company_id FROM company_profiles p JOIN company_profile_fts f ON f.rowid=p.rowid WHERE company_profile_fts MATCH ?) OR
                     e.id IN (SELECT a.canonical_id FROM advisories a JOIN advisory_fts f ON f.rowid=a.rowid WHERE advisory_fts MATCH ?) OR
                     e.id IN (SELECT a.id FROM articles a JOIN article_fts f ON f.rowid=a.rowid WHERE article_fts MATCH ?)'''
                    args=[expression]*4
                seeds=[r[0] for r in conn.execute('SELECT e.id FROM entities e '+where+' ORDER BY e.updated_at DESC,e.id LIMIT ?',(*args,candidate_limit+1))]
                partial |= len(seeds)>candidate_limit
                seeds=seeds[:candidate_limit]
            for key in seeds:
                add_entity(key)
            seed_entities=list(entities.values())
            seed_companies=[r['id'] for r in seed_entities if r['kind']=='company']
            partial |= len(seed_companies)>company_limit
            for cid in seed_companies[:company_limit]:
                included,incomplete=company_assets(conn,cid)
                partial |= incomplete
                for asset in included:
                    if asset['included']:
                        if len(assets)>=candidate_limit:
                            partial=True
                            break
                        assets.add(asset['id'])
                        add_entity(asset['id'])
            for item in seed_entities:
                if item['kind'] in ('technology','device','os','package'):
                    rows=conn.execute("SELECT DISTINCT from_id FROM edges WHERE to_id=? AND relation='observed_technology' ORDER BY from_id LIMIT ?",(item['id'],candidate_limit+1)).fetchall()
                    partial |= len(rows)>candidate_limit
                    for row in rows[:candidate_limit]:
                        if len(assets)>=candidate_limit and row[0] not in assets:
                            partial=True
                            break
                        assets.add(row[0])
                        add_entity(row[0])
                elif item['id'].startswith('domain:') or item['kind'] in ('domain','asset','ip'):
                    assets.add(item['id'])
            advisories={r['id'] for r in seed_entities if r['kind']=='vulnerability'}
            if exact or alias:
                advisories.add(self.canonical(conn,direct))
            alerts={}
            for selector,identities in (('asset_id',assets),('advisory_id',advisories)):
                if not identities:
                    continue
                slots=','.join('?' for _ in identities)
                rows=conn.execute('SELECT * FROM alerts WHERE '+selector+' IN ('+slots+') AND '+self.active_alert_filter()+' ORDER BY '+selector+',id LIMIT ?',(*sorted(identities),candidate_limit+1)).fetchall()
                partial |= len(rows)>candidate_limit
                for row in rows[:candidate_limit]:
                    alerts[row['id']]=dict(row)
            for alert in alerts.values():
                if len(results)>=expansion_limit:
                    partial=True
                    break
                key=alert['id']
                results[key]={'id':key,'canonical_id':key,'root_id':alert['asset_id'],'kind':'alert',
                              'name':alert['advisory_id']+' · '+(alert['product'] or ''),'route':'graph','detail_kind':'warning',
                              'updated_at':alert['last_seen'],'alert':alert}
                advisories.add(alert['advisory_id'])
                if len(assets)<candidate_limit:
                    assets.add(alert['asset_id'])
                    add_entity(alert['asset_id'])
                else:
                    partial=True
                add_entity(alert['advisory_id'])
            if assets:
                variants=set(assets)
                for key in assets:
                    if key.startswith('domain:'):
                        host=key[7:]
                        variants.add('domain:'+host[4:] if host.startswith('www.') else 'domain:www.'+host)
                slots=','.join('?' for _ in variants)
                owners={r[0] for r in conn.execute('SELECT DISTINCT from_id FROM edges WHERE to_id IN ('+slots+") AND relation='official_website' ORDER BY from_id LIMIT ?",(*sorted(variants),company_limit+1))}
                slots=','.join('?' for _ in assets)
                owners.update(r[0] for r in conn.execute('SELECT DISTINCT company_id FROM company_asset_decisions WHERE asset_id IN ('+slots+') ORDER BY company_id LIMIT ?',(*sorted(assets),company_limit+1)))
                partial |= len(owners)>company_limit
                for cid in sorted(owners)[:company_limit]:
                    if not conn.execute("SELECT 1 FROM entities WHERE id=? AND kind='company'",(cid,)).fetchone():
                        continue
                    associated,incomplete=company_assets(conn,cid)
                    partial |= incomplete
                    if any(a['included'] and a['id'] in assets for a in associated):
                        add_entity(cid)
            report_targets=set(entities)|advisories
            for identity in list(report_targets):
                if identity in advisories:
                    state={'truncated':False}
                    report_targets.update(self.aliases(conn,identity,state))
                    partial |= state['truncated']
            if report_targets:
                slots=','.join('?' for _ in report_targets)
                for table,column in (('signal_mentions','entity_id'),('article_links','advisory_id')):
                    rows=conn.execute('SELECT DISTINCT article_id FROM '+table+' WHERE '+column+' IN ('+slots+') ORDER BY '+column+',article_id LIMIT ?',(*sorted(report_targets),candidate_limit+1)).fetchall()
                    partial |= len(rows)>candidate_limit
                    for row in rows[:candidate_limit]:
                        add_entity(row[0])
            for row in conn.execute('SELECT id,ssid,identifier,updated_at FROM wireless_devices WHERE id=? OR identifier=? LIMIT 2',(q,q)):
                results[row['id']]={'id':row['id'],'canonical_id':row['id'],'root_id':row['id'],'kind':'wireless_device',
                                    'name':row['ssid'] or row['identifier'],'route':'graph','detail_kind':'entity','updated_at':row['updated_at']}
            ordered=sorted(results.values(),key=lambda r:r['id'])
            ordered.sort(key=lambda r:r['updated_at'] or '',reverse=True)
            ordered.sort(key=lambda r:r['kind']!='company')
            if pinned_id in results:
                ordered.sort(key=lambda r:r['id']!=pinned_id)
            items=[{k:v for k,v in row.items() if k!='updated_at'} for row in ordered[offset:offset+limit]]
            return {'items':items,'total':len(results),'partial':partial,'coverage':{'candidate_limit':candidate_limit,'expansion_limit':expansion_limit,
                    'company_limit':company_limit,'wireless_search':'exact identifier or ID only; no location lookup',
                    'extraction':'new articles; historical articles require bounded backfill','method':'indexed FTS + canonical advisory + included company asset joins'}}


def register_graph_routes(app, store):
    from fastapi import HTTPException, Query
    service=KnowledgeGraph(store)
    def call(fn,*args):
        try:
            return fn(*args)
        except LookupError as error:
            raise HTTPException(404,str(error)) from error
        except ValueError as error:
            raise HTTPException(422,str(error)) from error
    @app.get('/api/graph')
    def graph(root_id: str=Query(...,min_length=1,max_length=2048),depth: int=Query(2,ge=1,le=5),max_nodes: int=Query(120,ge=1,le=300),max_edges: int=Query(300,ge=1,le=800),include_wireless: bool=False):
        return call(service.graph,root_id,depth,max_nodes,max_edges,include_wireless)
    @app.get('/api/company-risk')
    def risk(id: str=Query(...,min_length=1,max_length=2048),include_subsidiaries: bool=False,limit: int=Query(50,ge=1,le=100)):
        return call(service.company_risk,id,include_subsidiaries,limit)
    @app.get('/api/intelligence')
    def intelligence(q: str=Query('',max_length=300),limit: int=Query(25,ge=1,le=100),offset: int=Query(0,ge=0,le=10000)):
        return call(service.intelligence,q,limit,offset)
    @app.post('/api/intelligence/extract')
    def extraction(after: int=Query(0,ge=0),limit: int=Query(25,ge=1,le=100)):
        from .text_signals import backfill
        return backfill(store,after,limit)
