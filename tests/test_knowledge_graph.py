import json
import tempfile
import unittest
from pathlib import Path

import httpx
import asyncio

from signalwatch.store import Store
from signalwatch.knowledge_graph import KnowledgeGraph
from signalwatch.text_signals import backfill


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.store=Store(Path(self.tmp.name)/'graph.db')
        self.kg=KnowledgeGraph(self.store)
    def tearDown(self):
        self.tmp.cleanup()
    def entity(self,key,kind='domain',name=None):
        return {'id':key,'kind':kind,'name':name or key}
    def fixture(self):
        self.store.ingest({'entities':[self.entity('company:a','company','Acme Holdings'),self.entity('company:b','company','Acme Inc')],
                          'advisories':[{'id':'CVE-2026-12345','title':'Widget issue','severity':9.8,'source':'nvd','url':'https://advisories.test/a',
                                         'affected':[{'vendor':'maker','product':'widget','version':'1.0'}]}],
                          'observations':[{'asset_id':'domain:a.test','vendor':'maker','product':'widget','version':'1.0','source_url':'https://a.test/','confidence':0},
                                          {'asset_id':'domain:b.test','vendor':'maker','product':'widget','version':'2.0'}],
                          'kev':[{'cveID':'CVE-2026-12345','dateAdded':'2001-01-01'}]})
        self.store.save_company_profile('company:a','Acme Holdings',aliases=['Shared Alias','Acme Group'])
        self.store.save_company_profile('company:b','Acme Inc',aliases=['Shared Alias'],parent_company_id='company:a')
        self.store.set_company_asset('company:a','https://a.test/','confirmed','owned','operator evidence','https://registry.test/a')
        self.store.set_company_asset('company:b','https://b.test/','candidate','owned','unverified','https://registry.test/b')
        self.store.reconcile()
    def test_five_hops_cycles_stable_and_hard_caps(self):
        self.store.ingest({'entities':[self.entity(str(i)) for i in range(12)],'edges':[{'from_id':str(i),'to_id':str((i+1)%12),'relation':'dns'} for i in range(12)]})
        graph=self.kg.graph('0',5,300,800)
        self.assertIn('5',[n['id'] for n in graph['nodes']])
        self.assertTrue(graph['truncated'])
        self.assertEqual(graph,self.kg.graph('0',5,300,800))
        small=self.kg.graph('0',5,3,2)
        self.assertLessEqual(len(small['nodes']),3)
        self.assertLessEqual(len(small['edges']),2)
        self.assertTrue(small['truncated'])
        ids={n['id'] for n in small['nodes']}
        self.assertTrue(all(e['from_id'] in ids and e['to_id'] in ids for e in small['edges']))
        with self.assertRaises(ValueError): self.kg.graph('0',6)
        with self.assertRaises(ValueError): self.kg.graph('0',2,301)
    def test_accepted_candidate_registry_network_never_propagate(self):
        self.fixture()
        self.store.ingest({'entities':[self.entity('ip:192.0.2.1'),self.entity('domain:other.test')], 'edges':[
            {'from_id':'company:b','to_id':'domain:a.test','relation':'registered_by'},
            {'from_id':'domain:b.test','to_id':'ip:192.0.2.1','relation':'resolves_to'},
            {'from_id':'domain:a.test','to_id':'ip:192.0.2.1','relation':'resolves_to'}]})
        risk=self.kg.company_risk('company:b')
        self.assertEqual(risk['items'],[])
        self.assertIsNone(risk['score'])
        self.assertEqual(risk['context_assets'][0]['status'],'candidate')
        self.store.set_company_asset('company:b','https://a.test/','confirmed','service','shared service','https://registry.test/')
        self.assertEqual(self.kg.company_risk('company:b')['items'],[])
        self.store.set_company_asset('company:b','https://a.test/','rejected','owned','rejected','https://registry.test/')
        self.assertEqual(self.kg.company_risk('company:b')['items'],[])
    def test_exact_alert_path_zero_confidence_old_kev_and_catalog_only(self):
        self.fixture()
        risk=self.kg.company_risk('company:a')
        self.assertEqual(len(risk['items']),1)
        self.assertEqual(risk['items'][0]['version_state'],'exact')
        self.assertGreaterEqual(risk['score'],85)
        path=risk['items'][0]['paths'][0]
        self.assertEqual(path[-2]['confidence'],0)
        self.assertEqual(path[-1]['to_id'],'CVE-2026-12345')
        graph=self.kg.graph('domain:a.test',3)
        self.assertTrue(any(e['relation']=='matched_advisory' for e in graph['edges']))
        self.assertTrue(all(e['evidence_role']=='catalog_only' for e in graph['edges'] if e['relation']=='affected_by'))
        self.assertFalse(any(n['kind']=='alert' for n in self.kg.graph('domain:b.test',1)['nodes']))
    def test_explicit_group_separate_from_entity(self):
        self.fixture()
        self.store.set_company_asset('company:a','https://a.test/','rejected','owned','not ours','https://registry.test/')
        self.store.set_company_asset('company:b','https://a.test/','confirmed','owned','owned','https://registry.test/')
        self.assertEqual(self.kg.company_risk('company:a')['items'],[])
        group=self.kg.company_risk('company:a',True)
        self.assertEqual(group['items'][0]['paths'][0][0]['relation'],'subsidiary')
        self.assertEqual(self.store.detail('company:a')['alerts'],[])
    def test_ambiguous_alias_negation_versions_idempotent_and_backfill(self):
        self.fixture()
        article={'url':'https://research.test/report','title':'Shared Alias and Acme Group database discussion',
                 'summary':'No exploit available for widget version 1.0. A patch is claimed. CVE-2026-12345.', 'published':'2026-10-19T00:00:00Z'}
        self.store.ingest({'articles':[article]})
        self.store.ingest({'articles':[article]})
        with self.store.connection() as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM text_signals').fetchone()[0],1)
            result=json.loads(conn.execute('SELECT extraction FROM text_signals').fetchone()[0])
            self.assertEqual(next(c for c in result['claims'] if c['kind']=='exploit')['status'],'negated')
            self.assertIn('1.0',result['versions'])
            self.assertEqual(next(m for m in result['mentions'] if m['entity_id']=='company:b')['status'],'candidate')
            self.assertEqual(next(m for m in result['mentions'] if m['entity_id']=='company:a')['status'],'resolved')
            self.assertEqual(conn.execute("SELECT count(*) FROM edges WHERE relation='candidate_mention'").fetchone()[0],1)
        first=backfill(self.store,0,1)
        self.assertEqual(first['processed'],1)
        self.assertEqual(backfill(self.store,first['next_cursor'],1)['processed'],0)
        self.assertEqual(len(self.kg.company_risk('company:a')['items']),1)
    def test_search_alias_cve_alert_counts_and_pagination(self):
        self.fixture()
        results=self.kg.intelligence('Acme Group')
        self.assertEqual(results['items'][0]['id'],'company:a')
        self.assertTrue(any(r['kind']=='alert' for r in results['items']))
        self.assertTrue(any(r['id']=='domain:a.test' for r in results['items']))
        results=self.kg.intelligence('CVE-2026-12345')
        self.assertTrue(any(r['kind']=='alert' for r in results['items']))
        page=self.kg.intelligence('CVE-2026-12345',1,1)
        self.assertEqual(page['total'],results['total'])
        self.assertEqual(len(page['items']),1)
    def test_exact_wireless_search_is_bounded_without_coordinates(self):
        with self.store.connection(write=True) as conn:
            conn.execute("INSERT INTO wireless_devices(id,radio_type,identifier,ssid,updated_at) VALUES('wireless:synthetic','wifi','00:00:00:00:00:00','Synthetic radio','2026-10-19')")
        result=self.kg.intelligence('00:00:00:00:00:00')
        self.assertEqual(result['total'],1)
        self.assertEqual(result['items'][0]['kind'],'wireless_device')
        graph=self.kg.graph('wireless:synthetic')
        self.assertIsNone(graph['nodes'][0]['risk'])
        self.assertNotIn('latitude',graph['nodes'][0]['metadata'])
    def test_search_linked_reporting_deduplicates_and_keeps_claims(self):
        self.fixture()
        self.store.ingest({'articles':[{'url':'https://research.test/link','title':'Acme Group report','summary':'CVE-2026-12345 database claim','cves':['CVE-2026-12345']} ]})
        result=self.kg.intelligence('CVE-2026-12345')
        self.assertEqual(len({r['id'] for r in result['items']}),len(result['items']))
        self.assertTrue(any(r['kind']=='article' for r in result['items']))
        article=next(r for r in result['items'] if r['kind']=='article')
        self.assertEqual(self.store.detail(article['id'])['article']['extraction']['method'],'deterministic-catalog-v1')

    def test_exact_identifiers_canonicalize_early_reports_and_graph_edges(self):
        ghsa='GHSA-AAAA-BBBB-CCCC'
        cve='CVE-2026-12345'
        base={'id':ghsa,'title':'Widget issue','source':'GitHub','url':'https://advisories.test/ghsa',
              'affected':[{'vendor':'maker','product':'widget','version':'1.0'}]}
        self.store.ingest({'advisories':[base], 'articles':[{'url':'https://news.test/early','title':ghsa+' report','summary':'Early report','cves':[ghsa]}]})
        self.store.ingest({'advisories':[dict(base,id=cve,aliases=[ghsa],source='nvd',url='https://advisories.test/cve'),
                                        dict(base,id=cve+'6',source='nvd',url='https://advisories.test/other')],
                           'kev':[{'cveID':cve,'dateAdded':'2026-01-01'}]})
        results=self.kg.intelligence(cve)['items']
        self.assertEqual({r['id'] for r in results if r['kind']=='vulnerability'},{cve})
        report=next(r['id'] for r in results if r['kind']=='article')
        self.assertEqual({r['id'] for r in self.kg.intelligence(ghsa)['items']},{r['id'] for r in results})
        graph=self.kg.graph(ghsa,1)
        self.assertEqual(graph['root_id'],cve)
        self.assertIn(report,{n['id'] for n in graph['nodes']})
        self.assertNotIn(ghsa,{n['id'] for n in graph['nodes']})
        self.assertNotIn('KEV:'+cve,{n['id'] for n in graph['nodes']})
        rewritten=next(e for e in graph['edges'] if e['from_id']==report)
        self.assertEqual(rewritten['to_id'],cve)
        self.assertEqual(rewritten['evidence']['source_to_id'],ghsa)

    def test_product_and_cve_search_resolve_only_accepted_company_assets(self):
        self.fixture()
        for query in ('widget','CVE-2026-12345'):
            results=self.kg.intelligence(query)['items']
            companies={r['id'] for r in results if r['kind']=='company'}
            self.assertIn('company:a',companies)
            self.assertNotIn('company:b',companies)
        self.store.set_company_asset('company:a','https://a.test/','rejected','owned','not ours','https://registry.test/')
        self.assertFalse(any(r['kind']=='alert' for r in self.kg.intelligence('Acme Group')['items']))

    def test_exact_identifier_finds_historical_links_without_a_vulnerability_node(self):
        cve='CVE-2026-12345'
        ghsa='GHSA-AAAA-BBBB-CCCC'
        self.store.ingest({'articles':[{'url':'https://news.test/historical','title':'Historical research',
                                       'summary':'Stored reporting record','cves':[cve]}]})
        with self.store.connection() as conn:
            self.assertIsNone(self.kg.node(conn,cve))
        result=self.kg.intelligence(cve)['items']
        self.assertEqual(len(result),1)
        self.assertEqual(result[0]['kind'],'article')
        self.assertEqual(self.kg.intelligence(cve+'6')['items'],[])
        with self.store.connection(write=True) as conn:
            conn.executemany('INSERT INTO advisory_aliases(alias,canonical_id) VALUES(?,?)',[(cve,cve),(ghsa,cve)])
            conn.execute('UPDATE article_links SET advisory_id=? WHERE advisory_id=?',(ghsa,cve))
        self.assertEqual(self.kg.intelligence(cve)['items'],result)
        self.assertEqual(self.kg.intelligence(ghsa)['items'],result)
        with self.store.connection() as conn:
            self.assertIsNone(self.kg.node(conn,cve))

    def test_exact_identifier_and_entity_pin_requested_root_before_newer_context(self):
        self.fixture()
        cve='CVE-2026-12345'
        ghsa='GHSA-AAAA-BBBB-CCCC'
        self.store.ingest({'articles':[{'url':f'https://news.test/newer/{n}','title':f'Newer report {n}',
                                       'summary':'Recent linked reporting','cves':[cve],'published':'2099-01-01T00:00:00Z'}
                                      for n in range(110)]})
        with self.store.connection(write=True) as conn:
            conn.execute("UPDATE entities SET updated_at='2000-01-01T00:00:00Z' WHERE id=?",(cve,))
            conn.execute("UPDATE alerts SET last_seen='2099-01-01T00:00:00Z'")
            conn.execute('INSERT INTO advisory_aliases(alias,canonical_id) VALUES(?,?)',(ghsa,cve))
        for query,root in ((cve,cve),(ghsa,cve),('domain:a.test','domain:a.test')):
            result=self.kg.intelligence(query,limit=1)
            self.assertGreater(result['total'],100)
            self.assertEqual(result['items'][0]['id'],root)

    def test_authoritative_rejection_suppresses_stale_reconciled_alerts(self):
        self.fixture()
        self.store.ingest({'advisories':[{'id':'CVE-2026-12345','source':'nvd','modified':'2030-01-01T00:00:00Z','rejected':True,'affected':[]}]})
        self.assertEqual(self.kg.company_risk('company:a')['items'],[])
        self.assertFalse(any(r['kind']=='alert' for r in self.kg.intelligence('CVE-2026-12345')['items']))
        self.assertFalse(any(n['kind']=='alert' for n in self.kg.graph('domain:a.test',2)['nodes']))

    def test_clause_scoped_claim_negation_and_denial(self):
        from signalwatch.text_signals import extract
        cases=[('No authentication is required; a working exploit is available.','claimed'),
               ('No authentication is required, a working exploit is available.','claimed'),
               ('No patch exists; exploitation has been observed.','claimed'),
               ('There is no evidence of active exploitation.','negated'),
               ('The vendor has not been actively exploited.','negated'),
               ('An exploit is not yet available.','negated'),
               ('Exploitation has not been observed.','negated'),
               ('Exploit code is not available.','negated'),
               ('The words actively exploited appear only in a denial.','negated')]
        with self.store.connection() as conn:
            for text,status in cases:
                with self.subTest(text=text):
                    result=extract(conn,{'url':'https://research.test/claim','summary':text})
                    self.assertEqual(next(c['status'] for c in result['claims'] if c['kind']=='exploit'),status)

    def test_extraction_reports_each_bounded_input_dimension(self):
        from signalwatch.text_signals import extract
        cases={'text':'x'*17000,
               'tokens':' '.join('word'+str(n) for n in range(129)),
               'cves':' '.join('CVE-2026-'+str(10000+n) for n in range(33)),
               'versions':' '.join('1.'+str(n) for n in range(33)),
               'claims':' '.join('Exploit claimed.' for n in range(33))}
        with self.store.connection() as conn:
            for reason,text in cases.items():
                with self.subTest(reason=reason):
                    result=extract(conn,{'url':'https://research.test/long','summary':text})
                    self.assertTrue(result['truncated'])
                    self.assertIn(reason,result['coverage']['truncation_reasons'])

    def test_incoming_adjacency_uses_early_limit_on_high_degree_nodes(self):
        self.store.ingest({'entities':[self.entity('ip:shared','ip')]})
        with self.store.connection(write=True) as conn:
            conn.executemany('INSERT INTO edges(from_id,to_id,relation) VALUES(?,?,?)',
                             ((f'source:{n:06}','ip:shared','reports_on') for n in range(10000)))
        with self.store.connection() as conn:
            steps=[0]
            def tick():
                steps[0]+=100
                return 0
            conn.set_progress_handler(tick,100)
            coverage={'truncated':False,'companies_expanded':0}
            neighbors=self.kg.neighbors(conn,{'id':'ip:shared','kind':'ip'},10,coverage)
            conn.set_progress_handler(None,0)
            self.assertEqual(len(neighbors),10)
            self.assertTrue(coverage['truncated'])
            self.assertLess(steps[0],10000)

    def test_common_term_catalog_lookup_is_bounded_before_hydration(self):
        from signalwatch.text_signals import extract
        def grow(company_start,company_end,technology_start,technology_end):
            with self.store.connection(write=True) as conn:
                conn.executemany("INSERT INTO entities(id,kind,name,value,updated_at) VALUES(?,'company',?,'','2026-01-01')",
                                 ((f'company:{n:06}',f'Company {n}') for n in range(company_start,company_end)))
                conn.executemany("INSERT INTO company_profiles(company_id,name,aliases,updated_at) VALUES(?,?,'[\"CommonProduct\"]','2026-01-01')",
                                 ((f'company:{n:06}',f'Company {n}') for n in range(company_start,company_end)))
                conn.executemany("INSERT INTO entities(id,kind,name,value,updated_at) VALUES(?,'technology','CommonProduct','','2026-01-01')",
                                 ((f'technology:{n:06}',) for n in range(technology_start,technology_end)))
        def measure():
            with self.store.connection() as conn:
                steps=[0]
                def tick():
                    steps[0]+=100
                    return 0
                conn.set_progress_handler(tick,100)
                result=extract(conn,{'url':'https://research.test/common','summary':'CommonProduct exploit claimed.'})
                conn.set_progress_handler(None,0)
                return steps[0],result
        grow(0,1000,0,9000)
        small_steps,small=measure()
        grow(1000,10000,9000,90000)
        large_steps,large=measure()
        self.assertLess(large_steps,30000)
        self.assertLess(large_steps,small_steps*2+1000)
        self.assertEqual(large,small)
        self.assertIn('catalog',large['coverage']['truncation_reasons'])
        self.assertTrue(large['mentions'])
        self.assertTrue(all(m['entity_id'].startswith('company:') and m['status']=='candidate' and m['confidence']==0.35
                            for m in large['mentions']))

    def test_backfill_refreshes_new_aliases_and_removes_replaced_feed_mentions(self):
        article={'url':'https://research.test/update','feed_url':'https://research.test/rss','title':'New Alias report','summary':'CVE-2026-12345'}
        self.store.ingest({'entities':[self.entity('company:new','company','Original company')],'articles':[article]})
        self.store.save_company_profile('company:new','Renamed company',aliases=['New Alias'])
        backfill(self.store,0,25)
        with self.store.connection() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM signal_mentions WHERE entity_id='company:new'").fetchone()[0],1)
        self.store.ingest({'articles':[dict(article,title='Correction',summary='Retracted.',cves=[])]})
        with self.store.connection() as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM signal_mentions').fetchone()[0],0)
            self.assertEqual(conn.execute("SELECT count(*) FROM edges WHERE relation IN ('text_mentions','candidate_mention')").fetchone()[0],0)

    def test_mention_caps_keep_cve_identifiers_and_catalog_uncertainty(self):
        from signalwatch.text_signals import extract
        self.store.ingest({'entities':[self.entity('company:'+str(n),'company','Brand'+str(n)) for n in range(101)]})
        with self.store.connection() as conn:
            result=extract(conn,{'url':'https://research.test/mentions','summary':' '.join('Brand'+str(n) for n in range(101))+' CVE-2026-12345'})
            self.assertEqual(len(result['mentions']),100)
            self.assertEqual(result['mentions'][0]['entity_id'],'CVE-2026-12345')
            self.assertIn('mentions',result['coverage']['truncation_reasons'])
        self.store.ingest({'entities':[self.entity('company:overflow'+str(n),'company','Ambiguous Brand') for n in range(201)]})
        with self.store.connection() as conn:
            result=extract(conn,{'url':'https://research.test/catalog','summary':'Ambiguous Brand'})
            self.assertIn('catalog',result['coverage']['truncation_reasons'])
            self.assertTrue(all(m['status']=='candidate' and m['confidence']==0.35 for m in result['mentions']))

    def test_auth_validation_not_found_and_encoded_id(self):
        from signalwatch.api import create_app
        app=create_app({'db':str(Path(self.tmp.name)/'api.db'),'api_token':'synthetic-test-token','cache_dir':self.tmp.name},auto_collect=False)
        app.state.store.ingest({'entities':[self.entity('domain:https://synthetic.test/a:b')]})
        async def check():
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as c:
                self.assertEqual((await c.get('/api/graph',params={'root_id':'x'})).status_code,401)
                h={'Authorization':'Bearer synthetic-test-token'}
                for params in ({},{'root_id':'x','depth':6},{'root_id':'x','max_edges':801}):
                    self.assertEqual((await c.get('/api/graph',params=params,headers=h)).status_code,422)
                self.assertEqual((await c.get('/api/graph',params={'root_id':'x'},headers=h)).status_code,404)
                response=await c.get('/api/graph',params={'root_id':'domain:https://synthetic.test/a:b'},headers=h)
                self.assertEqual(response.status_code,200)
                self.assertEqual(response.json()['root_id'],'domain:https://synthetic.test/a:b')
                self.assertEqual((await c.post('/api/intelligence/extract')).status_code,401)
        asyncio.run(check())

class SignalAdapterTests(unittest.TestCase):
    def test_public_export_parser_provenance_and_restricted_rejection(self):
        from signalwatch.normalization import public_signals, NormalizationError
        item={'source':'community_export','source_url':'https://public.test/export','observed_at':'2026-10-19T00:00:00Z','payload':json.dumps({'items':[{'url':'https://public.test/post/1','text':'No exploit for CVE-2026-12345','published':'2026-10-18T00:00:00Z','public':True}]}).encode(),'content_type':'application/json','metadata':{},'id':'synthetic-envelope','payload_hash':'synthetic-hash'}
        batch=public_signals(item,5)
        self.assertEqual(batch['articles'][0]['published'],'2026-10-18T00:00:00Z')
        self.assertEqual(batch['articles'][0]['source'],'community_export')
        self.assertEqual(batch['articles'][0]['cves'],['CVE-2026-12345'])
        item['payload']=json.dumps({'items':[{'url':'https://public.test/private','text':'restricted','visibility':'private'}]}).encode()
        with self.assertRaises(NormalizationError): public_signals(item,5)

    def test_public_export_corrections_replace_only_the_same_contribution(self):
        from signalwatch.normalization import public_signals
        with tempfile.TemporaryDirectory() as directory:
            store=Store(Path(directory)/'signals.db')
            envelope={'source':'public_research','source_url':'https://public.test/export','stream_key':'posts',
                      'content_type':'application/json','metadata':{},'id':'envelope','payload_hash':'hash'}
            def ingest(title,text,source='public_research'):
                item={**envelope,'source':source,'payload':json.dumps({'items':[{'url':'https://public.test/post','title':title,'text':text}]}).encode()}
                store.ingest(public_signals(item,5))
            ingest('CVE-2026-12345','Long original description of an exploit claim.')
            with store.connection() as conn:
                self.assertEqual(conn.execute('SELECT count(*) FROM article_links').fetchone()[0],1)
            ingest('Correction','Retracted.')
            with store.connection() as conn:
                self.assertEqual(conn.execute('SELECT count(*) FROM signal_mentions').fetchone()[0],0)
                self.assertEqual(conn.execute('SELECT count(*) FROM article_links').fetchone()[0],0)
            ingest('Independent report','Independent CVE-2026-67890 report.','independent_source')
            ingest('Second correction','Retracted again.')
            with store.connection() as conn:
                self.assertEqual(json.loads(conn.execute('SELECT cves FROM articles').fetchone()[0]),['CVE-2026-67890'])

class StagedSignalTests(unittest.TestCase):
    def test_real_worker_projects_public_claim_once(self):
        from signalwatch.config import load_config
        from signalwatch.ingestion import staging_queue, StagingWorker
        with tempfile.TemporaryDirectory() as directory:
            config=load_config(Path(directory)/'config.json')
            store=Store(config['db'])
            queue=staging_queue(store,config)
            worker=StagingWorker(store,config,queue)
            payload=json.dumps({'items':[{'url':'https://forum.test/post/1','title':'Pre-CVE patch claim','text':'No exploit available. Patch claimed for sample version 1.2.','public':True}]}).encode()
            first=queue.enqueue(payload,source='public_research',adapter='public_signals',content_type='application/json',stream_key='synthetic-thread',idempotency_key='synthetic-post')
            second=queue.enqueue(payload,source='public_research',adapter='public_signals',content_type='application/json',stream_key='synthetic-thread',idempotency_key='synthetic-post')
            self.assertEqual(first['id'],second['id'])
            self.assertEqual(worker.drain()['processed'],1)
            self.assertEqual(store.articles()['total'],1)
            with store.connection() as conn:
                result=json.loads(conn.execute('SELECT extraction FROM text_signals').fetchone()[0])
                self.assertEqual(next(c for c in result['claims'] if c['kind']=='exploit')['status'],'negated')
                self.assertFalse(any(m['entity_id'].startswith('CVE-') for m in result['mentions']))
            self.assertEqual(store.alerts()['total'],0)
