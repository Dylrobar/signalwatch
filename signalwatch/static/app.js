const $ = id => document.getElementById(id);
const defaultView = () => ({query:'',kind:'',eventKind:'',kev:false,offset:0,sort:'rank',versionState:''});
const eventKinds = {advisory_added:'Advisory added',advisory_changed:'Advisory changed',kev_added:'Added to KEV',kev_removed:'Removed from KEV',warning_opened:'Warning opened',warning_resolved:'Warning resolved'};
const state = {tab:'intelligence',...defaultView(),tabs:{},limit:50,total:0,items:[],status:null,request:0,selected:null,drawerHistory:[],sourceDetails:{},poll:null,statusFlight:null,dataController:null,toast:null,search:null,lastFocus:null};
const views = {
  intelligence:{eyebrow:'GLOBAL VULNERABILITY FEED',title:'Vulnerability intelligence',description:'Published advisories ranked by exploitation signals and severity.',placeholder:'Search advisories, products, CVEs…',endpoint:'advisories',export:'advisories',headers:['Severity','Advisory / affected product','Signals','Published',''],empty:'No intelligence collected yet',help:'Run the collectors to ingest public advisories and exploitation signals.'},
  warnings:{eyebrow:'INFRASTRUCTURE × INTELLIGENCE',title:'Potential exposure matches',description:'Product and version correlations with the evidence and reasoning behind each match.',placeholder:'Search assets, products, CVEs…',endpoint:'alerts',export:'alerts',headers:['Priority','Asset / advisory','Match confidence','Signals','Last seen',''],empty:'No infrastructure matches yet',help:'Collect infrastructure evidence or add a technology observation. Matches appear when collected advisories reference those products.'},
  infrastructure:{eyebrow:'CONNECTED PUBLIC EVIDENCE',title:'Infrastructure inventory',description:'Companies, domains, networks, technologies, devices, and their observed relationships.',placeholder:'Search entities, vendors, technologies…',endpoint:'search',export:'entities',headers:['Type','Entity','Evidence source','Observed',''],empty:'No infrastructure collected yet',help:'Add public URL seeds in Collectors to start building an evidence-backed inventory.'},
  news:{eyebrow:'SECURITY NEWS & RESEARCH',title:'Reports and research',description:'Collected reporting linked to its referenced CVEs and source material.',placeholder:'Search reports, sources, CVEs…',endpoint:'articles',export:'articles',headers:['Report','Source','Referenced CVEs','Published',''],empty:'No reports collected yet',help:'Run the news collectors or add public RSS and Atom feeds.'},
  changes:{eyebrow:'LOCAL OBSERVATION HISTORY',title:'Changes observed locally',description:'Changes recorded in this database. Observation times do not indicate original disclosure dates.',placeholder:'Search changes, subjects, CVEs…',endpoint:'events',export:'events',headers:['Change','Event / subject','Source','Observed locally',''],empty:'No local changes recorded',help:'Changes appear as advisories, exploitation signals, and potential warnings change in this database.'},
  collectors:{eyebrow:'COLLECTION CONTROL',title:'Sources and collection',description:'Run collectors, inspect source health, and extend the public evidence available to the system.'}
};

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function value(item, ...keys) {
  for (const key of keys) if (item && item[key] !== undefined && item[key] !== null && item[key] !== '') return item[key];
  return '';
}

function array(input) {
  if (Array.isArray(input)) return input;
  if (input === null || input === undefined || input === '') return [];
  if (typeof input === 'string') {
    try { const parsed = JSON.parse(input); if (Array.isArray(parsed)) return parsed; } catch {}
  }
  return [input];
}

function describe(input) {
  if (input === null || input === undefined) return '';
  if (typeof input !== 'object') return String(input);
  const content = value(input,'name','product','criteria','cpe','package','value','url','title');
  return content && typeof content !== 'object' ? String(content) : content?.name || JSON.stringify(input);
}

function safeURL(input) {
  try { const url = new URL(input); return ['https:','http:'].includes(url.protocol) ? url.href : null; } catch { return null; }
}

function link(url, label) {
  const href = safeURL(url);
  if (!href) return el('span','',label || describe(url));
  const anchor = el('a','',label || href);
  anchor.href = href;
  anchor.target = '_blank';
  anchor.rel = 'noopener noreferrer';
  return anchor;
}

function host(url) {
  const valid = safeURL(url);
  return valid ? new URL(valid).hostname : '—';
}

function date(input, precise = false) {
  if (!input) return '—';
  const parsed = new Date(typeof input === 'number' && input < 1e12 ? input * 1000 : input);
  if (Number.isNaN(parsed.getTime())) return String(input);
  return precise ? parsed.toLocaleString() : parsed.toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'});
}

function count(input) {
  return Number.isFinite(Number(input)) ? Number(input).toLocaleString() : '—';
}

function sbomLimit() {
  const maximum = Number(state.status?.config?.sbom_max_mb);
  return Number.isFinite(maximum) && maximum > 0 ? maximum : 20;
}

function percent(input) {
  const number = Number(input);
  return input === '' || input === null || input === undefined || !Number.isFinite(number) ? '—' : `${(number * 100).toFixed(number < .01 ? 2 : 1)}%`;
}

function badge(text, kind = '') {
  return el('span',`badge ${kind}`,text);
}

function severity(input) {
  const number = Number(input);
  if (input === '' || input === null || input === undefined) return badge('Unscored');
  if (!Number.isFinite(number)) return badge(String(input));
  const name = number >= 9 ? 'Critical' : number >= 7 ? 'High' : number >= 4 ? 'Medium' : 'Low';
  return badge(`${number.toFixed(1)} ${name}`,name.toLowerCase());
}

function signals(item) {
  const node = el('div','cell-tags');
  if (item.kev) node.append(badge('KNOWN EXPLOITED','kev'));
  if (item.epss !== null && item.epss !== undefined && item.epss !== '') node.append(badge(`EPSS ${percent(item.epss)}`));
  if (!node.children.length) node.append(el('span','cell-muted','—'));
  return node;
}

function eventBadge(kind) {
  const label = Object.hasOwn(eventKinds,kind) ? eventKinds[kind] : String(kind || 'Event').replaceAll('_',' ');
  return badge(label,['kev_added','warning_opened'].includes(kind) ? 'potential' : kind === 'warning_resolved' ? 'feed-ok' : kind === 'advisory_added' ? 'type' : '');
}

async function api(path, options = {}) {
  const response = await fetch(path,{...options,headers:{'Accept':'application/json',...(options.body ? {'Content-Type':'application/json'} : {}),...options.headers}});
  let body;
  try { body = await response.json(); } catch (error) { if (error.name === 'AbortError') throw error; throw new Error(`Service returned HTTP ${response.status} without a JSON response`); }
  if (!response.ok) {
    const error = new Error(describe(body.detail || body.error || body.message) || `HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return body;
}

function showError(error) {
  $('error-text').textContent = error instanceof Error ? error.message : String(error);
  $('error-banner').hidden = false;
}

function toast(message, error = false) {
  clearTimeout(state.toast);
  $('toast').textContent = message;
  $('toast').classList.toggle('error',error);
  $('toast').hidden = false;
  state.toast = setTimeout(() => { $('toast').hidden = true; },error ? 7000 : 4500);
}

function saveView() {
  state.tabs[state.tab] = Object.fromEntries(Object.keys(defaultView()).map(key => [key,state[key]]));
}

function writeURL(mode = 'push') {
  saveView();
  const url = new URL(window.location.href);
  for (const key of ['tab','q','kind','event_kind','kev','offset','sort','version_state']) url.searchParams.delete(key);
  url.searchParams.set('tab',state.tab);
  if (state.query) url.searchParams.set('q',state.query);
  if (state.tab === 'infrastructure' && state.kind) url.searchParams.set('kind',state.kind);
  if (state.tab === 'changes' && state.eventKind) url.searchParams.set('event_kind',state.eventKind);
  if (['intelligence','warnings'].includes(state.tab)) {
    if (state.kev) url.searchParams.set('kev','true');
    if (state.sort !== 'rank') url.searchParams.set('sort',state.sort);
  }
  if (state.tab === 'warnings' && state.versionState) url.searchParams.set('version_state',state.versionState);
  if (state.offset) url.searchParams.set('offset',String(state.offset));
  if (url.href !== window.location.href) window.history[mode === 'replace' ? 'replaceState' : 'pushState'](null,'',url);
}

function restoreURL() {
  saveView();
  const params = new URLSearchParams(window.location.search);
  const tab = Object.hasOwn(views,params.get('tab')) ? params.get('tab') : 'intelligence';
  const offset = Number(params.get('offset') || 0);
  state.tabs[tab] = {
    query:params.get('q') || '',kind:params.get('kind') || '',eventKind:tab === 'changes' && Object.hasOwn(eventKinds,params.get('event_kind')) ? params.get('event_kind') : '',kev:params.get('kev') === 'true',
    offset:Number.isSafeInteger(offset) && offset >= 0 ? Math.floor(offset / state.limit) * state.limit : 0,
    sort:params.get('sort') === 'newest' ? 'newest' : 'rank',
    versionState:['exact','affected_range','unknown','version_unverified'].includes(params.get('version_state')) ? params.get('version_state') : ''
  };
  switchTab(tab,false);
  writeURL('replace');
}

function renderKindOptions() {
  const kinds = state.status?.stats?.entity_kinds || {};
  const labels = {company:'Companies',domain:'Domains',ip:'IP addresses',asn:'Networks / ASNs',product:'Products',technology:'Technologies',device:'Devices',os:'Operating systems',url:'URLs',vendor:'Vendors',package:'Packages',vulnerability:'Vulnerability records'};
  const options = [el('option','','All entity types')];
  options[0].value = '';
  for (const kind of Object.keys(kinds).sort()) {
    const option = el('option','',`${labels[kind] || kind} (${count(kinds[kind])})`);
    option.value = kind;
    options.push(option);
  }
  if (state.kind && !Object.hasOwn(kinds,state.kind)) {
    const option = el('option','',state.kind);
    option.value = state.kind;
    options.push(option);
  }
  $('kind-filter').replaceChildren(...options);
  $('kind-filter').value = state.kind;
}

function switchTab(tab, updateURL = true) {
  if (!Object.hasOwn(views,tab)) return;
  clearTimeout(state.search);
  if (updateURL) saveView();
  state.tab = tab;
  Object.assign(state,defaultView(),state.tabs[tab] || {});
  $('search-input').value = state.query;
  $('kev-only').checked = state.kev;
  $('version-filter').value = state.versionState;
  $('sort-filter').value = state.sort;
  $('event-kind-filter').value = state.eventKind;
  renderKindOptions();
  for (const button of document.querySelectorAll('[data-tab]')) {
    const active = button.dataset.tab === tab;
    button.classList.toggle('active',active);
    if (active) button.setAttribute('aria-current','page'); else button.removeAttribute('aria-current');
    if (active) {
      const nav = button.parentElement;
      const bounds = nav.getBoundingClientRect();
      const position = button.getBoundingClientRect();
      if (position.left < bounds.left) nav.scrollLeft += position.left - bounds.left - 10;
      else if (position.right > bounds.right) nav.scrollLeft += position.right - bounds.right + 10;
    }
  }
  const view = views[tab];
  $('view-eyebrow').textContent = view.eyebrow;
  $('view-title').textContent = view.title;
  $('view-description').textContent = view.description;
  $('data-toolbar').hidden = tab === 'collectors';
  $('data-view').hidden = tab === 'collectors';
  $('collectors-view').hidden = tab !== 'collectors';
  $('kev-control').hidden = !['intelligence','warnings'].includes(tab);
  $('kind-filter').hidden = tab !== 'infrastructure';
  $('event-kind-filter').hidden = tab !== 'changes';
  $('version-filter').hidden = tab !== 'warnings';
  $('sort-filter').hidden = !['intelligence','warnings'].includes(tab);
  $('search-input').placeholder = view.placeholder || '';
  if (updateURL) writeURL();
  if (tab === 'collectors') {
    state.request++;
    state.dataController?.abort();
    $('refresh-data').disabled = false;
    document.querySelector('.workspace').setAttribute('aria-busy','false');
    renderSources();
  } else loadData();
}

function parameters() {
  const params = new URLSearchParams({limit:String(state.limit),offset:String(state.offset)});
  if (state.query) params.set('q',state.query);
  if (state.tab === 'infrastructure' && state.kind) params.set('kind',state.kind);
  if (state.tab === 'changes' && state.eventKind) params.set('kind',state.eventKind);
  if (['intelligence','warnings'].includes(state.tab)) {
    if (state.kev) params.set('kev','true');
    params.set('sort',state.sort);
  }
  if (state.tab === 'warnings' && state.versionState) params.set('version_state',state.versionState);
  return params;
}

async function loadData(quiet = false) {
  if (state.tab === 'collectors') return;
  const request = ++state.request;
  state.dataController?.abort();
  const controller = new AbortController();
  state.dataController = controller;
  const view = views[state.tab];
  const params = parameters();
  const exporting = new URLSearchParams({kind:view.export});
  if (state.query) exporting.set('q',state.query);
  if (state.tab === 'infrastructure' && state.kind) exporting.set('entity_kind',state.kind);
  if (state.tab === 'changes' && state.eventKind) exporting.set('event_kind',state.eventKind);
  if (['intelligence','warnings'].includes(state.tab)) {
    if (state.kev) exporting.set('kev','true');
    exporting.set('sort',state.sort);
  }
  if (state.tab === 'warnings' && state.versionState) exporting.set('version_state',state.versionState);
  $('export-data').href = `/api/export?${exporting}`;
  $('sort-caption').textContent = state.tab === 'infrastructure' ? 'Recently observed first' : state.tab === 'news' ? 'Newest reports first' : state.tab === 'changes' ? 'Newest local observations first' : state.sort === 'newest' ? 'Newest first' : 'Highest signal first';
  document.querySelector('.workspace').setAttribute('aria-busy','true');
  if (!quiet) {
    state.items = [];
    $('result-count').textContent = 'Loading…';
    $('table-body').replaceChildren();
    $('results-table').hidden = true;
    $('empty-state').hidden = true;
    $('pagination').hidden = true;
  }
  $('refresh-data').disabled = true;
  try {
    const data = await api(`/api/${view.endpoint}?${params}`,{signal:controller.signal});
    if (request !== state.request) return;
    state.items = array(data.items);
    state.total = Number(data.total ?? state.items.length);
    if (state.offset > 0 && state.offset >= state.total) {
      state.offset = Math.max(0,Math.floor((state.total - 1) / state.limit) * state.limit);
      writeURL('replace');
      return loadData(quiet);
    }
    renderData();
    $('last-refresh').textContent = `Updated ${new Date().toLocaleTimeString(undefined,{hour:'2-digit',minute:'2-digit'})}`;
  } catch (error) {
    if (request !== state.request || error.name === 'AbortError') return;
    showError(error);
    $('result-count').textContent = 'Unable to load records';
    if (!state.items.length) renderEmpty('Collection service unavailable',error.message);
  } finally {
    if (request === state.request) {
      $('refresh-data').disabled = false;
      document.querySelector('.workspace').setAttribute('aria-busy','false');
    }
  }
}

function cell(content, className = '') {
  const node = el('td',className);
  if (content instanceof Node) node.append(content); else node.textContent = content ?? '—';
  return node;
}

function mainCell(title, subtitle, id = '') {
  const node = el('div','record-main');
  if (id) node.append(el('div','record-id',id));
  node.append(el('div','record-title',title || 'Untitled'));
  if (subtitle) node.append(el('span','record-sub',subtitle));
  return node;
}

function advisoryTitle(item) {
  const title = item.title || '';
  if (title && title !== item.canonical_id && title !== item.id) return title;
  const summary = String(item.summary || title || item.canonical_id || item.id || '').replace(/\s+/g,' ');
  return summary.length > 175 ? `${summary.slice(0,175)}…` : summary;
}

function renderData() {
  const view = views[state.tab];
  const heading = el('tr');
  const headers = [...view.headers];
  if (state.sort === 'newest' && state.tab === 'intelligence') headers[3] = 'Modified';
  if (state.sort === 'newest' && state.tab === 'warnings') headers[4] = 'First matched';
  for (const name of headers) heading.append(el('th','',name));
  $('table-head').replaceChildren(heading);
  $('table-body').replaceChildren();
  $('results-table').hidden = !state.items.length;
  $('empty-state').hidden = Boolean(state.items.length);
  $('pagination').hidden = state.total <= state.limit;
  $('result-count').textContent = `${count(state.total)} ${state.tab === 'warnings' ? 'potential matches' : state.tab === 'infrastructure' ? 'entities' : state.tab === 'news' ? 'reports' : state.tab === 'changes' ? 'local changes' : 'advisories'}${state.query ? ' matching your search' : ''}`;
  $('page-label').textContent = `${count(state.offset + 1)}–${count(Math.min(state.offset + state.items.length,state.total))} of ${count(state.total)}`;
  $('previous-page').disabled = state.offset === 0;
  $('next-page').disabled = state.offset + state.limit >= state.total;
  if (!state.items.length) {
    renderEmpty(state.query || state.kind || state.eventKind || state.kev || state.versionState ? 'No matching records' : view.empty,state.query || state.kind || state.eventKind || state.kev || state.versionState ? 'Adjust your search or filters to see more collected records.' : view.help);
    return;
  }
  for (const item of state.items) {
    const row = el('tr','data-row');
    row.tabIndex = 0;
    row.dataset.recordId = item.id || item.canonical_id || '';
    row.setAttribute('aria-label',`View ${value(item,'title','name','value','canonical_id','id')}`);
    if (state.tab === 'intelligence') {
      const affected = array(item.affected).slice(0,4).map(describe).join(' · ');
      row.append(cell(severity(item.severity)),cell(mainCell(advisoryTitle(item),affected || item.summary,value(item,'canonical_id','id'))),cell(signals(item)),cell(date(state.sort === 'newest' ? item.modified || item.published : item.published),'cell-muted'),cell('↗','link-arrow'));
    } else if (state.tab === 'warnings') {
      const match = el('div');
      match.append(badge(`${Math.round(Number(item.confidence || 0) * 100)}% evidence confidence`,'potential'),el('span','record-sub',String(item.version_state || 'version unverified').replaceAll('_',' ')));
      const priority = el('div');
      priority.append(severity(item.severity));
      if (item.rank !== null && item.rank !== undefined) priority.append(el('span','record-sub',`Rank ${Number(item.rank).toFixed(1)}`));
      row.append(cell(priority),cell(mainCell(item.asset_name || item.product || 'Unidentified asset',item.title,item.advisory_id)),cell(match),cell(signals(item)),cell(date(state.sort === 'newest' ? item.first_seen : item.last_seen),'cell-muted'),cell('↗','link-arrow'));
    } else if (state.tab === 'infrastructure') {
      const metadata = item.metadata || {};
      const context = [metadata.vendor,metadata.product,metadata.version].filter(Boolean).join(' · ');
      row.append(cell(badge(item.kind || 'entity','type')),cell(mainCell(item.name || item.value,context || (item.name !== item.value ? item.value : ''))),cell(host(item.source_url),'cell-muted'),cell(date(item.observed_at || item.updated_at),'cell-muted'),cell('↗','link-arrow'));
    } else if (state.tab === 'changes') {
      row.append(cell(eventBadge(item.kind)),cell(mainCell(item.title,item.subject_id || item.canonical_id)),cell(item.source || host(item.url),'cell-muted'),cell(date(item.observed_at,true),'cell-muted'),cell('↗','link-arrow'));
    } else {
      row.append(cell(mainCell(item.title,item.summary)),cell(item.source || host(item.url),'cell-muted'),cell(array(item.cves).join(', ') || '—','cve-list'),cell(date(item.published),'cell-muted'),cell('↗','link-arrow'));
    }
    row.addEventListener('click',() => openDetails(item,row));
    row.addEventListener('keydown',event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openDetails(item); } });
    $('table-body').append(row);
  }
}

function renderEmpty(title, description) {
  $('results-table').hidden = true;
  $('empty-state').hidden = false;
  $('empty-title').textContent = title;
  $('empty-description').textContent = description;
  $('empty-action').hidden = Boolean(state.query || state.kind || state.eventKind || state.kev || state.versionState);
}

function sourceName(source) {
  return typeof source === 'string' ? source : value(source,'name','id','source','type') || 'Unnamed source';
}

function sourceError(source) {
  if (!source || typeof source !== 'object') return '';
  return [...new Set([value(source,'error','last_error'),...array(source.counts?.errors)].map(error => typeof error === 'object' && error ? [error.source || error.name || error.url,error.error || error.message || describe(error)].filter(Boolean).join(': ') : describe(error)).filter(Boolean))].join(' · ');
}

function sourceRecords(source) {
  const explicit = value(source,'records','count','items','last_count');
  if (explicit !== '') return Number(explicit) || 0;
  const counts = source.counts || {};
  if (counts.records !== undefined) return Number(counts.records) || 0;
  const keys = ['advisories','articles','entities','observations','kev','epss','edges','companies','domains'].filter(key => typeof counts[key] === 'number');
  return keys.length ? keys.reduce((total,key) => total + counts[key],0) : null;
}

function coverageCell(source) {
  const node = el('div','source-coverage');
  const coverage = source.coverage ?? source.counts?.coverage;
  const counts = source.counts || {};
  const scopes = new Set([source.coverage_scope,typeof coverage === 'string' ? coverage : null].filter(Boolean));
  for (const scope of scopes) node.append(el('div','coverage-scope',String(scope).replaceAll('_',' ')));
  if (coverage && typeof coverage === 'object') {
    for (const [key,content] of Object.entries(coverage)) {
      if (key.endsWith('_at') || content === null || typeof content === 'object') continue;
      const text = typeof content === 'number' ? count(content) : typeof content === 'boolean' ? content ? 'yes' : 'no' : String(content).replaceAll('_',' ');
      node.append(el('span','coverage-field',`${key.replaceAll('_',' ')}: ${text}`));
    }
  }
  for (const key of ['pending','backlog']) {
    if (coverage && typeof coverage === 'object' && Object.hasOwn(coverage,key)) continue;
    const content = source[key] ?? counts[key];
    if (typeof content === 'number' && Number.isFinite(content)) node.append(el('span',content ? 'coverage-pending' : 'coverage-field',`${count(content)} ${key}`));
    else if (typeof content === 'boolean') node.append(el('span',content ? 'coverage-pending' : 'coverage-field',content ? `${key} remaining` : `no ${key} reported`));
  }
  for (const key of ['targets','enriched','routed','feeds','feed_pages_pending']) if (typeof counts[key] === 'number') node.append(el('span','coverage-field',`${key.replaceAll('_',' ')}: ${count(counts[key])}`));
  if (counts.more === true) node.append(el('span','coverage-pending','More pages pending'));
  if (source.coverage_floor) node.append(el('span','coverage-field',`Coverage since ${date(source.coverage_floor,true)}`));
  if (source.coverage_through) node.append(el('span','coverage-field',`Coverage through ${date(source.coverage_through,true)}`));
  if (source.gap) node.append(el('span','coverage-pending',typeof source.gap === 'string' ? source.gap : 'Collection gap flagged'));
  if (source.checked_at) node.append(el('span','coverage-field',`Checked ${date(source.checked_at,true)}`));
  if (!node.children.length) node.append(el('span','cell-muted','Not reported'));
  return node;
}

function renderFeedHealth(source) {
  const raw = source.feed_health;
  const feeds = Array.isArray(raw) ? raw : raw && typeof raw === 'object' ? Object.entries(raw).map(([url,feed]) => ({url,...feed})) : [];
  const coverage = source.coverage && typeof source.coverage === 'object' ? source.coverage : source.counts || {};
  const metrics = ['configured','attempted','successful','unchanged','failed'].filter(key => typeof coverage[key] === 'number');
  if (!feeds.length && !metrics.length) return;
  const name = sourceName(source);
  const details = el('details','feed-health');
  details.open = Boolean(state.sourceDetails[name]);
  details.addEventListener('toggle',() => { state.sourceDetails[name] = details.open; });
  const summary = el('summary');
  summary.addEventListener('click',() => { state.sourceDetails[name] = !details.open; });
  const title = el('span','feed-health-title',name === 'news' ? 'News feed health' : `${name} feed health`);
  const subtitle = el('span','feed-health-caption');
  if (typeof coverage.failed === 'number' && coverage.failed > 0) subtitle.textContent = `${count(coverage.failed)} failed · inspect individual feeds`;
  else if (feeds.length) subtitle.textContent = `${count(feeds.length)} feed records · inspect results`;
  else subtitle.textContent = 'Inspect the latest feed collection';
  title.append(subtitle);
  summary.append(title,el('span','feed-health-toggle','+'));
  details.append(summary);
  const content = el('div','feed-health-content');
  if (metrics.length) {
    const grid = el('dl','feed-metrics');
    for (const key of metrics) {
      const metric = el('div',key === 'failed' && coverage[key] > 0 ? 'feed-metric failed' : 'feed-metric');
      metric.append(el('dt','',key),el('dd','',count(coverage[key])));
      grid.append(metric);
    }
    content.append(grid,el('p','feed-metrics-note','Successful includes unchanged feeds. Entry counts describe the last parsed feed response.'));
  }
  if (coverage.finished_at || coverage.started_at) content.append(el('p','feed-run-time',`${coverage.finished_at ? 'Finished' : 'Started'} ${date(coverage.finished_at || coverage.started_at,true)}`));
  if (feeds.length) {
    const table = el('table','feed-table');
    const head = el('thead');
    const heading = el('tr');
    for (const label of ['Feed','Status','Last parsed entries','Last successful fetch','Last attempt / error']) heading.append(el('th','',label));
    head.append(heading);
    const body = el('tbody');
    for (const feed of feeds) {
      const row = el('tr');
      const identity = el('div','feed-identity');
      identity.append(link(feed.url,feed.name || host(feed.url)));
      if (feed.url) identity.append(el('span','feed-url',feed.url));
      const status = feed.status === 'ok' || feed.ok === true ? badge('Fetched','feed-ok') : feed.status === 'unchanged' ? badge('Unchanged') : feed.status === 'error' || feed.ok === false ? badge('Failed','feed-failed') : el('span','cell-muted',feed.status || 'Not attempted');
      const attempt = el('div','feed-attempt');
      if (feed.last_attempt || feed.checked_at) attempt.append(el('span','cell-muted',date(feed.last_attempt || feed.checked_at,true)));
      const error = feed.error || feed.last_error;
      if (error) attempt.append(el('div','source-error',describe(error)));
      else if (!feed.last_attempt && !feed.checked_at) attempt.append(el('span','cell-muted','—'));
      const entries = feed.articles ?? feed.entries ?? feed.count;
      row.append(cell(identity),cell(status),cell(typeof entries === 'number' ? count(entries) : '—','cell-number'),cell(date(feed.last_success || (feed.ok === true ? feed.checked_at : ''),true),'cell-muted'),cell(attempt));
      body.append(row);
    }
    table.append(head,body);
    const scroll = el('div','table-scroll');
    scroll.tabIndex = 0;
    scroll.setAttribute('aria-label','Individual feed collection health');
    scroll.append(table);
    content.append(scroll);
  } else content.append(el('p','feed-metrics-note','Individual feed results have not been recorded.'));
  details.append(content);
  $('feed-health').append(details);
}

function renderSources() {
  const status = state.status || {};
  const configured = Object.entries(status.config?.sources || {}).map(([name,enabled]) => ({name,enabled}));
  const saved = array(status.sources).map(source => typeof source === 'string' ? {name:source} : source);
  const sources = [...new Map([...configured,...saved].map(source => [sourceName(source),{...configured.find(item => item.name === sourceName(source)),...source}])).values()];
  const running = array(status.current_sources).map(sourceName);
  const historical = sources.filter(source => !Object.hasOwn(status.config?.sources || {},sourceName(source))).length;
  $('source-count').textContent = `${count(configured.length)} collectors${historical ? ` · ${count(historical)} historical runs` : ''}`;
  $('collector-status').textContent = status.running ? 'Collection running' : 'Ready to collect';
  $('current-sources').textContent = running.length ? running.join(' · ') : '';
  $('sources-body').replaceChildren();
  $('feed-health').replaceChildren();
  $('sources-empty').hidden = Boolean(sources.length);
  for (const raw of sources) {
    const source = typeof raw === 'string' ? {name:raw} : raw;
    const name = sourceName(source);
    const row = el('tr','source-family-row');
    row.dataset.source = name;
    const title = el('div');
    title.append(el('div','source-name',name));
    if (source.url) title.append(el('div','source-url',source.url));
    const error = sourceError(source);
    const active = running.includes(name);
    const label = active ? el('span','source-ok','Collecting…') : error ? el('div','source-error',describe(error)) : source.status === 'interrupted' ? badge('Interrupted','potential') : source.enabled === false ? el('span','cell-muted','Disabled in schedule') : value(source,'last_success','last_ok') ? el('span','source-ok','Healthy') : el('span','cell-muted','Not collected yet');
    const run = el('button','button quiet',active ? 'Running' : 'Run ↗');
    run.type = 'button';
    run.setAttribute('aria-label',`Run ${name} collector`);
    run.disabled = Boolean(status.running) || !Object.hasOwn(status.config?.sources || {},name);
    if (!Object.hasOwn(status.config?.sources || {},name)) run.title = 'Historical collection run';
    run.addEventListener('click',() => collect([name],run));
    const records = sourceRecords(source);
    const recordsCell = cell(records === null ? '—' : count(records),'cell-number');
    if (source.counts) recordsCell.title = Object.entries(source.counts).filter(([,total]) => typeof total === 'number').map(([kind,total]) => `${kind}: ${count(total)}`).join(' · ');
    row.append(cell(title),cell(date(value(source,'last_success','last_ok','last_run'),true),'cell-muted'),recordsCell,cell(coverageCell(source)),cell(label),cell(run));
    $('sources-body').append(row);
    if (name === 'news') renderFeedHealth(source);
  }
}

function refreshStatus() {
  clearTimeout(state.poll);
  if (document.hidden) return Promise.resolve();
  if (state.statusFlight) return state.statusFlight;
  state.statusFlight = updateStatus().finally(() => {
    state.statusFlight = null;
    if (!document.hidden) state.poll = setTimeout(refreshStatus,state.status?.running ? 10000 : 60000);
  });
  return state.statusFlight;
}

async function updateStatus() {
  try {
    const status = await api('/api/status');
    const previous = state.status;
    state.status = status;
    $('sbom-limit').textContent = `JSON document · request limit ${count(sbomLimit())} MiB`;
    const stats = status.stats || {};
    for (const key of ['entities','advisories','alerts','articles']) $(`count-${key}`).textContent = count(stats[key] ?? 0);
    $('warning-badge').hidden = !stats.alerts;
    $('warning-badge').textContent = count(stats.alerts);
    const errors = array(status.sources).filter(sourceError).length;
    $('source-error-badge').hidden = !errors;
    $('source-error-badge').textContent = String(errors);
    $('run-state').className = `run-state ${status.running ? 'running' : 'ready'}`;
    $('run-state').replaceChildren(el('i'),document.createTextNode(status.running ? 'Collecting' : 'Service online'));
    $('collect-now').disabled = Boolean(status.running);
    $('collect-now').replaceChildren(document.createTextNode(status.running ? 'Collecting…' : 'Collect now'),el('span','','↗'));
    $('footer-status').textContent = `${count(stats.observations ?? 0)} observations · ${count(stats.edges ?? 0)} connections`;
    const error = value(status,'error','job_error','last_error');
    if (error) showError(describe(error));
    renderKindOptions();
    renderSources();
    if (previous && !document.hidden && state.tab !== 'collectors' && (previous.running || status.running || JSON.stringify(previous.stats) !== JSON.stringify(stats))) await loadData(true);
  } catch (error) {
    $('run-state').className = 'run-state error';
    $('run-state').replaceChildren(el('i'),document.createTextNode('Service unavailable'));
    $('footer-status').textContent = 'Connection interrupted';
    showError(error);
  }
}

async function collect(sources = [], button = $('collect-now')) {
  button.disabled = true;
  try {
    const result = await api('/api/collect',{method:'POST',body:JSON.stringify(sources.length ? {sources} : {})});
    if (result.error) throw new Error(describe(result.error));
    toast(result.running && !result.queued ? 'Collection is running.' : 'Collection queued.');
    await refreshStatus();
  } catch (error) { showError(error); button.disabled = false; }
}

function section(container, title) {
  const node = el('section','detail-section');
  node.append(el('h3','',title));
  container.append(node);
  return node;
}

function fields(container, title, entries) {
  const present = entries.filter(([,content]) => content !== null && content !== undefined && content !== '');
  if (!present.length) return;
  const node = section(container,title);
  const grid = el('dl','detail-grid');
  for (const [label,content] of present) {
    const dd = el('dd');
    if (content instanceof Node) dd.append(content); else dd.textContent = String(content);
    grid.append(el('dt','',label),dd);
  }
  node.append(grid);
}

function listSection(container, title, items, render) {
  if (!items.length) return;
  const list = el('ul','detail-list');
  for (const item of items) {
    const li = el('li');
    const result = render(item);
    if (result instanceof Node) li.append(result); else li.textContent = String(result);
    list.append(li);
  }
  section(container,title).append(list);
}

function detailType(detail, fallback = 'infrastructure') {
  const kind = detail.entity?.kind || detail.kind;
  if (detail.advisory || detail.canonical_id || kind === 'vulnerability') return 'intelligence';
  if (detail.article || kind === 'article') return 'news';
  return kind ? 'infrastructure' : fallback;
}

function recordControl(label, id, originalURL = '') {
  if (!id) return link(originalURL,label);
  const button = el('button','detail-link',label);
  button.type = 'button';
  button.addEventListener('click',() => navigateRecord(id,originalURL));
  return button;
}

function originalSource(url) {
  return link(url,'Open original source ↗');
}

function updateDrawerBack() {
  $('drawer-back').hidden = !state.drawerHistory.length;
}

async function navigateRecord(id, originalURL = '') {
  const previous = state.selected;
  if (!previous) return;
  const pending = el('p','drawer-request','Loading connected record…');
  $('drawer-content').append(pending);
  const token = {};
  previous.pending = token;
  try {
    const detail = await api(`/api/entity?${new URLSearchParams({id})}`);
    if (state.selected !== previous || previous.pending !== token) return;
    previous.scrollTop = $('detail-drawer').scrollTop;
    state.drawerHistory.push(previous);
    const type = detailType(detail);
    const item = type === 'intelligence' ? detail.advisory || detail.entity || detail : type === 'news' ? detail.article || detail.entity || detail : detail.entity || detail;
    state.selected = {item,tab:type,detail};
    renderDetails(item,detail);
    $('detail-drawer').scrollTop = 0;
    $('drawer-back').focus();
  } catch (error) {
    if (state.selected !== previous || previous.pending !== token) return;
    if (error.status === 404 && safeURL(originalURL)) {
      previous.scrollTop = $('detail-drawer').scrollTop;
      state.drawerHistory.push(previous);
      state.selected = {item:{id,title:id},tab:'unavailable',originalURL};
      renderUnavailable(id,originalURL);
      $('drawer-back').focus();
    } else { pending.textContent = `Connected record unavailable: ${error.message}`; }
  }
}

function renderUnavailable(id, originalURL) {
  $('drawer-kind').textContent = 'ORIGINAL SOURCE';
  $('drawer-content').replaceChildren(el('h2','',id),el('p','','This record is not available in the local collection.'),originalSource(originalURL));
  updateDrawerBack();
}

function drawerBack() {
  const previous = state.drawerHistory.pop();
  if (!previous) return;
  state.selected = previous;
  if (previous.tab === 'unavailable') renderUnavailable(previous.item.id,previous.originalURL); else renderDetails(previous.item,previous.detail);
  $('detail-drawer').scrollTop = previous.scrollTop || 0;
  ($('drawer-back').hidden ? $('close-drawer') : $('drawer-back')).focus();
}

function renderEventDetails(item, detail) {
  const event = {...item,...(detail?.event || detail || {})};
  const container = $('drawer-content');
  $('drawer-kind').textContent = 'LOCAL CHANGE';
  updateDrawerBack();
  container.append(el('div','record-id',event.id),el('h2','',event.title || (Object.hasOwn(eventKinds,event.kind) ? eventKinds[event.kind] : 'Local change')));
  const tags = el('div','detail-tags');
  tags.append(eventBadge(event.kind));
  container.append(tags,el('p','detail-notice','Recorded when this database observed the change. This time does not identify the original disclosure date.'));
  fields(container,'Local observation',[
    ['Observed locally',date(event.observed_at,true)],['Subject',event.subject_id],['Canonical ID',event.canonical_id],['Source',event.source]
  ]);
  if (event.subject_id || event.canonical_id) {
    const connected = section(container,'Connected records');
    if (event.subject_id) connected.append(recordControl(`Open subject · ${event.subject_id}`,event.subject_id,event.url));
    if (event.canonical_id && event.canonical_id !== event.subject_id) connected.append(el('br'),recordControl(`Open advisory · ${event.canonical_id}`,event.canonical_id,event.url));
  }
  if (event.before !== undefined || event.after !== undefined) {
    const previous = event.before && typeof event.before === 'object' && !Array.isArray(event.before) ? event.before : event.before === undefined || event.before === null ? {} : {value:event.before};
    const current = event.after && typeof event.after === 'object' && !Array.isArray(event.after) ? event.after : event.after === undefined || event.after === null ? {} : {value:event.after};
    const changed = [...new Set([...Object.keys(previous),...Object.keys(current)])].filter(key => key !== 'changed_fields' && JSON.stringify(previous[key]) !== JSON.stringify(current[key]));
    const snapshot = section(container,'Changed fields');
    if (changed.length) {
      const table = el('table','event-diff');
      const head = el('thead');
      const heading = el('tr');
      for (const label of ['Field','Before','After']) heading.append(el('th','',label));
      head.append(heading);
      const body = el('tbody');
      for (const key of changed) {
        const row = el('tr');
        row.append(cell(key,'event-field'));
        for (const values of [previous,current]) row.append(cell(el('pre','event-value',Object.hasOwn(values,key) ? JSON.stringify(values[key],null,2) : 'Not present')));
        body.append(row);
      }
      table.append(head,body);
      const scroll = el('div','table-scroll');
      scroll.tabIndex = 0;
      scroll.setAttribute('aria-label','Before and after changed fields');
      scroll.append(table);
      snapshot.append(scroll);
    } else snapshot.append(el('p','','No changed field snapshots were recorded with this event.'));
  }
  if (event.url) section(container,'Source evidence').append(link(event.url,event.url));
}

function renderDetails(item, detail = null) {
  const container = $('drawer-content');
  container.replaceChildren();
  const type = state.selected?.tab || state.tab;
  if (type === 'changes') { renderEventDetails(item,detail); return; }
  const entity = {...item,...(detail?.entity || detail || {}),...(type === 'intelligence' ? detail?.advisory : type === 'news' ? detail?.article : {})};
  updateDrawerBack();
  $('drawer-kind').textContent = type === 'warnings' ? 'POTENTIAL EXPOSURE MATCH' : type === 'infrastructure' ? `${String(entity.kind || 'entity').toUpperCase()} / PUBLIC EVIDENCE` : type === 'news' ? 'NEWS & RESEARCH' : 'VULNERABILITY INTELLIGENCE';
  if (type !== 'infrastructure') container.append(el('div','record-id',value(entity,'canonical_id','advisory_id','id')));
  container.append(el('h2','',value(entity,'title','name','value') || 'Record details'));
  const tags = el('div','detail-tags');
  if (type === 'warnings' || type === 'intelligence') tags.append(severity(entity.severity));
  if (entity.kev) tags.append(badge('KNOWN EXPLOITED','kev'));
  if (entity.epss !== null && entity.epss !== undefined) tags.append(badge(`EPSS ${percent(entity.epss)}`));
  if (type === 'warnings') tags.append(badge('POTENTIAL MATCH','potential'));
  if (entity.kind) tags.append(badge(entity.kind,'type'));
  if (tags.children.length) container.append(tags);
  if (entity.summary) container.append(el('p','',entity.summary));
  if (type === 'warnings') {
    container.append(el('p','detail-notice','This is a product correlation. The matching evidence and version information below determine whether the advisory applies to this asset.'));
    fields(container,'Match details',[
      ['Asset',entity.asset_name],['Product',[entity.vendor,entity.product,entity.version].filter(Boolean).join(' ')],['Advisory',entity.advisory_id],['Confidence',`${Math.round(Number(entity.confidence || 0) * 100)}%`],['Version state',String(entity.version_state || 'version unverified').replaceAll('_',' ')],['Priority rank',entity.rank],['EPSS date',entity.epss_date ? date(entity.epss_date) : ''],['KEV added',entity.kev_date ? date(entity.kev_date) : ''],['First seen',date(entity.first_seen,true)],['Last seen',date(entity.last_seen,true)]
    ]);
    listSection(container,'Why this matched',array(entity.reasons),describe);
    if (entity.advisory_id) section(container,'Connected advisory').append(recordControl(entity.advisory_id,entity.advisory_id,entity.url));
    if (entity.evidence) listSection(container,'Observation evidence',array(entity.evidence),evidence => link(typeof evidence === 'object' ? value(evidence,'url','source_url') : evidence,describe(evidence)));
    if (entity.asset_id) {
      const button = el('button','button','View asset evidence ↗');
      button.type = 'button';
      button.addEventListener('click',() => navigateRecord(entity.asset_id,entity.source_url));
      section(container,'Connected asset').append(button);
    }
  } else if (type === 'infrastructure') {
    fields(container,'Entity details',[
      ['Type',entity.kind],['Value',entity.value],['Observed',date(entity.observed_at,true)],['Updated',date(entity.updated_at,true)],['Confidence',entity.confidence !== undefined ? `${Math.round(Number(entity.confidence) * 100)}%` : '']
    ]);
    if (entity.metadata && Object.keys(entity.metadata).length) fields(container,'Attributes',Object.entries(entity.metadata).map(([name,content]) => [name,typeof content === 'object' ? JSON.stringify(content) : content]));
    listSection(container,'Relationships',array(detail?.relationships),edge => {
      const node = el('div');
      const relationship = el('div','detail-relationship');
      relationship.append(recordControl(edge.from_name || edge.from_id || edge.source || '',edge.from_id,edge.source_url),el('span','detail-relation',`→ ${String(edge.relation || edge.kind || edge.type || '').replaceAll('_',' ')} →`),recordControl(edge.to_name || edge.to_id || edge.target || '',edge.to_id,edge.source_url));
      node.append(relationship);
      if (edge.source_url) node.append(el('br'),link(edge.source_url,host(edge.source_url)));
      return node;
    });
    listSection(container,'Observations',array(detail?.observations),observation => {
      const node = el('div');
      node.append(el('div','',[observation.vendor,observation.product,observation.version].filter(Boolean).join(' ') || observation.evidence || describe(observation)));
      if (observation.evidence) node.append(el('small','',describe(observation.evidence)));
      if (observation.source_url) node.append(link(observation.source_url,host(observation.source_url)));
      return node;
    });
    listSection(container,'Related advisories',array(detail?.advisories),advisory => {
      const node = el('div');
      node.append(recordControl(`${advisory.canonical_id || advisory.advisory_id || advisory.id || ''} · ${advisory.title || ''}`,advisory.id || advisory.canonical_id || advisory.advisory_id,advisory.url));
      if (advisory.url) node.append(el('br'),originalSource(advisory.url));
      if (advisory.version_state) node.append(el('small','',String(advisory.version_state).replaceAll('_',' ')));
      return node;
    });
    listSection(container,'Related news signals',array(detail?.related_articles),entry => {
      const article = entry.article || entry;
      const node = el('div');
      node.append(recordControl(article.title || article.url,article.id,article.url));
      if (article.url) node.append(el('br'),originalSource(article.url));
      node.append(el('small','',`${article.source || host(article.url)} · ${date(article.published)} · ${String(entry.match_type || 'product mention').replaceAll('_',' ')}`));
      if (entry.reason || entry.reasons) node.append(el('small','',entry.reason || array(entry.reasons).map(describe).join(' · ')));
      if (entry.match_phrases?.length) node.append(el('small','',`Matched: ${entry.match_phrases.join(' · ')}`));
      return node;
    });
    if (detail && !array(detail.relationships).length && !array(detail.observations).length) container.append(el('p','', 'No additional relationships or technology observations have been collected for this entity.'));
  } else {
    fields(container,'Publication',[
      ['Source',entity.source],['Published',date(entity.published,true)],['Modified',date(entity.modified,true)],['Aliases',array(entity.aliases).join(', ')],['EPSS percentile',entity.percentile !== null && entity.percentile !== undefined ? percent(entity.percentile) : ''],['EPSS date',entity.epss_date ? date(entity.epss_date) : ''],['KEV added',entity.kev_date ? date(entity.kev_date) : '']
    ]);
    listSection(container,'Affected products & versions',array(entity.affected),affected => {
      if (typeof affected !== 'object') return describe(affected);
      const node = el('div');
      node.append(el('div','',[affected.vendor,affected.product || affected.name || affected.package?.name || affected.cpe].filter(Boolean).join(' / ') || describe(affected)));
      const constraints = [affected.version && !['*','-'].includes(affected.version) ? `Version ${affected.version}` : '',...[
        ['versionStartIncluding','≥'],['versionStartExcluding','>'],['versionEndIncluding','≤'],['versionEndExcluding','<']
      ].filter(([key]) => affected[key]).map(([key,operator]) => `${operator} ${affected[key]}`)].filter(Boolean);
      if (constraints.length) node.append(el('small','',constraints.join(' · ')));
      const vulnerable = affected.version_range || affected.vulnerable_version_range;
      if (vulnerable) node.append(el('small','',`Vulnerable versions: ${vulnerable}`));
      if (affected.first_patched_version) node.append(el('small','',`First patched version: ${value(affected.first_patched_version,'identifier','version') || describe(affected.first_patched_version)}`));
      if (affected.version_unverified) node.append(badge('Version constraints unverified','potential'));
      if (affected.cve_default_status) node.append(el('small','',`Default status: ${affected.cve_default_status}`));
      if (array(affected.cve_versions).length) node.append(el('small','','CVE native version rules'),el('pre','',JSON.stringify(affected.cve_versions,null,2)));
      if (array(affected.versions).length) node.append(el('pre','',JSON.stringify(affected.versions,null,2)));
      if (array(affected.ranges).length) node.append(el('pre','',JSON.stringify(affected.ranges,null,2)));
      return node;
    });
    listSection(container,'Affected product labels · identity unverified',array(entity.configurations?.unverified_products).filter(product => product && typeof product === 'object'),product => {
      const node = el('div');
      node.append(el('div','',product.name || [product.vendor,product.product].filter(Boolean).join(' / ') || product.product_id || describe(product)));
      node.append(el('small','',[product.product_id ? `Product ID: ${product.product_id}` : '',product.identity_status || 'identity unverified'].filter(Boolean).join(' · ')));
      if (product.defaultStatus) node.append(el('small','',`Default status: ${product.defaultStatus}`));
      if (array(product.versions).length) node.append(el('small','','CVE native version rules'),el('pre','',JSON.stringify(product.versions,null,2)));
      return node;
    });
    listSection(container,'Publisher remediations',array(entity.configurations?.remediations).filter(remediation => remediation && typeof remediation === 'object'),remediation => {
      const node = el('div');
      const title = remediation.title || String(remediation.category || 'Remediation').replaceAll('_',' ');
      node.append(el('div','',title));
      if (remediation.details) node.append(el('div','remediation-details',remediation.details));
      if (remediation.url) node.append(link(remediation.url,remediation.url));
      return node;
    });
    listSection(container,'Referenced CVEs',array(entity.cves),cve => recordControl(describe(cve),describe(cve),`https://www.cve.org/CVERecord?id=${encodeURIComponent(describe(cve))}`));
    listSection(container,'Related reporting',array(detail?.articles),article => {
      const node = el('div');
      node.append(recordControl(article.title || article.url,article.id,article.url),el('small','',`${article.source || host(article.url)} · ${date(article.published)}`));
      if (article.url) node.append(originalSource(article.url));
      return node;
    });
  }
  const references = [...array(entity.references),...array(entity.url),...array(entity.source_url)];
  const unique = new Set();
  listSection(container,'Sources & references',references.filter(reference => {
    const url = typeof reference === 'object' ? value(reference,'url','source_url') : reference;
    if (!safeURL(url) || unique.has(url)) return false;
    unique.add(url);
    return true;
  }),reference => {
    const url = typeof reference === 'object' ? value(reference,'url','source_url') : reference;
    return link(url,url);
  });
}

async function openDetails(item, origin = document.activeElement) {
  state.lastFocus = origin;
  state.lastFocusId = String(item.id || item.canonical_id || '');
  state.drawerHistory = [];
  const selection = {item,tab:state.tab};
  state.selected = selection;
  $('detail-drawer').hidden = false;
  $('drawer-overlay').hidden = false;
  document.body.classList.add('drawer-open');
  $('detail-drawer').scrollTop = 0;
  $('close-drawer').focus();
  renderDetails(item);
  if (selection.tab !== 'warnings' && item.id) {
    const loading = el('p','drawer-loading',selection.tab === 'changes' ? 'Loading change snapshot…' : 'Loading connected evidence…');
    $('drawer-content').append(loading);
    try {
      const detail = await api(`/api/${selection.tab === 'changes' ? 'event' : 'entity'}?${new URLSearchParams({id:item.id})}`);
      if (state.selected === selection) {
        selection.detail = detail;
        if (selection.tab !== 'changes') selection.tab = detailType(detail,selection.tab);
        renderDetails(item,detail);
      }
    } catch (error) { if (state.selected === selection) { loading.textContent = `Connected evidence unavailable: ${error.message}`; } }
  }
}

function closeDetails() {
  $('detail-drawer').hidden = true;
  $('drawer-overlay').hidden = true;
  document.body.classList.remove('drawer-open');
  state.selected = null;
  state.drawerHistory = [];
  const target = state.lastFocus?.isConnected ? state.lastFocus : [...document.querySelectorAll('.data-row')].find(row => row.dataset.recordId === state.lastFocusId) || $('search-input');
  target?.focus();
}

function renderSBOMReport(response, filename) {
  const container = $('sbom-report');
  const report = response.report || {};
  container.replaceChildren(el('h3','','Inventory import result'),el('p','sbom-filename',filename));
  fields(container,'Document',[['Format',report.format],['Specification version',report.spec_version]]);
  const keys = ['total','imported','skipped','duplicates','observations'].filter(key => typeof report[key] === 'number');
  if (keys.length) {
    const metrics = el('dl','sbom-metrics');
    for (const key of keys) {
      const metric = el('div','');
      metric.append(el('dt','',key),el('dd','',count(report[key])));
      metrics.append(metric);
    }
    container.append(metrics);
  }
  if (report.skip_reasons && typeof report.skip_reasons === 'object') fields(container,'Skipped entry reasons',Object.entries(report.skip_reasons).map(([reason,total]) => [reason,typeof total === 'number' ? count(total) : describe(total)]));
  if (array(report.warnings).length) section(container,'Import warnings').append(el('pre','',array(report.warnings).map(warning => typeof warning === 'string' ? warning : JSON.stringify(warning,null,2)).join('\n')));
  if (response.matching !== undefined) section(container,'Global correlation result').append(el('pre','',JSON.stringify(response.matching,null,2)));
  container.hidden = false;
}

function wireForm(id, endpoint, body) {
  const form = $(id);
  form.addEventListener('submit',async event => {
    event.preventDefault();
    const result = form.querySelector('.form-result');
    const button = form.querySelector('button[type="submit"]');
    result.textContent = '';
    result.classList.remove('error');
    button.disabled = true;
    try {
      const payload = body(new FormData(form));
      const response = await api(endpoint,{method:'POST',body:JSON.stringify(payload)});
      result.textContent = response.message || (id === 'seed-form' ? `${response.count ?? payload.urls.length} seeds added.` : id === 'feed-form' ? 'Feed added.' : 'Observation added.');
      form.reset();
      await refreshStatus();
    } catch (error) { result.textContent = error.message; result.classList.add('error'); }
    finally { button.disabled = false; }
  });
}

for (const button of document.querySelectorAll('[data-tab]')) button.addEventListener('click',() => switchTab(button.dataset.tab));
for (const button of document.querySelectorAll('[data-go]')) button.addEventListener('click',() => switchTab(button.dataset.go));
$('search-input').addEventListener('input',event => {
  clearTimeout(state.search);
  state.search = setTimeout(() => { state.query = event.target.value.trim(); state.offset = 0; writeURL(); loadData(); },250);
});
$('kev-only').addEventListener('change',event => { state.kev = event.target.checked; state.offset = 0; writeURL(); loadData(); });
$('kind-filter').addEventListener('change',event => { state.kind = event.target.value; state.offset = 0; writeURL(); loadData(); });
$('event-kind-filter').addEventListener('change',event => { state.eventKind = event.target.value; state.offset = 0; writeURL(); loadData(); });
$('version-filter').addEventListener('change',event => { state.versionState = event.target.value; state.offset = 0; writeURL(); loadData(); });
$('sort-filter').addEventListener('change',event => { state.sort = event.target.value; state.offset = 0; writeURL(); loadData(); });
$('refresh-data').addEventListener('click',() => loadData());
$('collect-now').addEventListener('click',() => collect());
$('previous-page').addEventListener('click',() => { state.offset = Math.max(0,state.offset - state.limit); writeURL(); loadData(); });
$('next-page').addEventListener('click',() => { state.offset += state.limit; writeURL(); loadData(); });
$('empty-action').addEventListener('click',() => switchTab('collectors'));
$('dismiss-error').addEventListener('click',() => { $('error-banner').hidden = true; });
$('close-drawer').addEventListener('click',closeDetails);
$('drawer-back').addEventListener('click',drawerBack);
$('drawer-overlay').addEventListener('click',closeDetails);
document.addEventListener('keydown',event => {
  if (event.key === 'Escape' && state.selected) closeDetails();
  if (event.key === '/' && !state.selected && state.tab !== 'collectors' && !['INPUT','TEXTAREA','SELECT'].includes(document.activeElement.tagName)) { event.preventDefault(); $('search-input').focus(); }
  if (event.key === 'Tab' && state.selected) {
    const focusable = [...$('detail-drawer').querySelectorAll('a[href],button:not([disabled]),[tabindex="0"]')].filter(node => !node.hidden && node.getClientRects().length);
    const first = focusable[0];
    const last = focusable.at(-1);
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
  }
});
document.addEventListener('visibilitychange',() => { clearTimeout(state.poll); if (!document.hidden) refreshStatus(); });
window.addEventListener('popstate',() => { if (state.selected) closeDetails(); restoreURL(); });
wireForm('seed-form','/api/seeds',form => {
  const urls = [...new Set(String(form.get('urls') || '').split(/\s+/).filter(Boolean))];
  if (!urls.length || urls.some(url => !safeURL(url))) throw new Error('Enter valid HTTP or HTTPS URLs, one per line.');
  return {urls};
});
wireForm('feed-form','/api/sources/feed',form => {
  const url = String(form.get('url') || '').trim();
  if (!safeURL(url)) throw new Error('Enter a valid HTTP or HTTPS feed URL.');
  return {name:String(form.get('name') || '').trim(),url};
});
wireForm('observation-form','/api/observations',form => {
  const data = Object.fromEntries(form);
  if (!safeURL(data.asset_url)) throw new Error('Enter a valid HTTP or HTTPS asset URL.');
  return data;
});
$('sbom-form').addEventListener('submit',async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = form.querySelector('button[type="submit"]');
  const result = form.querySelector('.form-result');
  button.disabled = true;
  result.classList.remove('error');
  result.textContent = 'Reading JSON…';
  $('sbom-report').replaceChildren();
  $('sbom-report').hidden = true;
  try {
    const asset_url = $('sbom-asset-url').value.trim();
    const source_key = $('sbom-source-key').value.trim();
    const file = $('sbom-file').files[0];
    if (!safeURL(asset_url)) throw new Error('Enter a valid HTTP or HTTPS asset URL.');
    if (!source_key) throw new Error('Enter a source key.');
    if (!file) throw new Error('Select a JSON SBOM file.');
    const maximum = sbomLimit();
    if (file.size > maximum * 1024 * 1024) throw new Error(`SBOM JSON exceeds the ${count(maximum)} MiB limit.`);
    let document;
    try { document = JSON.parse(await file.text()); } catch (error) { throw new Error(`Invalid JSON: ${error.message}`); }
    result.textContent = 'Importing inventory…';
    const body = JSON.stringify({asset_url,source_key,document});
    if (new Blob([body]).size > maximum * 1024 * 1024) throw new Error(`SBOM request exceeds the ${count(maximum)} MiB limit, including asset and source information.`);
    const response = await api('/api/import/sbom',{method:'POST',body});
    renderSBOMReport(response,file.name);
    result.textContent = response.saved === false ? 'Inventory was not saved.' : 'Inventory imported.';
    result.classList.toggle('error',response.saved === false);
    await refreshStatus();
  } catch (error) { result.textContent = error.message; result.classList.add('error'); }
  finally { button.disabled = false; }
});
refreshStatus();
restoreURL();
