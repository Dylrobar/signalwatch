# SignalWatch

Self-hosted public infrastructure and vulnerability intelligence application for Linux/WSL. The Python 3.11+ backend uses one process, SQLite WAL, and asynchronous HTTP. This repository includes the Python service, its bundled local interface, and the tested React dashboard in `frontend/`. No external database, message broker, LLM, or paid search subscription is required. The Python service runs without Node; building the separate React frontend requires Bun or Node.

## Run

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install .
signalwatch init
signalwatch serve
```

Open http://127.0.0.1:8765. Collection starts when enabled sources are due and follows independent persisted schedules. Configuration and data belong to the directory containing `config.json`. Stop with Ctrl+C; restart with the same configuration to resume checkpoints.

```bash
docker compose up --build -d
```

Docker binds the same local port and persists configuration, database, and caches under the mounted `data` directory.

## Repository layout

| Path | Contents |
| --- | --- |
| `signalwatch/` | Python API, collectors, matching, SQLite storage, and bundled local interface |
| `tests/` | Python parser, matching, collector, and HTTP API tests |
| `frontend/` | React/TanStack dashboard, package configuration, lockfile, and frontend tests |
| `config.example.json` | Backend configuration defaults |
| `Dockerfile` / `compose.yaml` | Local Python service container |

The frontend includes the tested fixes directly. This standalone repository is not currently connected to Lovable Git sync; creating or pushing this repository does not configure that connection. The upstream `frontend/AGENTS.md` is retained, including its history-preservation instructions for a future connected project.

## React frontend

From another terminal:

```bash
cd frontend
bun install --frozen-lockfile
bun run dev --host 127.0.0.1 --port 5174
```

Open http://127.0.0.1:5174. The dashboard starts disconnected and shows no invented records. In **Connection settings**, enter the actual backend base URL without `/api`, its optional shared token, and choose **Save & connect**. URL path prefixes are preserved. The URL is remembered locally; the token stays in memory unless you choose tab-session storage.

The dashboard connects directly to the separately running Python service. Collectors, matching, and persistence stay in Python. See `frontend/README.md` for frontend validation and the generated template's local preview limitation.

## Remote Python connection

The Python backend has not been deployed by this repository. A hosted frontend needs an HTTPS backend URL reachable from its browser. `localhost` refers to the computer running that browser.

On the chosen backend host, initialize the application using the Run commands above. Start it behind an HTTPS reverse proxy:

```bash
export SIGNALWATCH_CORS_ORIGINS='http://127.0.0.1:5174'
read -rsp 'API token (use the same value in the frontend): ' SIGNALWATCH_API_TOKEN
printf '\n'
export SIGNALWATCH_API_TOKEN
signalwatch --config config.json serve --host 127.0.0.1 --port 8765
```

Replace the CORS value with the actual frontend origin when hosting the frontend. Multiple origins use a comma-separated list; omit paths and wildcards. The local development origin above allows the dashboard running on port 5174 to connect to this service.

Choose a nonempty token for a protected connection. The token is optional for local use; when set, every `/api/**` request requires `Authorization: Bearer <token>`. `GET /health` stays public and reports whether authentication is required. Configuration changes require a server restart. For Docker, export the same variables before `docker compose up --build -d`; Compose passes them into the container and keeps port 8765 bound to the host's loopback interface.

Point the HTTPS reverse proxy at `http://127.0.0.1:8765`, preserving request paths, query strings, and the Authorization header. For example, inside an existing Nginx HTTPS server block:

```nginx
location / {
    proxy_pass http://127.0.0.1:8765;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header Authorization $http_authorization;
    client_max_body_size 21m;
}
```

The proxy body limit must accommodate the configured SBOM request limit. Let `OPTIONS` preflight requests reach SignalWatch. CORS is configured by SignalWatch; avoid adding a second set of CORS headers at the proxy. Equivalent JSON settings are `cors_origins` and `api_token` in `config.example.json`; the environment variables override them.

Check the running backend locally from another terminal, supplying the same token:

```bash
curl --fail http://127.0.0.1:8765/health
read -rsp 'API token: ' SIGNALWATCH_API_TOKEN
printf '\n'
curl --fail -H "Authorization: Bearer $SIGNALWATCH_API_TOKEN" http://127.0.0.1:8765/api/status
```

The bundled interface at `/` has no token entry; use `frontend/` for a protected connection. With no token and no CORS origins configured, the default local interface continues to work. This shared token grants access to the whole API; it is not a per-user account system.

## Collection

| Source | Collected data | Update behavior |
| --- | --- | --- |
| NVD | CVEs, CVSS, affected CPEs, version bounds, original applicability configurations, vendor advisory references | Initial recent/modified feeds; META checks thereafter; API catch-up after an extended outage |
| CISA KEV | Known exploitation, required actions, dates, ransomware fields | Complete validated snapshots; removed entries lose KEV status |
| FIRST EPSS | CVE exploitation scores, percentiles, score date | Daily bulk gzip; unchanged payloads skip ingestion |
| GitHub Advisory Database | Package advisories, CVE aliases, vulnerable ranges, patch versions | Incremental cursor pagination, bounded requests per run |
| OSV | Package ecosystems, PURLs, ranges, aliases, withdrawals | Bounded ranged reads of change index; persisted resumable backlog |
| CVE Program | Published CNA records, early CVE descriptions, affected products, CVSS, rejections | Bounded recent release deltas and current change manifest; explicit coverage floor and collection gaps |
| Vendor CSAF | Structured CISA OT/IT/vendor advisories and Siemens ProductCERT records, product status and remediation | Four ROLIE feeds; bounded document backlog and revision tracking |
| RIPEstat | Public IP routing prefixes and announcing ASNs | Enriches observed public IPs in small batches, refreshed daily |
| Wikidata | Companies and their published official websites | Small batches with per-class continuation |
| Security/vendor RSS | Article titles, summaries, publication dates, CVE mentions | Conditional fetches and URL deduplication |
| Public websites/DNS | Visible technology fingerprints, version evidence, domain/IP relationships | Bounded regular HTTP crawling, robots rules, scheduled refresh |
| Exposure | CT certificates, passive DNS, TXT/SPF/DMARC/DKIM, credentialed indexed banners, configured network exports | Weekly bounded target rotation |
| Corporate | Public job APIs, registry/procurement evidence, PDF/OOXML metadata, configured exports | Weekly per-provider budgets and continuation |
| Developer | Public repository manifests, archive indexes, registry tags, configured JS/API/app metadata | Weekly bounded discovery and manifest rotation |
| Threat | Disclosure lists, ZDI, Apple release index, news, credentialed telemetry, configured social/bug exports | 15-minute family schedule and product/indicator qualification |
| Hardware | Scoped WiGLE queries, FCC exports, credentialed industrial device indexes | Monthly bounded query rotation |

Version 0.8.0 adds a searchable 83-entry provider/collector catalog with public, credentialed, configured URL, and import-only access modes. The catalog distinguishes available capabilities from successful collection. [Source setup, schedules, evidence rules, and the complete provider matrix](docs/sources.md) document all additions. The initial target selection uses Apache, Cisco, and Microsoft from existing website seeds; it can be changed through authenticated source settings.

The 12 default RSS/Atom feeds include The Hacker News, BleepingComputer, Krebs on Security, SANS ISC, CERT-EU, Microsoft MSRC, SecurityWeek, Fortinet PSIRT, Debian, Ubuntu, CERT/CC, and Palo Alto Networks. Add feeds and website seeds through Collectors. NVD vendor advisory references and Wikidata websites expand the crawl queue automatically. Discovery counts show URLs accepted or rejected at the configured queue ceiling.

The database is global in scope, with finite source coverage. It does not enumerate the entire Internet. Initial NVD collection is a recent window, RSS contains each publisher's available feed history, and OSV/GitHub backlogs advance over successive cycles. Historical NVD collection is explicit:

```bash
signalwatch bootstrap --years 2024 2025 2026
signalwatch bootstrap --years all
```

Full historical collection uses substantially more disk and time. Collection status, errors, counts, and last success timestamps remain visible in Collectors. One failing source does not stop the other collectors. Run any family individually from its row. RSS health includes attempted, successful, unchanged, and failed feeds, with each feed's last successful fetch and error. A successful bounded run can still have a pending backlog.

Wikidata rate limiting pauses that source until its saved retry time; the pause survives restarts and manual collection requests. Other collectors continue. The dashboard shows a compact issue summary, an expandable list of details, and the retry time. Old saved errors are formatted for display too, so encoded queries and HTML error pages do not fill the table. A website collector can be Partial while still saving pages: unavailable domains, timeouts, denied requests, and robots exclusions remain visible as coverage limitations.

Version 0.9.3 retries transient 502/504 responses within existing request limits, honors host cooldowns outside cache locks, preserves fair target rotation, and reuses failed robots lookups within each website run. Default OSS-Security and Full Disclosure feeds can fall back to bounded public Openwall archives when their feeds fail; archive access still follows robots rules. Fallback coverage stays Partial with original feed errors, message dates and archive provenance. Full Disclosure's mirror currently denies automated access, so it remains blocked while its primary feed is unavailable. Recovered primary feeds clear their saved error state.

CVE Program collection prioritizes recent updates; it is not a full CVE archive. Its coverage floor and any detected gap remain visible. CSAF gradually drains each publisher's available feed history, preserving fixed/not-affected status and remediation in the full record. Only explicit known-affected CPE/PURL identities participate in matching; unsupported product identities remain available as unverified source data. Native CNA version/status rules are retained and marked unverified where they cannot be evaluated.

## Use

- **Intelligence:** ranked global advisory records, KEV filter, CVSS/EPSS, affected products, and original source evidence.
- **Warnings:** potential advisory matches against recorded deployments, including version matching reasons and evidence URLs.
- **Infrastructure:** searchable company, domain, IP, vendor, technology, OS, device, and package records with relationships.
- **News:** security articles and CVE references. Entity details also show exact product mentions as candidate signals before a CVE exists.
- **Changes:** local advisory additions/changes, KEV additions/removals, and warning openings/clearances, with before/after evidence and filtered export.
- **Collectors:** run sources, add public URLs/RSS, and record a technology observation from existing inventory evidence.

Searches, filters, and pagination survive tab switches. The current view is encoded in the URL for reloads, sharing, and browser Back/Forward. Intelligence and Warnings support priority/newest sorting; Warnings also filter known exploitation and version-match state. Exports apply the same active filters and retain full records.

Follow company/domain/product relationships, advisory IDs, and article references inside the evidence drawer; its Back control restores the previous record. Product catalog details show their published advisories even when no deployment has been observed. CVE aliases resolve to the actual stored source document. Package details retain both enumerated versions and affected ranges.

### Company profiles

In Infrastructure, add a company or open an existing company to edit its display name, legal name, aliases, brands, parent company, identity source, and notes. Names, aliases, brands, and legal names are searchable. Parent/subsidiary links describe the saved corporate structure; they do not automatically transfer assets or warnings between companies. Profile edits and asset decisions are stored separately from collector records and survive later collector refreshes.

Company profiles list official website associations, observed redirect destinations, and manual asset decisions with their sources, timestamps, confidence, and reasons. Observed redirects between a hostname and its `www` equivalent contribute to the company's observations and potential warnings. Other redirect destinations appear as candidates until reviewed. DNS answers, shared addresses, hosting networks, and CNAMEs do not establish company ownership.

Confirm an owned asset to include its observations and warnings and queue its supplied URL for the normal web collector. Record third-party services separately: their relationships remain visible without attributing their technologies to the company's owned inventory. Candidate and rejected associations do not contribute to the company rollup. Each manual decision requires an evidence description and source URL; reset restores automatic attribution. Company asset traversal is bounded and reports truncation when the limit is reached. An official website association identifies a company's published website, rather than proving legal ownership of its hosting infrastructure.

`POST /api/companies/profile` creates or updates a profile using `company_id` (omitted for creation), `name`, `legal_name`, `aliases`, `brands`, `parent_company_id`, `notes`, and `source_url`. `POST /api/companies/assets` accepts `company_id`, `asset_url`, `status` (`confirmed`, `candidate`, `rejected`, or `automatic`), `role` (`owned` or `service`), `evidence`, and `source_url`. Both return full company detail. `GET /api/entity?id=...` includes the `company_profile` and aggregated evidence for included assets. These routes use the existing API authentication.

Change history starts when this version is installed. Existing database contents are registered without invented events. "First observed locally" is the ingestion time, separate from the publisher's disclosure date. Source updates generate events when titles, CVSS, affected identities/version rules, or rejection status change; unchanged downloads and timestamp-only changes do not generate events. Warning clearance means the current records no longer match, rather than proof of remediation. History is retained for 90 days, capped at 50,000 events by default.

Partial collector errors remain visible. HTML challenge pages are rejected as invalid feeds. Duplicate reporting retains each feed's CVE contribution, including across collection cycles; publisher corrections replace that feed's contribution. Polling pauses while the browser tab is hidden, overlapping refreshes are combined, and superseded searches are cancelled. The advisory total counts active canonical advisories; `advisory_documents` in the API retains the raw source-document count.

CPE catalog entries describe products; they do not prove deployment by a company. Company relationships come from explicit official-website evidence. Website fingerprints describe visible responses, scripts, or generators; they do not identify hidden infrastructure or arbitrary IoT devices. Import existing inventory to connect those assets.

Warnings remain potential matches. Exact/range/unknown version states are separate from source evidence confidence. Full CPE Boolean applicability and OS prerequisites require verification. Supported numeric CPE ranges, strict numeric SemVer, and PyPI ranges are compared; unsupported version syntax is retained as unverified. No exploit execution occurs.

Successful page refreshes replace that page's automated observations. Failed requests preserve the last evidence and expose the error. Observations retain their timestamps; an unreachable or unvisited page is historical evidence. KEV and EPSS dates are retained separately from deployment evidence.

Network relationships describe BGP routing from RIPE RIS, including multiple announcing ASNs. They do not establish company ownership or deployment on a shared network. Successful no-route results count as checked; failed enrichment remains pending. Routing relationships retain their observation timestamps. DNS discovery tries the configured system resolver and falls back to DNS over HTTPS when resolution fails. A/AAAA and CNAME evidence retains the resolver, query URI, observation time, and TTL where available. Successful cached answers retain their original observation time. NXDOMAIN is a valid negative answer; resolver and partial-family failures appear in collection health.

## SBOM inventory

Import CycloneDX 1.4–1.7 JSON or SPDX 2.2/2.3 JSON through Collectors or the CLI. Supply the asset's full HTTP(S) URL and an inventory source key. The URL identifies this inventory scope, including its path; it is not fetched by the importer. Reimporting the same asset/source replaces only that inventory, preserving manual observations and other source keys. An empty valid inventory clears that source's observations.

Explicit CPEs connect to NVD/vendor product rules; supported PURLs connect to OSV/GitHub package identities. Multiple installed versions of the same package are retained. Supported PURL types are npm, pypi, maven, golang, cargo, nuget, gem, composer, hex, and pub. Qualified/subpath PURLs, unsupported identities, excluded components, external version ranges, and conflicting versions are reported as skipped. Package names alone do not establish identities. SPDX 3/JSON-LD and XML formats are unsupported. This extracts inventory fields rather than performing full SBOM schema validation.

```bash
signalwatch import-sbom inventory.cdx.json --asset https://service.example/app --source production
signalwatch import-sbom inventory.spdx.json --asset https://service.example/app --source production
signalwatch export --kind events --event-kind warning_opened > warning-openings.jsonl
```

`POST /api/import/sbom` accepts `asset_url`, `source_key`, and a JSON `document` object. The import report includes imported/skipped/duplicate components, observations, skip reasons, and current matching totals. Its request limit defaults to 20 MiB. Imports remain local to the application.

## Unified staging queue

Version 0.7.0 adds one durable `raw_ingress` table for heterogeneous inputs. Every source uses the same envelope: original payload bytes, SHA-256, source, MIME type, adapter, source URL, JSON metadata, observation/receipt times, optional stream/idempotency keys, and processing state. New formats need an adapter rather than a database migration. Payloads and metadata are data; source URLs are provenance and are not fetched by the staging worker.

| Adapter | Accepted input | Normalized output |
| --- | --- | --- |
| `vulnerability_json` | NVD, GHSA, OSV, or canonical advisory JSON | Existing advisory/product records |
| `news` | RSS/Atom or plain article text with `metadata.article_url` | Articles and CVE references; text without an article URL remains evidence |
| `dns` | DNS text records or structured DNS JSON | Domain anchors, DNS record evidence, and relationships |
| `pdf_metadata` | Already extracted PDF metadata as JSON/text | Document evidence; binary PDF extraction is a separate producer step |
| `wireless` | MAC/BSSID CSV, text, or JSON logs | Wireless evidence with normalized MAC addresses and explicit log fields |
| `normalized_batch` | Existing `Store.ingest` batch JSON | Existing models, including explicit snapshot markers |
| `opaque` | Any bytes | Generic evidence with a bounded preview and raw-record reference |
| `auto` | Recognized MIME type, JSON shape, or `metadata.record_type` | A supported adapter above; unknown input becomes opaque evidence |

Adapters do not infer company ownership, hidden technologies, device vendors, or vulnerable deployments from DNS, documents, or MAC addresses. Those records remain evidence until explicit attribution/inventory connects them. Adapters cap parsed input records at 5,000 per item; derived entities and relationships may increase the normalized row count. Existing native collectors and SBOM imports retain their current ingestion/checkpoint paths; this queue accepts new raw inputs and explicit normalized batches.

`POST /api/staging` returns HTTP 202 after durable enqueue. For example:

```json
{
  "source": "dns-import",
  "adapter": "dns",
  "content_type": "text/plain",
  "stream_key": "example.net",
  "idempotency_key": "export-0001",
  "observed_at": "2026-10-19T12:00:00Z",
  "metadata": {"resolver": "imported-log"},
  "payload_encoding": "utf-8",
  "payload": "example.net. 300 IN TXT \"v=spf1 -all\"\n"
}
```

`utf-8` strings and `base64` transport preserve their decoded bytes, including whitespace. `json` accepts a JSON value and stores a canonical serialization; use a UTF-8 string, base64, or the CLI when original JSON formatting matters. `observed_at` requires a timezone in API requests and defaults to receipt time; publisher disclosure dates remain separate. Metadata is capped at 16 KiB. All staging routes use the existing API authentication.

| Route | Purpose |
| --- | --- |
| `GET /api/staging?status=dead&limit=50&offset=0` | Paginated envelope/state listing without raw payloads |
| `GET /api/staging/stats` | Counts, bytes, limits, and worker health |
| `GET /api/staging/{id}` | One envelope and processing result/error |
| `GET /api/staging/{id}/payload` | Exact retained bytes as an attachment |
| `POST /api/staging/{id}/retry` | Retry a failed record; optional `{"adapter":"opaque"}` changes its adapter |

```bash
signalwatch stage records.txt --source dns-import --adapter dns --stream-key example.net
signalwatch stage report-metadata.json --source reports --adapter pdf_metadata
signalwatch stage wireless.csv --source imported-logs --adapter wireless
signalwatch staging list --status dead
signalwatch staging show 1 --payload > original-input.bin
signalwatch staging retry 1 --adapter opaque
signalwatch staging work --limit 25
signalwatch staging stats
signalwatch staging prune
```

The server starts a background worker, including with `serve --no-collect`. `staging work` runs one bounded drain without a server. Workers claim fenced leases; normalized writes and the processed acknowledgment commit in one SQLite transaction. Invalid formats become `dead`; transient errors retry after 30 and 60 seconds, with three attempts total. Expired leases can be reclaimed. Failed records retain their original bytes for inspection and retry.

Arrival order is preserved per `(source, stream_key)`, across adapters. A delayed record blocks later records in that stream while other streams progress. Use distinct stream keys for independent datasets. Once a newer record has processed, retained older records cannot be retried over it, even if the newer raw record is later pruned. Explicit idempotency keys deduplicate within `(source, stream_key, adapter)` only while the raw row is retained; a conflicting payload or envelope is rejected. Repeated observations without a key remain separate records.

Defaults allow 8 MiB per payload and 512 MiB/10,000 raw records total. Processed raw records expire after seven days and may be evicted sooner to admit new data; normalized records remain. Pending, processing, and dead records are never evicted automatically. When they fill capacity, admission returns HTTP 503 with `Retry-After: 30`. Raw references can outlive raw retention, so payload retrieval may later return 404. These bounds cover raw payload bytes, not total SQLite/index/WAL disk usage.

## Wireless datasets and company evidence

The Wireless view imports WiGLE CSV or CSV.gz exports, displays observation clusters on a map, and opens device histories and company evidence. Uploads enter the existing staging queue in bounded chunks; canonical `wireless_datasets`, `wireless_devices`, and `wireless_observations` tables preserve every source row, including identical repeated observations. Dataset identity is the original file SHA-256; `(dataset_id, source_row)` prevents reimports from duplicating observations. Interrupted imports resume from the retained archive.

The original uploaded bytes remain under the database directory's `wireless-imports` directory and are available through the authenticated source-download endpoint. Staging retention does not delete that archive or canonical wireless observations. Keep the database and its adjacent import directory on persistent storage.

| Field | Interpretation |
| --- | --- |
| Coordinates / GPS accuracy | Scanner positions and reported location uncertainty; map points represent observations. A device's representative point records its source dataset, row, and timestamp. Older chunks do not replace a newer representative observation. |
| `FirstSeen` | Per-observation time. Native WiGLE exports use UTC despite omitting a suffix; original text is preserved. Epoch-1970 sentinels become unknown timestamps. Generic CSV without native provenance retains an unspecified timezone. |
| `Frequency` | Wi-Fi MHz; Bluetooth device-class code; cellular channel-number field. It is not universally MHz. |
| Identifier / type | Stable identity uses radio type plus identifier. Cellular identifiers retain their full source value; Wi-Fi and Bluetooth MAC addresses normalize separately. |
| Raw row / validation | Unknown columns and original field text remain available. Invalid coordinates remain in the observation with validation reasons and no map point. |
| Company links | Registry manufacturer assignments, advertised providers, and nearby business candidates retain separate roles and evidence. A manufacturer or nearby facility does not establish the device operator. Manual confirmation or rejection is explicit; rejection suppresses automatic links for that company. |

Official IEEE/Bluetooth registry imports enrich manufacturer/provider evidence; existing device classifications can be imported with provenance. Business matching uses imported public OpenStreetMap facility records and observation coordinates with uncertainty. External business lookups require `lookup_businesses: true`; ordinary enrichment does not send observation areas to another service. The map works locally, with optional OpenStreetMap tiles enabled explicitly in the interface. Company profiles include a distinct-device wireless summary. Wireless observations alone create no software deployments or vulnerability warnings.

All endpoints use the existing API authentication:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/import/wigle` | Raw CSV/CSV.gz request body; optional `X-Filename` and `X-Source-Url`; returns `202` and dataset/job ID. |
| `GET /api/wireless/datasets` / `GET /api/wireless/datasets/{id}` | Counts, bounds, import state, and progress. |
| `GET /api/wireless/datasets/{id}/source` | Original uploaded bytes. |
| `GET /api/wireless/stats?dataset_id=...` | Global or dataset-scoped distinct-device and observation counts. |
| `GET /api/wireless/devices` / `GET /api/wireless/devices/{id}` | Search, type/dataset/company filters, observation history, and attribution evidence. |
| `GET /api/wireless/map?bbox=west,south,east,north&zoom=...` | Bounded GeoJSON clusters with matched observation totals; supports dataset, type, query, and company filters. |
| `POST /api/wireless/devices/{id}/company` | Evidence-backed manual operator confirmation or rejection. |
| `GET/POST /api/wireless/facilities` | Inspect or add sourced business locations. |
| `POST /api/wireless/registries` / `POST /api/wireless/device-enrichment` | Import manufacturer registries or prior device classifications with source provenance. |
| `POST /api/wireless/business-import` | Import an existing Overpass JSON export with source provenance. |
| `GET/POST /api/wireless/enrichment` | Inspect or request manufacturer/existing-business matching; external bounded queries require `lookup_businesses: true`. |

## Configuration and performance

Edit the generated `config.json`. Restart after editing it externally. RSS additions made through the UI persist immediately.

Existing configurations gain the new collector switches from defaults. An existing explicit `feeds` array is preserved; copy additional feed entries from `config.example.json` to adopt the expanded RSS list while retaining custom feeds. The bundled list replaces the currently unavailable Cisco RSS endpoint with SecurityWeek.

| Setting | Default | Purpose |
| --- | --- | --- |
| `concurrency` / `per_host` | 32 / 4 | Shared connection pool and per-host connection limit |
| `interval_minutes` | 30 | Fallback family interval |
| `source_intervals` | RSS/threat 15 minutes, vulnerability sources 360, recon 10080, hardware 43200 | Independent family schedules; manual collection bypasses intervals |
| `source_targets` | Apache, Cisco, Microsoft | Explicit domains and optional public job-board/repository/CIK/document identifiers |
| `provider_settings` / `provider_credentials` | Public defaults / Empty | Provider options and environment-loaded credentials; see source matrix |
| `public_source_batch` / `public_source_records` / `public_source_concurrency` | 3 / 100 / 4 | Extension target/request budgets, parsed records per response, concurrent requests per family |
| `threat_source_batch` | 8 | Threat-provider request budget per cycle; deferred coverage remains visible |
| `watch_products` / `exploit_keywords` | Empty / Exploit and patch indicators | Mandatory product-and-indicator filter for social qualification |
| `crawl_batch` / `crawl_pages` / `crawl_depth` | 50 / 8 / 1 | Hosts per cycle and bounded same-host page traversal |
| `crawl_interval_hours` | 24 | Website refresh interval |
| `max_discovered_domains` | 10000 | Automatic source expansion ceiling |
| `osv_max_records` | 500 | OSV records per run, retaining backlog continuation |
| `osv_index_chunk_mb` / `osv_index_chunks` / `osv_index_max_chunks` | 1 / 8 / 32 | Index chunk MiB, initial scan budget, and maximum adaptive chunk budget |
| `cve_max_records` | 250 | CVE Program records per run |
| `cve_max_zip_mb` | 16 | Compressed cumulative CVE delta archive limit |
| `csaf_max_records` / `csaf_feeds` | 100 / Four official feeds | CSAF document budget and ROLIE source URLs |
| `network_batch` / `network_interval_hours` | 20 / 24 | Public IP enrichment budget and refresh interval |
| `news_concurrency` | 8 | Bound concurrent feed workers before HTTP requests enter the pool |
| `dns_mode` | `fallback` | `system`, `fallback`, or direct `doh` resolution |
| `dns_doh_url` | `https://dns.google/resolve` | Resolver supporting the Google-style DNS JSON API |
| `dns_timeout` / `dns_concurrency` | 5 / 4 | System/DoH timeout and resolver worker limits |
| `sbom_max_mb` | 20 | Maximum SBOM file/request size in MiB; fractional limits supported |
| `events_retention_days` / `events_max_rows` | 90 / 50000 | Local event retention and row cap |
| `staging_max_payload_mb` / `staging_max_mb` | 8 / 512 | Per-item and total retained raw payload MiB |
| `staging_max_records` / `staging_max_completed` | 10000 / 10000 | Raw admission cap and processed-record retention cap |
| `staging_batch` / `staging_poll_seconds` | 25 / 2 | Items per worker drain and idle polling interval |
| `staging_retention_days` | 7 | Processed raw-record retention; pending/dead records remain |
| `wireless_import_max_mb` / `wireless_chunk_rows` | 32 / 5000 | Uploaded file MiB limit and rows per staging chunk; chunk size must be 1–5000 |
| `timeout` | 30 | HTTP request timeout in seconds |
| `headers` / `user_agent` | Application user agent | Request header configuration |
| `sources` | All enabled | Individual collector switches |
| `nvd_api_key` / `github_token` | Empty | Optional provider credentials; environment variables `NVD_API_KEY` / `GITHUB_TOKEN` override these |
| `cors_origins` | Empty array | Exact browser frontend origins; `SIGNALWATCH_CORS_ORIGINS` overrides with a comma-separated list |
| `api_token` | Empty | Optional shared Bearer token for `/api/**`; `SIGNALWATCH_API_TOKEN` overrides this |

The NVD bulk path works without a key. GitHub public request limits apply; a token increases capacity. HTTP caches, conditional requests, source checkpoints, batched transactions, indexed product joins, and FTS5 avoid repeated downloads and broad Cartesian matching. A database-specific process lock prevents overlapping collectors. The browser reads the same WAL database while collection runs.

OSV seeks by modification time when its index changes. Pending runs that produce no records double the scan budget up to `osv_index_max_chunks`. A very large group sharing one timestamp can still exceed that cap after repeated index revisions; the collector reports a partial result with `no_progress_runs` and retains its watermark. Increase the index chunk budget to advance through that group.

This is a single-user service with optional shared API authentication and no account system. `--host` and `--port` override its bind address and port.

## CLI and data

```bash
signalwatch collect
signalwatch collect --sources nvd kev epss news
signalwatch collect --sources cve_program csaf network
signalwatch status
signalwatch seed https://nginx.org/ https://www.apache.org/
signalwatch export --kind advisories > advisories.jsonl
signalwatch export --kind alerts > warnings.jsonl
signalwatch import-jsonl inventory.jsonl --kind observations
```

Observation JSONL accepts one object per line. Required fields are `asset_id`, `vendor`, and `product`; supported fields include `version`, `source_url`, `evidence`, `observed_at`, `confidence`, and `cpe`. Native package inventory uses `ecosystem` and `package` instead of CPE vendor/product. Entity and relationship JSONL can be imported separately with `--kind entities` and `--kind edges`. Without `--kind`, each line is a batch object containing arrays keyed by record type.

The SQLite database is the complete local store. Table responses use bounded excerpts; the detail endpoint and JSON exports retain full records. `/docs` exposes the local API schema. `signalwatch serve --no-collect` opens existing data without scheduling source requests.

```bash
python -m unittest discover -s tests -v
```

Validation includes automated parser, matching, checkpoint, HTTP, and API tests; bounded live collection; and Chromium/Playwright checks at desktop and mobile sizes. Tests cover malformed feeds, cross-feed corrections, CNA rejection precedence, network context, and changing OSV index revisions.

Version 0.4.0 validation includes API inventory replacement, multiple package versions, event filtering/export/rollback, DNS response codes and TTLs, and live system-to-DoH fallback. A bounded live pipeline connected five discovered IPs to four routing prefixes and two ASNs, while recording ten new local advisory events.

Validation on 2026-10-18: 165 automated tests and nine Chromium browser check groups passed at desktop and mobile sizes. An isolated QA database exercised imports and warning transitions; live public collection verified DNS/routing context and local advisory history separately.

Version 0.5.0 validation: 175 Python tests and 12 frontend tests passed, as did strict TypeScript checking and the frontend production build. Remote API tests use real HTTP requests to verify optional authentication, protected exports and mutations, exact-origin preflights, reverse-proxy paths, credential omission, and readable error responses. Fourteen local Chromium interaction groups covered authentication, filtered exports, navigation, forms, and mobile layouts. A separate flow imported explicit test inventory against an actual stored public advisory, displayed a potential warning, then cleared the inventory and verified the local warning-clearance event. Browser validation used a copied database and local frontend source; it did not publish or synchronize a Lovable project. The wheel builds successfully with all package files included.

Version 0.7.0 validation: all 256 backend tests passed, including all five heterogeneous input families, exact raw bytes, authenticated HTTP ingestion, background processing, CLI round trips, malformed inputs, explicit idempotency expiry, concurrent capacity/claims, lease fencing, atomic rollback, stream ordering, failed-record replay guards, and retention. Independent queue/adapter review cleared. No frontend files or dependencies changed in this release.

Version 0.8.0 validation: all 378 backend tests and 47 frontend tests passed, with strict TypeScript and a production build. Independent reviews covered source attribution, raw staging, retries/deferred coverage, credentials, settings persistence, and target rotation. Actual-API Chromium checks passed at desktop/mobile sizes against the 83-entry catalog. A bounded isolated live run fetched public DNS, GitHub, ZDI, Dark Reading, and Apple records and processed all nine raw responses, producing articles/software/network evidence with zero invented deployment observations. The wheel builds with all extension modules and the PDF metadata dependency.

## Primary source documentation

- https://nvd.nist.gov/vuln/data-feeds
- https://nvd.nist.gov/developers/vulnerabilities
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://www.first.org/epss/data
- https://docs.github.com/en/rest/security-advisories/global-advisories
- https://google.github.io/osv.dev/data/
- https://www.wikidata.org/wiki/Wikidata:Data_access
- https://github.com/CVEProject/cvelistV5
- https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json
- https://productcert.siemens.com/productcert/csaf/ssa-feed-tlp-white.json
- https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html
- https://stat.ripe.net/docs/data-api/api-endpoints/network-info
- https://developers.google.com/speed/public-dns/docs/doh/json
- https://cyclonedx.org/docs/latest/
- https://spdx.github.io/spdx-spec/v2.3/external-repository-identifiers/
- https://github.com/package-url/purl-spec
