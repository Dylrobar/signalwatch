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

Open http://127.0.0.1:8765. Collection starts immediately and repeats every 30 minutes while the service runs. Configuration and data belong to the directory containing `config.json`. Stop with Ctrl+C; restart with the same configuration to resume checkpoints.

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

The 12 default RSS/Atom feeds include The Hacker News, BleepingComputer, Krebs on Security, SANS ISC, CERT-EU, Microsoft MSRC, SecurityWeek, Fortinet PSIRT, Debian, Ubuntu, CERT/CC, and Palo Alto Networks. Add feeds and website seeds through Collectors. NVD vendor advisory references and Wikidata websites expand the crawl queue automatically. Discovery counts show URLs accepted or rejected at the configured queue ceiling.

The database is global in scope, with finite source coverage. It does not enumerate the entire Internet. Initial NVD collection is a recent window, RSS contains each publisher's available feed history, and OSV/GitHub backlogs advance over successive cycles. Historical NVD collection is explicit:

```bash
signalwatch bootstrap --years 2024 2025 2026
signalwatch bootstrap --years all
```

Full historical collection uses substantially more disk and time. Collection status, errors, counts, and last success timestamps remain visible in Collectors. One failing source does not stop the other collectors. Run any family individually from its row. RSS health includes attempted, successful, unchanged, and failed feeds, with each feed's last successful fetch and error. A successful bounded run can still have a pending backlog.

Wikidata rate limiting pauses that source until its saved retry time; the pause survives restarts and manual collection requests. Other collectors continue. The dashboard shows a compact issue summary, an expandable list of details, and the retry time. Old saved errors are formatted for display too, so encoded queries and HTML error pages do not fill the table. A website collector can be Partial while still saving pages: unavailable domains, timeouts, denied requests, and robots exclusions remain visible as coverage limitations.

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

## Configuration and performance

Edit the generated `config.json`. Restart after editing it externally. RSS additions made through the UI persist immediately.

Existing configurations gain the new collector switches from defaults. An existing explicit `feeds` array is preserved; copy additional feed entries from `config.example.json` to adopt the expanded RSS list while retaining custom feeds. The bundled list replaces the currently unavailable Cisco RSS endpoint with SecurityWeek.

| Setting | Default | Purpose |
| --- | --- | --- |
| `concurrency` / `per_host` | 32 / 4 | Shared connection pool and per-host connection limit |
| `interval_minutes` | 30 | Collection cycle interval |
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
