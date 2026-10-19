# Public sources without account setup

Version 0.12.0 adds public source collection to the existing Python workers, raw staging queue, SQLite graph, and authenticated dashboard. It adds no hosted service or scanner executable. Existing explicit source/provider disables, credentials, company targets, and schedules are retained.

## Automatic collection

| Capability | Implementation | Scope |
| --- | --- | --- |
| Certificate hostnames | `ctlogs` with existing `crtsh` fallback | Known target domains; serial paginated requests with persisted quotas/cooldowns. Anonymous ctlogs coverage includes valid certificates and certificates expired within 90 days, with at most 10 pages. |
| Legal entities and parents | `gleif` | Public legal-name search and publisher-reported LEI parents. Search matches remain candidates and do not merge company profiles. |
| Jobs and documents | `corporate_discovery`, existing Greenhouse/Lever/document adapters | Company homepage plus one linked company page; discovered public board/document links, bounded weekly rotation and cache. Public documents expose publisher metadata, not verified installed software. |
| Freight evidence | `importyeti_public` | Public visible company tables only; exact page-name check and candidate company context. No locked fields or infrastructure ownership inference. |
| MISP intelligence | `circl_misp` | CIRCL public OSINT manifest and at most two changed event documents per cycle from a seven-day modification window. Report dates remain distinct from modification dates. |
| IP context | `greynoise_public` | Existing public IPv4 inventory; at most eight anonymous requests per UTC day, spaced three hours apart. HTTP 404 records an unknown/no-observation result, never a benign verdict. |
| Dependencies and candidate secrets | Existing `github_public` adapter | Bounded public repository root files, expanded manifest/lock parsing, redacted static findings, and exact-version OSV batch lookups. No whole-organization history scan or credential validation. |

Existing RIPEstat, NVD, CISA KEV, OSV, GitHub Advisories, CVE Program, and CSAF collection remains in place. New records are visible through the existing Collectors, Infrastructure, evidence details, and Knowledge Graph views. The source catalog reports actual access mode, health, requirements, and bounded coverage.

MISP JSON is retained in the private raw queue/HTTP cache using the existing ingestion design; encoded attachment fields may be present in these original bytes. The graph projection discards attachment and malware-sample data, and the collector never decodes or fetches sample binaries or follows observable URLs. Static secret findings contain redacted matches/fingerprints; original public artifact bytes retain the existing raw cache/staging behavior.

## Omitted under the no-setup constraint

- Separate MISP, OpenCTI, OpenCVE, or IVRE deployments and their additional databases/services.
- OTX, SecurityTrails, new WiGLE API access, or other feeds requiring absent credentials or registration. Existing supplied credentials continue to work through their original adapters.
- SEC contact configuration when no truthful contact User-Agent is supplied; existing configured SEC submissions collection remains supported.
- Unrestricted LinkedIn/Indeed scraping, locked freight data, and native APK/IPA extraction.
- Automatic current FCC ULS coverage: official bulk/query endpoints returned HTTP 403 during verification; accessible official Socrata datasets contained 2018 data. No historical snapshot is represented as current coverage.

Cert Spotter has a limited unauthenticated personal/evaluation mode and is implemented as an optional provider, disabled by default. Its documentation requests account setup for production use; ctlogs is the enabled public alternative.

## Primary references

- https://api.ctlogs.dev/
- https://sslmate.com/help/reference/ct_search_api_v1
- https://www.gleif.org/en/lei-data/gleif-api
- https://docs.greenhouse.io/job-board.html
- https://github.com/lever/postings-api
- https://www.importyeti.com/
- https://www.circl.lu/doc/misp/feed-osint/
- https://docs.greynoise.io/docs/using-the-greynoise-community-api
- https://google.github.io/osv.dev/api/
