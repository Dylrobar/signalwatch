# Source expansion: version 0.8.0

The catalog contains 83 provider/collector entries: 11 existing native collectors and 72 additions across exposure, corporate, developer, threat, and hardware families. Access modes are explicit: 21 public adapters, 17 credentialed adapters, 25 configured public URL/export adapters, and nine import-only sources, alongside the 11 native collectors. An entry is not evidence of successful collection. Missing credentials, target fields, URLs, and imports remain visible as setup requirements.

Every new collector stages original response bytes with provider, target/query context, MIME type, content hash, observation time, and a replay reference. The `public_source` adapter dispatches normalization into the existing entity/article models. There is one staging schema and no provider-specific database tables.

## Default targets and schedules

The initial target list selects Apache Software Foundation (`apache.org`), Cisco (`cisco.com`), and Microsoft (`microsoft.com`) from existing configured website seeds. Their public GitHub organization identifiers are configured; Microsoft's CIK is `0000789019`. These labels are collection scope, not inferred legal ownership or deployed inventory. Replace or extend `source_targets` through configuration or the settings endpoint. Job board IDs, document URLs, wireless queries, contact headers, and credentials require explicit configuration.

| Family | Default interval |
| --- | --- |
| `news`, `threat` | 15 minutes |
| `nvd`, `kev`, `epss`, `github`, `osv`, `cve_program`, `csaf` | Six hours |
| `exposure`, `corporate`, `developer` | Seven days |
| `hardware` | 30 days |
| `web`, `network`, `wikidata` | Existing `interval_minutes`, default 30 minutes; internal refresh TTLs still apply |

`source_intervals` overrides family intervals in minutes. Attempt completion and next-run times persist across restarts. Manual collection bypasses intervals while honoring source retry cooldowns. Errors do not create tight retry loops. A provider's disabled/unconfigured/deferred state never becomes a fresh success.

`public_source_batch` defaults to three targets/requests per provider; exact traversal budgets vary by adapter and remain bounded. Corporate targets/documents, network targets, developer targets/manifests, and hardware queries rotate with persisted cursors. `public_source_concurrency` defaults to four concurrent requests per extension family. `public_source_records` defaults to 100 input records per response; derived entities/relationships can add rows. `threat_source_batch` defaults to eight provider requests, sufficient to poll all six enabled default threat feeds each 15-minute cycle. Enabling more feeds than that budget produces visible deferred coverage and rotation.

The six newly enabled threat defaults are Full Disclosure, OSS-Security, ZDI Published, ZDI Upcoming, Dark Reading, and Apple's security release index. Existing RSS additions remain intact and are not downloaded twice through new defaults. A publisher error or unavailable HTML page remains a provider error. Other public/provider integrations run when their target fields or URLs are present; key-required integrations remain unconfigured until supplied.

## Configuration and API

| Setting | Content |
| --- | --- |
| `source_targets` | Objects with `domain`, optional `name`, `company_id`, `github_org`, `gitlab_group`, `cik`, `greenhouse_board`, `lever_site`, `document_urls`, `javascript_urls`, `sourcemap_urls`, `dkim_selectors`, `bssids`, and provider-specific target fields |
| `provider_settings` | Provider-keyed nonsecret options: `enabled`, `url`/`urls`, `query`, repositories, explicit IPs, board-specific options, SEC `user_agent`, and wireless query bounds |
| `provider_credentials` | Provider-keyed credential strings/objects loaded from local configuration or environment; omitted from API settings/status |
| `watch_products` | Explicit product/package identifiers required for high-frequency social qualification |
| `exploit_keywords` | Exploit, vulnerability, or patch indicators for the qualification rule |

`GET /api/sources/catalog` returns `{items,total}` with provider ID, family, access mode, description, official documentation link, credential environment name, current health, and missing requirements. The Collectors tab displays this catalog with filtering, provider errors/counts, and family schedules.

`GET /api/sources/settings` returns public collection settings. `POST /api/sources/settings` accepts partial updates to `source_targets`, `provider_settings`, `source_intervals`, `sources`, `watch_products`, and `exploit_keywords`; it persists atomically and takes effect without restarting. Family/provider maps merge existing settings; target/product arrays replace their previous values. Credentials and credential-bearing URLs are rejected by this endpoint. All routes use existing bearer authentication.

```bash
signalwatch collect --sources exposure corporate developer threat hardware
signalwatch status
signalwatch staging list --status dead
```

For every provider, `SIGNALWATCH_<UPPERCASE_PROVIDER_ID>_CREDENTIALS` accepts a credential string or JSON object. Common aliases include `SHODAN_API_KEY`, `CENSYS_API_KEY`, `FOFA_API_KEY`, `ZOOMEYE_API_KEY`, `NETLAS_API_KEY`, `GREYNOISE_API_KEY`, `URLHAUS_AUTH_KEY`, `VULNCHECK_API_KEY`, `ATTACKERKB_API_KEY`, `SAM_GOV_API_KEY`, and `OPENCORPORATES_API_KEY`. Existing `GITHUB_TOKEN` is reused only for fixed GitHub API requests. Environment changes require a service restart.

| Provider | Credential/required scope |
| --- | --- |
| Censys | `api_key` Personal Access Token, explicit CenQL `query`; optional `organization_id` |
| WiGLE | JSON object with `api_name` and `api_token`; explicit BSSID/SSID query or bounded coordinates |
| OpenCorporates/SAM.gov | Credential string or object with `api_key`, `token`, or `key`; target legal-name query |
| SEC EDGAR | Target `cik`; descriptive `provider_settings.sec_edgar.user_agent` with contact email, or `SIGNALWATCH_SEC_USER_AGENT` |
| GreyNoise Community | API key and explicit public IPv4 list; this is an IP lookup adapter, not a global free feed |
| Docker Hub | Bearer credential plus repository names, or an explicitly configured public export URL |
| Industrial indexers | Explicit query and `shodan`/`censys` credentials, shared through `credential_provider` |

## Evidence semantics

Job descriptions, PDF/OOXML producer properties, repository manifests, API specifications, container tags, archive records, sensor reports, wireless addresses, and certificate names retain their source context. They do not automatically establish a company's current deployment, asset ownership, vulnerable version, device model, or parent/subsidiary relationship. A registry record can support identity review; it does not overwrite manual company profiles. Certificate validity, DNS TTLs, archive timestamps, source publication times, and local discovery times remain distinct where supplied.

The document adapter extracts actual PDF information/XMP with `pypdf` and OOXML core/application properties with ZIP/XML parsing. It preserves producer/creator claims without guessing an OS from a software name. Container adapters collect tags/architecture metadata; they do not inspect image filesystems. App-store adapters accept public metadata/export URLs rather than downloading APK/IPA/extension binaries. FCC adapters accept configured public JSON/CSV/HTML exports; the retired/unverified License View endpoint is not advertised as a working integration.

The rule filter requires a watched product identifier **and** an exploit/patch indicator. It records matched terms and qualification reasons in `_signal`. Unqualified social records remain generic evidence; regular security news remains available. No NLP service is called, and qualification is not a vulnerability verdict. Early reports without a CVE stay attributed articles/evidence until an authoritative advisory arrives.

Import-only entries cover sources without an unrestricted supported discovery API. They can be ingested through the staging API/CLI with `adapter=public_source` and `metadata.provider` set to the catalog ID. A configured URL mode fetches only the explicitly supplied public/export URL. Provider-specific `format` or artifact metadata may be required for structured interpretation; opaque staging remains available for unsupported formats.

## Provider catalog

| ID | Family | Access | Provider |
| --- | --- | --- | --- |
| `nvd` | `nvd` | `native` | [NVD](https://nvd.nist.gov/) |
| `kev` | `kev` | `native` | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) |
| `epss` | `epss` | `native` | [FIRST EPSS](https://www.first.org/epss/) |
| `github` | `github` | `native` | [GitHub Advisory Database](https://github.com/advisories) |
| `osv` | `osv` | `native` | [OSV](https://osv.dev/) |
| `cve_program` | `cve_program` | `native` | [CVE Program](https://www.cve.org/) |
| `csaf` | `csaf` | `native` | [Vendor CSAF](https://www.csaf.io/) |
| `network` | `network` | `native` | [RIPEstat routing](https://stat.ripe.net/) |
| `wikidata` | `wikidata` | `native` | [Wikidata company websites](https://www.wikidata.org/) |
| `news` | `news` | `native` | [Security/vendor RSS](https://github.com/Dylrobar/signalwatch#collection) |
| `web` | `web` | `native` | [Public websites and DNS](https://github.com/Dylrobar/signalwatch#collection) |
| `crtsh` | `exposure` | `public` | [crt.sh certificate transparency](https://crt.sh/) |
| `passive_dns` | `exposure` | `public` | [HackerTarget passive host search](https://hackertarget.com/find-dns-host-records/) |
| `dns_txt` | `exposure` | `public` | [Public DNS TXT / SPF / DMARC / DKIM](https://developers.google.com/speed/public-dns/docs/doh/json) |
| `shodan` | `exposure` | `api_key` | [Shodan indexed banners](https://developer.shodan.io/api) |
| `censys` | `exposure` | `api_key` | [Censys Platform search](https://docs.censys.com/reference/v3-globaldata-search-query) |
| `fofa` | `exposure` | `api_key` | [FOFA indexed assets](https://fofapro.github.io/fofa-py/fofa.html) |
| `zoomeye` | `exposure` | `api_key` | [ZoomEye indexed assets](https://github.com/zoomeye-ai/ZoomEye-python/blob/master/api.md) |
| `netlas` | `exposure` | `api_key` | [Netlas indexed responses](https://docs.netlas.io/api-reference/) |
| `dnsdumpster` | `exposure` | `configured_url` | [DNSDumpster](https://dnsdumpster.com/) |
| `securitytrails` | `exposure` | `configured_url` | [SecurityTrails](https://docs.securitytrails.com/) |
| `rapiddns` | `exposure` | `configured_url` | [RapidDNS](https://rapiddns.io/) |
| `bgpview` | `exposure` | `configured_url` | [BGPView](https://bgpview.io/) |
| `he_bgp` | `exposure` | `configured_url` | [Hurricane Electric BGP Toolkit](https://bgp.he.net/) |
| `arin` | `exposure` | `configured_url` | [ARIN registry](https://www.arin.net/resources/registry/whois/rdap/) |
| `greenhouse` | `corporate` | `public` | [Greenhouse public job boards](https://docs.greenhouse.io/job-board) |
| `lever` | `corporate` | `public` | [Lever public postings](https://github.com/lever/postings-api) |
| `sec_edgar` | `corporate` | `public` | [SEC EDGAR submissions](https://www.sec.gov/search-filings/edgar-application-programming-interfaces) |
| `opencorporates` | `corporate` | `api_key` | [OpenCorporates](https://api.opencorporates.com/documentation/API-Reference) |
| `sam_gov` | `corporate` | `api_key` | [SAM.gov public entity registrations](https://open.gsa.gov/api/entity-api/) |
| `company_documents` | `corporate` | `public` | [Public company document metadata](https://pypdf.readthedocs.io/en/stable/user/metadata.html) |
| `public_procurement` | `corporate` | `configured_url` | [Configured public procurement exports](https://www.usaspending.gov/) |
| `freight_exports` | `corporate` | `configured_url` | [Configured public freight exports](https://www.census.gov/foreign-trade/) |
| `indeed` | `corporate` | `import` | [Indeed exports](https://docs.indeed.com/) |
| `linkedin_jobs` | `corporate` | `import` | [LinkedIn job exports](https://learn.microsoft.com/en-us/linkedin/talent/) |
| `glassdoor` | `corporate` | `import` | [Glassdoor exports](https://www.glassdoor.com/) |
| `importyeti` | `corporate` | `import` | [ImportYeti exports](https://www.importyeti.com/) |
| `enigma` | `corporate` | `import` | [Enigma exports](https://www.enigma.com/) |
| `github_public` | `developer` | `public` | [GitHub public repositories](https://docs.github.com/en/rest/repos) |
| `gitlab_public` | `developer` | `public` | [GitLab public projects](https://docs.gitlab.com/api/groups/) |
| `bitbucket_public` | `developer` | `configured_url` | [Bitbucket public repositories](https://developer.atlassian.com/cloud/bitbucket/rest/api-group-repositories/) |
| `wayback_cdx` | `developer` | `public` | [Internet Archive CDX](https://github.com/internetarchive/wayback/tree/master/wayback-cdx-server) |
| `commoncrawl` | `developer` | `public` | [Common Crawl URL index](https://index.commoncrawl.org/) |
| `javascript_artifacts` | `developer` | `configured_url` | [Public JavaScript and sourcemaps](https://tc39.es/ecma426/) |
| `dockerhub` | `developer` | `api_key` | [Docker Hub tag metadata](https://docs.docker.com/reference/api/hub/latest/operations/ListRepositoryTags/) |
| `quay` | `developer` | `public` | [Quay public tag metadata](https://docs.quay.io/api/) |
| `postman_public` | `developer` | `configured_url` | [Postman public collections](https://learning.postman.com/docs/collaborating-in-postman/using-workspaces/public-workspaces/) |
| `swaggerhub_public` | `developer` | `configured_url` | [SwaggerHub public specifications](https://support.smartbear.com/swaggerhub/docs/en/explore-and-manage-apis/export-an-api-definition.html) |
| `appstore_public` | `developer` | `configured_url` | [Apple App Store public metadata](https://apps.apple.com/) |
| `googleplay_public` | `developer` | `configured_url` | [Google Play public metadata](https://play.google.com/store/apps) |
| `chrome_webstore_public` | `developer` | `configured_url` | [Chrome Web Store public metadata](https://chromewebstore.google.com/) |
| `slack_apps_public` | `developer` | `configured_url` | [Slack Marketplace public metadata](https://slack.com/marketplace) |
| `fulldisclosure` | `threat` | `public` | [Full Disclosure](https://seclists.org/fulldisclosure/) |
| `oss_security` | `threat` | `public` | [OSS-Security](https://seclists.org/oss-sec/) |
| `zdi_upcoming` | `threat` | `public` | [ZDI Upcoming Advisories](https://www.zerodayinitiative.com/rss/) |
| `zdi_published` | `threat` | `public` | [ZDI Published Advisories](https://www.zerodayinitiative.com/rss/) |
| `zdi_blog` | `threat` | `public` | [ZDI Research Blog](https://www.zerodayinitiative.com/rss/) |
| `dark_reading` | `threat` | `public` | [Dark Reading](https://www.darkreading.com/) |
| `apple_security` | `threat` | `public` | [Apple Security Releases](https://support.apple.com/en-us/100100) |
| `cisco_psirt` | `threat` | `public` | [Cisco PSIRT](https://sec.cloudapps.cisco.com/security/center/rss.x) |
| `oss_fuzz` | `threat` | `configured_url` | [OSS-Fuzz Public Disclosures](https://google.github.io/oss-fuzz/getting-started/bug-disclosure-guidelines/) |
| `exploit_db` | `threat` | `configured_url` | [Exploit-DB](https://gitlab.com/exploit-database/exploitdb) |
| `greynoise` | `threat` | `api_key` | [GreyNoise Community IP Lookup](https://docs.greynoise.io/reference/getcommunityip) |
| `urlhaus` | `threat` | `api_key` | [URLhaus](https://urlhaus.abuse.ch/api/) |
| `vulncheck` | `threat` | `api_key` | [VulnCheck KEV](https://docs.vulncheck.com/community/vulncheck-kev/schema) |
| `attackerkb` | `threat` | `api_key` | [AttackerKB](https://api.attackerkb.com/v1/api-docs/docs) |
| `packet_storm` | `threat` | `configured_url` | [Packet Storm](https://packetstorm.news/) |
| `hackerone_hacktivity` | `threat` | `import` | [HackerOne Hacktivity](https://hackerone.com/hacktivity) |
| `redhat_security` | `threat` | `configured_url` | [Red Hat Security Data](https://access.redhat.com/security/data) |
| `ubuntu_launchpad` | `threat` | `configured_url` | [Ubuntu Launchpad Security Bugs](https://bugs.launchpad.net/ubuntu) |
| `debian_tracker` | `threat` | `configured_url` | [Debian Security Tracker](https://security-tracker.debian.org/tracker/) |
| `shadowserver` | `threat` | `import` | [Shadowserver](https://www.shadowserver.org/what-we-do/network-reporting/) |
| `anyrun` | `threat` | `import` | [ANY.RUN](https://any.run/cybersecurity-blog/api-documentation/) |
| `hybrid_analysis` | `threat` | `import` | [Hybrid Analysis](https://www.hybrid-analysis.com/docs/api/v2-changelog) |
| `reddit_netsec` | `threat` | `api_key` | [Reddit r/netsec](https://support.reddithelp.com/hc/en-us/articles/16160319875092-Reddit-Data-API-Wiki) |
| `reddit_sysadmin` | `threat` | `api_key` | [Reddit r/sysadmin](https://support.reddithelp.com/hc/en-us/articles/16160319875092-Reddit-Data-API-Wiki) |
| `mastodon` | `threat` | `configured_url` | [Mastodon Public Hashtag](https://docs.joinmastodon.org/client/public/) |
| `bluesky` | `threat` | `public` | [Bluesky Public Search](https://docs.bsky.app/docs/api/app-bsky-feed-search-posts) |
| `wigle` | `hardware` | `api_key` | [WiGLE wireless observations](https://api.wigle.net/swagger) |
| `fcc_uls` | `hardware` | `configured_url` | [FCC ULS license exports](https://www.fcc.gov/wireless/universal-licensing-system) |
| `fcc_equipment` | `hardware` | `configured_url` | [FCC equipment authorization exports](https://www.fcc.gov/engineering-technology/laboratory-division/general/equipment-authorization) |
| `shodan_ics` | `hardware` | `api_key` | [Shodan industrial protocol index](https://developer.shodan.io/api) |
| `censys_devices` | `hardware` | `api_key` | [Censys indexed devices](https://docs.censys.com/reference/v3-globaldata-search-query) |
