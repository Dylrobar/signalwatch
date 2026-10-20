# HTTP technology fingerprints

SignalWatch's existing `web` collector now extracts structured technology evidence from HTTP headers, cookie names, script URLs, meta tags, HTML attributes and selected page signatures. It also parses Content-Security-Policy host sources to record possible SaaS integrations. This runs inside the existing Render process and SQLite database, using the same HTTP proxy routing, robots checks, rate limits, queue, refresh schedule and collection controls.

Run **Public websites and DNS** from the collection controls, or use `signalwatch collect --sources web`. Official company websites and scoped certificate-discovered subdomains already enter this bounded queue. Each cycle obeys `crawl_batch`, `crawl_pages`, `crawl_depth`, `concurrency` and `crawl_interval_hours`. A completed web cycle does not mean every known domain was revisited.

## Evidence and matching

The company technology view and evidence drawer distinguish:

- **HTTP detection:** a signature matched the fetched response. An observed version is shown only when a version was extracted from that signature.
- **Implied dependency:** a possible dependency inferred from another detected technology. It has no observed version and creates no deployment observation.
- **CSP allowlist hint:** a service hostname allowed by a CSP directive. An allowlist entry does not establish that the service is used or installed. It creates no deployment observation.

Fingerprints retain their source URL, observation times, method, signal type, evidence snippet and relevant dependency/CSP provenance. Cookie evidence and its HTTP cache metadata retain names only, never cookie values. Revalidated responses preserve names and repeated CSP headers. A new response replaces the previous page's current evidence.

Only direct signatures with a curated CPE identity join domain observations used by the existing CVE matcher. Generic Java session cookies do not establish Tomcat, Next.js does not establish a Node.js server, and browser SDK versions do not become versions of a vendor's server product. A potential advisory match still requires review; the header or page may describe a reverse proxy or bundled client resource.

Company evidence follows existing included-asset decisions. Discovered subdomains remain candidates until attributed; their HTTP evidence is linked to the domain in the graph and does not automatically raise company risk. Redirect destinations are attributed using their own host, not the company associated with the starting URL.

## Larger fingerprint catalog

`web_fingerprint_catalog` defaults to `true` in server configuration. The worker loads the [ProjectDiscovery Wappalyzer catalog](https://github.com/projectdiscovery/wappalyzergo/blob/main/fingerprints_data.json) through the shared HTTP client and retains a validated local copy for offline use. Refresh checks are daily. Set `"web_fingerprint_catalog": false` in `config.json` and restart to use only the bundled curated rules.

The catalog has thousands of technology definitions; this integration supports the passive HTTP vectors available without executing JavaScript. It does not run a headless browser. Unsupported browser-only vectors, invalid patterns, evaluation time limits and fallback state are included in collection diagnostics. Download, rule, output and regex-runtime limits keep collection bounded.

Catalog detections supplement the evidence view. Their CPE strings are not promoted automatically into CVE matching. Bundled curated detections continue when catalog refresh fails. Source attribution and catalog digest remain available for review. ProjectDiscovery distributes its catalog under the [MIT license](https://github.com/projectdiscovery/wappalyzergo/blob/main/LICENSE.md).
