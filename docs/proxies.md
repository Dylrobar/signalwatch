# Optional proxies for public HTTP collection

Configure proxies on the server running the Python worker. Credentials belong in
Render's environment secrets or a local private environment, never in the browser,
Lovable frontend variables, tracked configuration, API payloads, or a proxy URL.
The API does not need these credentials to receive worker results.

Set **one** of these environment variables:

```sh
# Small lists can be supplied directly as JSON.
SIGNALWATCH_PROXY_LIST_JSON='["proxy-a.example.test:8080","https://proxy-b.example.test:8443"]'
```

Or upload a private JSON file to the worker and configure its absolute path:

```sh
SIGNALWATCH_PROXY_LIST_FILE='/path/to/private/proxies.json'
```

The file can contain the provider's exported list, using `entryPoint` and `port`:

```json
[
  {"entryPoint": "proxy-a.example.test", "port": 8080, "ip": "192.0.2.10", "countryCode": "US"},
  {"entryPoint": "proxy-b.example.test", "port": 8081, "ip": "192.0.2.11", "countryCode": "US"}
]
```

`ip` and `countryCode` describe the provider's exit address and are ignored when
connecting. The client connects to `entryPoint:port`. Lists may also mix these
objects with HTTP(S) proxy URL strings. Scheme-free strings require a port;
explicit HTTP(S) URLs default to port 80 or 443. URLs must have no credentials,
path (including a trailing slash), query, or fragment. Only HTTP(S) proxies are
supported. The list must have 1–256 entries and be at most 256 KiB; duplicate
endpoints are removed after normalization.

If authentication is required, set both secrets separately:

```sh
SIGNALWATCH_PROXY_USERNAME='<provider-username>'
SIGNALWATCH_PROXY_PASSWORD='<provider-password>'
```

Use the complete proxy authentication username required by your provider.
Oxylabs ISP usernames require the `user-` prefix; include it in
`SIGNALWATCH_PROXY_USERNAME` (for example, `user-<provider-username>`).
SignalWatch sends this value unchanged.

Docker Compose passes these four variables and `SIGNALWATCH_PROXY_DIRECT_HOSTS`
into the service. Export them before starting Compose; a file path must refer to
a file inside the container, such as
`/data/proxies.json` on the existing persistent data mount. On Render, add the
JSON list and both credential variables to the service environment.

Restart the worker after changing its environment. With the proxy list and
credential variables unset, the existing HTTP connection behavior is unchanged.
An invalid or incomplete configuration fails closed with a sanitized error.

## Direct routes for official government feeds

When a proxy pool is configured, SignalWatch connects directly to these exact
hosts by default:

- `www.cisa.gov`
- `nvd.nist.gov`
- `services.nvd.nist.gov`

These public publisher routes are selected before sending a request. They retain
HTTPS certificate verification, origin concurrency limits, caching, and cooldowns,
and never send the pool's proxy credentials. This prevents public CISA and NVD
feeds from being sent through a provider that restricts government destinations.
Oxylabs documents [government sites as restricted ISP proxy targets](https://developers.oxylabs.io/products/proxies/isp-proxies/restricted-targets)
and [gateway `403` as a restricted-target denial](https://developers.oxylabs.io/products/proxies/isp-proxies/response-codes).
Using the proxy for these targets requires the provider's approval; rotating
ports does not resolve that restriction.

To replace the default direct routes, supply comma-separated exact hostnames:

```sh
SIGNALWATCH_PROXY_DIRECT_HOSTS='www.cisa.gov,nvd.nist.gov,services.nvd.nist.gov'
```

Names are normalized for case, IDNA, and a trailing dot. The setting accepts IP
literals, but no URLs, ports, credentials, paths, or wildcards. Empty comma entries
are ignored. A hostname applies to that host's requests; it does not match parent
domains, subdomains, or names that merely end with the same text. An override
replaces the entire default set. To require the configured proxy for every host,
explicitly set `SIGNALWATCH_PROXY_DIRECT_HOSTS=''`.

The route is checked again at every redirect. A direct request that redirects to
another host uses that host's configured route. Direct requests remain available
while the proxy pool is cooling down or has rejected authentication. Direct
failures do not rotate or disable proxy endpoints.

These are chosen routes, not automatic fallbacks. A request assigned to the proxy
never switches to direct access after a proxy error. A direct request also never
switches to a proxy after an origin denies access. Unknown hosts continue to use
the configured proxy, and neither route bypasses source access or rate limits.

## Rotation, failures, and rate limits

New requests assigned to the proxy select endpoints in round-robin order.
Transient transport failures may try another available endpoint within the request's existing retry
budget; failed endpoints cool down for 60 seconds. If all usable endpoints are
cooling down, the request reports unavailability and the earliest remaining
cooldown. Proxy authentication rejection disables that client's pool until it is
recreated with corrected credentials. Proxy denials fail without rotation.
When a proxy gateway reports a `429` throttle, a `403` with `Retry-After`, or a
transient gateway failure with `Retry-After`, its cooldown applies to the entire
pool, so another port cannot bypass the provider's limit. Requests already waiting to retry recheck pool
availability before making another attempt. Gateway deadlines persist in the
shared cache across new client instances and worker restarts. Their cache markers
contain only a deadline and HTTP status, keyed by a hash of normalized endpoints.

Origin responses `429`, `502`, `503`, and `504` retain the same proxy for that
request's retries. The collector honors `Retry-After` and shares destination host
cooldowns and concurrency limits across proxies, including every redirect hop.
Redirects are bounded and drop origin authorization and explicit cookie headers
when crossing origins. Origin `401`, `403`, and `404`
fail immediately: fix the source API credentials, access permission, or URL.
For rate-limited `403` responses, the collector also records `Retry-After` or
`X-RateLimit-Reset` when present. Origin cooldowns are saved in the worker's cache
directory so creating a new HTTP client or restarting the worker does not erase
them; keep that cache on persistent storage to retain them across deployments.
Rotating proxies does not repair missing endpoints or invalid source credentials
and does not bypass denied access or source rate limits.

Proxy use is restricted to the Python public HTTP client. It does not proxy
browser traffic, incoming API connections, native DNS queries, or other network
tools. HTTPS certificate verification remains enabled. Proxy credentials are
passed separately as HTTP proxy authentication and are omitted from endpoint
representations and configuration diagnostics.
