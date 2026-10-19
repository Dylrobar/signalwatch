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

Docker Compose passes these four variables into the service. Export them before
starting Compose; a file path must refer to a file inside the container, such as
`/data/proxies.json` on the existing persistent data mount. On Render, add the
JSON list and both credential variables to the service environment.

Restart the worker after changing its environment. With all four variables unset,
the existing HTTP connection behavior is unchanged. An invalid or incomplete
configuration fails closed with a sanitized error. A configured pool never
silently falls back to a direct connection.

New public HTTP requests select proxies in round-robin order. Transient transport
failures may try another available endpoint within the request's existing retry
budget; failed endpoints cool down for 60 seconds. If all usable endpoints are
cooling down, the request reports unavailability and the earliest remaining
cooldown. Proxy authentication rejection disables that client's pool until it is
recreated with corrected credentials. Proxy denials fail without rotation.
When a proxy gateway reports a `429` throttle or a transient gateway failure with
`Retry-After`, its cooldown applies to the entire pool, so another port cannot
bypass the provider's limit. Requests already waiting to retry recheck pool
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
