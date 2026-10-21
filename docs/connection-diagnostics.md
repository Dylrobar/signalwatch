# Render and Lovable connection

Backend: `https://signalwatch-2ssi.onrender.com` (no `/api` suffix).
The active UI is Dylrobar/signalwatch-early-warning; this repository's frontend is legacy.

Docker runs `signalwatch --config /data/config.json runtime --host 0.0.0.0`.
`PORT` overrides the configured port for both runtime and serve; explicit `--port` wins.
Render healthCheckPath is `/health`. No nginx/CORS proxy is needed.

Set `SIGNALWATCH_CORS_ORIGINS` to:

```text
https://*.lovable.app,https://*.lovableproject.com
```

Append exact custom domains, e.g. `,https://intel.example.com`. These two HTTPS
preview patterns are the only supported wildcards. They allow any subdomain on
those shared platforms, so keep Bearer authentication enabled. For a narrower
policy use exact preview origins instead. Apex domains, arbitrary wildcard
patterns, HTTP previews, paths, and nondefault ports are not matched.
CORS responses echo one matching origin and include `Vary: Origin`.
OPTIONS preflight does not require a token. Disallowed origins/methods/headers
return JSON 403. Browsers cannot read the JSON for a disallowed origin; use this
script or curl to distinguish it from ingress/network failure. A valid origin
receives readable JSON 401 for missing/invalid credentials.

```bash
BASE=https://signalwatch-2ssi.onrender.com
ORIGIN=https://id-preview--c29cd860-16f8-4211-875c-c8a919c3dda2.lovable.app
curl --max-time 120 -i "$BASE/health" -H "Origin: $ORIGIN"
curl --max-time 120 -i -X OPTIONS "$BASE/api/status" \
  -H "Origin: $ORIGIN" -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Headers: authorization'
read -rs -p 'API token: ' SIGNALWATCH_API_TOKEN
export SIGNALWATCH_API_TOKEN
curl --max-time 120 -i "$BASE/api/status" -H "Origin: $ORIGIN" \
  -H "Authorization: Bearer $SIGNALWATCH_API_TOKEN"
python scripts/check_connection.py --base "$BASE" --origin "$ORIGIN"
unset SIGNALWATCH_API_TOKEN
```

Expected: all three return 200 and exactly one Access-Control-Allow-Origin
matching ORIGIN. Without the token, `/api/status` should return 401 when auth is
configured. A 502/503/504 may indicate startup or ingress; missing/duplicate
CORS headers indicate policy or a second header-injecting proxy.

The active frontend handshake transitions from checking health to retrying
health (network, 502/503/504 only), then checking API authentication, then
connected or an explicit error. Four health attempts, each capped at 25 seconds,
with two-second retry delays share a 120-second overall deadline. Invalid
responses and auth failures are not retried; mutations are never retried by
this handshake. Closing/editing cancels the attempt. Only a successful health
and status handshake saves the connection. Errors retain the inputs for retry.
