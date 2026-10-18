# SignalWatch frontend

React/TanStack dashboard for the Python API in this repository. The tested fixes are included directly; no patch step is required. This checkout is standalone and has not been linked to Lovable Git sync.

## Run locally

Use a current Bun release with the committed lockfile. The source was also checked with Node 22.

```bash
bun install --frozen-lockfile
bun run dev --host 127.0.0.1 --port 5174
```

Open http://127.0.0.1:5174. Start the Python backend separately using the root README. No collection or database runs in this frontend.

## Connect a backend

1. Run the Python service locally or host it behind HTTPS.
2. Set `SIGNALWATCH_CORS_ORIGINS` on that service to the frontend's exact origin, such as `http://127.0.0.1:5174` for development. Multiple origins are comma-separated, without paths or wildcards.
3. Optionally set `SIGNALWATCH_API_TOKEN`. Every `/api/*` request then requires the same Bearer token; `GET /health` remains public.
4. Open **Connection settings**, enter the backend base URL without `/api`, and the optional token. **Test connection** checks health and authorization; **Save & connect** also verifies both before saving.

The URL is kept in localStorage. The token stays in memory or, if selected, sessionStorage for that browser tab. HTTP is accepted only for localhost, meaning the machine running the browser. Backend path prefixes are preserved for requests and authenticated exports.

## Checks and build

```bash
bun run test
bunx tsc --noEmit
bun run build
```

The build generates Nitro/Cloudflare output under `.output/`. The generated template's current `preview` command looks for `dist/server/server.js`, which is not emitted by this configuration; use the development command above for local browser work. Production build success does not configure hosting or Lovable synchronization.

The frontend was checked with strict TypeScript, 12 unit tests, real HTTP responses from the Python service, and desktop/mobile Chromium interactions. The dashboard has six views: Intelligence, Warnings, Infrastructure, News, Changes, and Collectors. Empty or disconnected states show the backend's actual state, and warnings remain potential correlations with their evidence.
