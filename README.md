# GraphQL Security Suite

A web app for security-testing GraphQL endpoints. One app, several modes:

- **Dashboard** — live, animated security posture (score + tests-passed gauges, findings by
  severity, control-area pass rates, observed hosts, scan timeline).
- **Target** — define the base request (paste a raw HTTP request or fill the structured form).
  Every test derives its probes from this one request, so authenticated endpoints work.
- **Scanner** — 61 tests across 16 control areas (schema discovery, auth, authorization,
  field-level authz, input/injection, mutations, DoS, data exposure, subscriptions, business
  logic, file upload, SSRF, config/transport, CORS/CSRF, external deps, logging/audit).
- **Repeater** — edit and resend a request; inspect the response and query metrics.
- **Analyzer** — static analysis of a schema (SDL or introspection JSON) + recover operations
  from a client JS bundle. No live target needed.
- **Proxy** — forward GraphQL traffic through the suite and watch each query's depth, complexity,
  aliases and batch size live.
- **Report** — every finding with **evidence** (request+response), a **recommendation/fix**,
  **criticality** (severity + CVSS 3.1), and **CWE** (always) / **CVE** (when the fingerprint
  matches a known advisory). Exports to Markdown and self-contained HTML.

> **Authorized testing only.** Active scanning sends real probes (bounded DoS, injection and CSRF
> checks). Only test endpoints you own or are explicitly permitted to test. An authorization
> acknowledgement is required before any scan runs.

## Prerequisites (on any machine)

Either:

- **Node.js 24+** and npm (for local dev / running directly), **or**
- **Docker** + Docker Compose (to run it containerised — no Node needed).

## Clone and run on another machine

```bash
git clone <your-repo-url>
cd <repo-folder>
```

### Option A — Node (dev, hot reload)

```bash
npm install
npm run dev
```

- Frontend: http://localhost:5173
- API: http://localhost:8787 (Vite proxies `/api` and `/proxy` to it)

### Option B — Node (single process, production mode)

```bash
npm install
npm run build        # builds the frontend into web/dist
npm start            # server serves the built app
```

Then open http://localhost:8787.

### Option C — Docker (no Node required)

```bash
docker compose up --build
```

Then open http://localhost:8787 (the server serves the built frontend in production).

> Windows note: the dev server runs on Node via `tsx`; no global installs are needed beyond
> Node/npm. If port 8787 or 5173 is busy, set `PORT` (server) or edit `web/vite.config.ts`.

## Tests

```bash
npm test
```

Covers the raw-HTTP request parser (including the sample authenticated request), the request-model
variants, the schema analyzer, JS-source extraction and query complexity metrics.

## Notes

- The server runs on Node 24 via `tsx` (dev and prod); the frontend is built with Vite.
- Geolocation of hosts is best-effort and offline; local/private targets aren't plotted, and no
  external IP lookup runs by default, so no fake points are shown.
- The proxy observes traffic; it does not block it in this version.
- No login on the app itself (single local user).
