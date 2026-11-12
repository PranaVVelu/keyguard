# Deployment

KeyGuard is **local-first** (spec §12: "deploy only after security controls and tests"). This page covers the
supported local run and the checklist that has to be completed before any public hosting. **Nothing has been
deployed publicly.**

## Local: one command (Docker)

```bash
docker compose up --build
# web: http://localhost:3000   api: http://localhost:8000/api/health
```

- The API runs as an unprivileged user with **one worker**, because rate-limit counters are per process. Its SQLite
  database lives in the `keyguard-data` volume.
- The API URL is compiled into the web bundle (`NEXT_PUBLIC_API_URL` build argument).
- CI (`docker` job) builds both images, waits for both health checks, and smoke-tests the stack: create a lab, read it
  with the token, and get a 404 without it.

## Local: without Docker

See the README. In short: `uv sync` plus `uvicorn` for the API, and `npm install` plus `npm run dev` for the web app.

## Configuration

| Variable | Service | Default | Purpose |
|----------|---------|---------|---------|
| `KEYGUARD_DATABASE_URL` | api | `sqlite:///./keyguard.db` | SQLAlchemy URL |
| `KEYGUARD_WEB_ORIGIN` | api | `http://localhost:3000` | CORS allow-list (comma-separated) |
| `KEYGUARD_CLEANUP_INTERVAL` | api | `300` | Seconds between TTL cleanup passes (`0` = off) |
| `KEYGUARD_RATE_CLIENT` | api | `600/60` | Per-client limit on every request (`N/seconds` or `off`) |
| `KEYGUARD_RATE_LAB_CREATE` | api | `20/60` | Per-client lab creation limit |
| `KEYGUARD_RATE_LAB` | api | `120/60` | Per-lab limit (counted after authorization) |
| `KEYGUARD_RP_ID` | api | `localhost` | WebAuthn relying-party ID: the site's registrable domain |
| `KEYGUARD_COOKIE_SECURE` | api | unset | Set to `1` behind HTTPS so the session cookie gets `Secure` |
| `KEYGUARD_RATE_AUTH` | api | `30/60` | Per-client limit on the passkey endpoints |
| `KEYGUARD_ENV` | api | `development` | `production` turns on the startup safety check |
| `KEYGUARD_RATE_STORE` | api | `memory` | `database` shares counters across workers and instances |
| `KEYGUARD_TRUSTED_PROXIES` | api | unset | IPs and CIDRs whose `X-Forwarded-For` is believed |
| `KEYGUARD_PROXY_SECRET` | api, web | unset | Shared secret for the web app's `/api` proxy (free-subdomain mode, D-013) |
| `KEYGUARD_API_INTERNAL_URL` | web | unset | Where the web proxy forwards `/api/*` (e.g. `https://keyguard-api.onrender.com`) |
| `KEYGUARD_CLIENT_IP_HEADER` | web | `x-real-ip` | Platform header carrying the visitor's IP |
| `KEYGUARD_WORKERS` | api (container) | `1` | uvicorn workers (safe above 1 with the database rate store) |
| `KEYGUARD_HSTS` | api, web (build) | unset | `1` adds Strict-Transport-Security |
| `NEXT_PUBLIC_API_URL` | web (build) | `http://localhost:8000` | API base URL compiled into the bundle |

## Free hosting (no domain needed)

Step-by-step guide: **[DEPLOY_FREE.md](DEPLOY_FREE.md)** (Vercel + Render + Neon, with a `render.yaml` blueprint).

## Before any public hosting (release gate, spec §11–12)

Status after Sprint 11 (D-013). ✅ means done and evidenced in `SECURITY_TESTS.md`. ☐ means it needs a host or a person.

| # | Gate | Status |
|---|------|--------|
| 1 | **PostgreSQL**: full suite and matrix (incl. MX-08 concurrency) pass on it | ✅ CI job `api-postgres` (Postgres 17) on every push; [matrix evidence](evidence/matrix-postgres.md). Fixed two PostgreSQL-only bugs (32-bit columns, racing limit checks) |
| 2 | **Shared rate limiting** across workers and instances | ✅ `KEYGUARD_RATE_STORE=database` (atomic upsert, hashed keys) |
| 3 | **Trusted client address** behind a proxy or CDN | ✅ `KEYGUARD_TRUSTED_PROXIES`; `X-Forwarded-For` is read only from trusted peers, right to left |
| 4 | **TLS and headers**: HSTS, CSP, CORS limited to the web origin | ✅ Headers on both apps; HSTS with `KEYGUARD_HSTS=1`. TLS itself comes from the host. CSP keeps `'unsafe-inline'` scripts for now (D-013) |
| 5 | **Lab token design review** | ✅ Reviewed (D-013): `sessionStorage` kept, with the CSP limiting exfiltration. Cookie-based lab tokens are a follow-up |
| 6 | **Monitoring** | ◐ `/api/health` checks the database (503 if it's down). Alerting on 5xx, sustained 429s and `LAB_CAPACITY` is set up on the host |
| 7 | **Usability sessions** (`USABILITY.md`) | ☐ Needs participants |
| 8 | **Accounts**: same site, RP ID, secure cookie | ✅ Enforced at startup by the production check; the deployment must put web and API on one site |
| 9 | **Wording**: the "fictional" disclaimer is on every page | ✅ Footer |

### Production environment (the API refuses to start without these when `KEYGUARD_ENV=production`)

```bash
KEYGUARD_ENV=production
KEYGUARD_DATABASE_URL=postgresql+psycopg://USER:PASSWORD@HOST:5432/keyguard
KEYGUARD_WEB_ORIGIN=https://app.example.com
KEYGUARD_RP_ID=example.com
KEYGUARD_COOKIE_SECURE=1
KEYGUARD_HSTS=1
KEYGUARD_RATE_STORE=database
KEYGUARD_TRUSTED_PROXIES=10.0.0.0/8      # the host's load-balancer range, OR:
KEYGUARD_PROXY_SECRET=<32+ random chars>  # free-subdomain mode: only the web app's /api proxy may call the API
```

Web build: `NEXT_PUBLIC_API_URL=https://api.example.com` and `KEYGUARD_HSTS=1`.

The spec suggests Vercel for the web app and a separately hosted API. Either fits once these gates are met. Choosing a
host and creating accounts is a decision for the project owner.
