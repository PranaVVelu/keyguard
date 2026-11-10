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
| `NEXT_PUBLIC_API_URL` | web (build) | `http://localhost:8000` | API base URL compiled into the bundle |

## Before any public hosting (release gate, spec §11–12)

Every item must be done and evidenced in `SECURITY_TESTS.md`:

1. **PostgreSQL:**
   - point `KEYGUARD_DATABASE_URL` at Postgres;
   - re-run the full pytest suite and the structured matrix against it;
   - prove MX-08 (concurrent submissions → at most one allow) holds there.
2. **Shared rate limiting:** move the counters to a shared store (for example Redis) before running more than one
   worker or instance.
3. **Trusted client address:** behind a proxy or CDN, derive the client key from a trusted forwarding header
   configured for that proxy only, never from a client-supplied header.
4. **TLS and headers:**
   - HTTPS only, with HSTS;
   - a Content-Security-Policy that limits scripts to the app's own origin (the lab token is in `sessionStorage`);
   - CORS restricted to the deployed web origin.
5. **Lab token design review:** the spec's open decision "auth/session design" must be revisited for a public demo
   (D-002 accepted `sessionStorage` for local and educational use only).
6. **Monitoring:**
   - alert on 5xx responses, sustained 429s and `LAB_CAPACITY`;
   - check that the cleanup loop runs (log lines `cleanup:`).
7. **Usability:** run the sessions in `USABILITY.md` and fix what they find.
8. **Wording:** keep "Fictional vehicles and simulated credentials only" visible on every page (it's in the footer).

The spec suggests Vercel for the web app and a separately hosted API. Either fits once these gates are met. Choosing a
host and creating accounts is a decision for the project owner.
