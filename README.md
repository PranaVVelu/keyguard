# KeyGuard

Educational digital-vehicle-access security lab: ECDSA P-256 challenge-response, revocation,
replay protection and an isolated vulnerable-vs-hardened comparison. Fictional vehicles only.

**Status: MVP complete (Sprint 8 of 8).** All seven P0 features plus Security Analytics (F08) work end to end, and the
backend makes every decision:
- **Garage:** request unlock or lock and see the server's decision.
- **Digital Keys:** non-extractable browser keys, enrollment and revocation.
- **Inspector:** a step-by-step view of a real challenge-response exchange.
- **Attack Lab:** replay, tampering and signed-bytes substitution scenarios against an isolated vulnerable verifier and the real engine, side by side.
- **Security Analytics:** a searchable event log with failure categories.

The spec's 11-row mandatory test matrix passes through the real API ([latest evidence](docs/evidence/matrix-latest.md)).
Real-browser Playwright tests drive the whole journey, and all of it runs in CI.

It's ready as a **local demo**. Public hosting needs the gates in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) first, and
the usability sessions haven't been run yet. See [docs/RELEASE_GATES.md](docs/RELEASE_GATES.md) for exactly what is
and isn't met.

## Quick start

```bash
docker compose up --build      # then open http://localhost:3000
```

Then follow the [6-minute demo script](docs/DEMO.md).

## Layout

```
apps/web/          Next.js 16 + TypeScript + Tailwind
  lib/             encoding.ts (kg-auth-v1), crypto.ts (Web Crypto), keystore.ts (IndexedDB), auth-flow.ts, api.ts
  tests/           node --test (encoding vectors, Web Crypto interop, helpers, API client)
  e2e/             Playwright (owner journey, tampering, isolation, accessibility)
services/api/      FastAPI backend
  app/security/    protocol.py (kg-auth-v1 + ECDSA verify), challenges.py (atomic consume), authenticate.py (decision engine),
                   labs.py, keys.py, events.py, ratelimit.py, cleanup.py
  app/models/      DB tables, API schemas
  app/routes/      HTTP endpoints
  tests/           pytest suite
docs/              spec, review, threat model, decisions, test evidence, test vectors
```

## Setup without Docker

Requires [uv](https://docs.astral.sh/uv/) (it provides Python 3.12) and Node 24+.

```bash
cd services/api
uv sync --python 3.12
uv run pytest
uv run python -m app.evidence.matrix   # structured security matrix (spec §7)
uv run uvicorn app.main:create_app --factory --reload --port 8000
```

```bash
cd apps/web
npm install
npm test             # unit tests
npm run dev          # http://localhost:3000
npx playwright install chromium && npm run e2e   # real-browser tests (starts its own API and web server)
```

## Implemented API

| Method | Endpoint | Notes |
|--------|----------|-------|
| POST | `/api/labs` | Creates a lab and one fictional vehicle. Returns `lab_token` once. |
| GET | `/api/labs/{id}/vehicles` | Requires `Authorization: Bearer <lab_token>`. Any failure returns `404 LAB_NOT_FOUND`. |
| POST | `/api/labs/{id}/keys` | Enroll a P-256 SPKI public key for a vehicle in this lab |
| GET | `/api/labs/{id}/keys` | List key metadata (fingerprint, status; never the key bytes) |
| POST | `/api/labs/{id}/keys/{keyId}/revoke` | Revoke a credential (immediate; idempotent) |
| POST | `/api/labs/{id}/challenges` | Issue a 30-second single-use challenge for (vehicle, key, action) |
| POST | `/api/labs/{id}/authenticate` | Verify a signed challenge; returns allow/deny with a reason and a 6-step trace |
| GET | `/api/labs/{id}/scenarios` | List Attack Lab scenarios |
| POST | `/api/labs/{id}/scenarios/{scenario}` | Run vulnerable vs hardened on disposable state |
| GET | `/api/labs/{id}/lab-runs` | Scenario run history (expected vs actual per mode) |
| GET | `/api/labs/{id}/events` | Sanitized event history; filter by `category`, `result`, `reason`, `q`; paged |
| GET | `/api/labs/{id}/events/summary` | Pass/fail per category, failure reasons, authentication timing |
| GET | `/api/health` | Liveness check |

Every endpoint is rate limited (`429 RATE_LIMITED` with `Retry-After`; limits are in D-009). Expired labs are deleted by a
background cleanup task (`KEYGUARD_CLEANUP_INTERVAL`, default 300 s).

> Upgrading from an earlier sprint? The event table changed. Delete your local `keyguard.db` (lab data is disposable);
> the API refuses to start on a stale schema and tells you so.

## Docs

- [Product requirements and status](docs/PRD.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Release gates](docs/RELEASE_GATES.md)
- [Deployment](docs/DEPLOYMENT.md)
- [Demo script](docs/DEMO.md)
- [Usability and accessibility](docs/USABILITY.md)
- [Requirements review and sprint plan](docs/REQUIREMENTS_REVIEW.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Decisions](docs/DECISIONS.md)
- [Security test evidence](docs/SECURITY_TESTS.md)
- [Design direction (draft)](docs/DESIGN_DIRECTION.md)
- [Spec (PDF)](docs/KeyGuard_Product_and_Engineering_Specification.pdf)

## Limitations

A valid signature does not prove physical proximity (relay attacks are out of scope). Browser keys are not hardware-backed.
Passing the curated test suite does not prove the system is secure in general.
