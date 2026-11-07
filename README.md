# KeyGuard

Educational digital-vehicle-access security lab: ECDSA P-256 challenge-response, revocation,
replay protection and an isolated vulnerable-vs-hardened comparison. Fictional vehicles only.

**Status: Sprint 4: core test suite passing.** The browser enrolls a non-extractable key and signs a server
challenge, and the backend verifies and decides. Credentials can be revoked. All 11 rows of the spec's mandatory
test matrix pass through the real API, and a structured runner records the evidence on every CI run
([latest](docs/evidence/matrix-latest.md)).
See [docs/SECURITY_TESTS.md](docs/SECURITY_TESTS.md) for exactly what is and isn't proven.

## Layout

```
apps/web/          Next.js 16 + TypeScript + Tailwind
  lib/             encoding.ts (kg-auth-v1), crypto.ts (Web Crypto), keystore.ts (IndexedDB), auth-flow.ts, api.ts
  tests/           node --test (encoding vectors, Web Crypto interop)
services/api/      FastAPI backend
  app/security/    protocol.py (kg-auth-v1 + ECDSA verify), challenges.py (atomic consume), authenticate.py (decision engine), labs.py, keys.py
  app/models/      DB tables, API schemas
  app/routes/      HTTP endpoints
  tests/           pytest suite
docs/              spec, review, threat model, decisions, test evidence, test vectors
```

## Setup

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
npm test             # TS encoder + Web Crypto tests
npm run dev          # http://localhost:3000
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
| GET | `/api/health` | Liveness check |

Not implemented yet: events API, attack-lab scenarios (Sprint 5).

## Docs

- [Requirements review and sprint plan](docs/REQUIREMENTS_REVIEW.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Decisions](docs/DECISIONS.md)
- [Security test evidence](docs/SECURITY_TESTS.md)
- [Design direction (draft)](docs/DESIGN_DIRECTION.md)
- [Spec (PDF)](docs/KeyGuard_Product_and_Engineering_Specification.pdf)

## Limitations

A valid signature does not prove physical proximity (relay attacks are out of scope). Browser keys are not hardware-backed.
Passing the curated test suite does not prove the system is secure in general.
