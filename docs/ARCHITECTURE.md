# KeyGuard Architecture

How the pieces fit, where every security decision is made, and why. The decisions themselves (with alternatives and
dates) are in [DECISIONS.md](DECISIONS.md), threats in [THREAT_MODEL.md](THREAT_MODEL.md), and evidence in
[SECURITY_TESTS.md](SECURITY_TESTS.md).

## Components

```
 Browser (Next.js 16, React 19)                         FastAPI service (Python 3.12)                    SQLite (WAL)
 ───────────────────────────────                        ─────────────────────────────                    ────────────
 Pages: Garage · Digital Keys · Inspector ·             middleware: per-client rate limit                labs (token hash)
        Attack Lab · Security Analytics                 routes/  labs · keys · auth · lab · events       vehicles
 lib/crypto.ts    Web Crypto P-256, non-extractable ─┐  require_lab: bearer → SHA-256 → compare_digest   digital_keys (SPKI)
 lib/keystore.ts  CryptoKey handles in IndexedDB      │             → per-lab rate limit                 challenges
 lib/encoding.ts  kg-auth-v1 signed bytes             │  security/  authenticate.py  ◀── the decision     security_events
 lib/auth-flow.ts challenge → sign → authenticate     │             challenges.py   atomic consume        lab_runs
 lib/api.ts       typed client, bearer from session ──┼─▶           protocol.py     encode + verify
 sessionStorage   lab_token (tab-scoped)              │             keys, labs, events, ratelimit, cleanup
                                                      │  lab/       vulnerable verifier (in-memory only) ─▶ temp DB per run
                                                      │  evidence/  structured matrix runner (CI)
                                                      └─ HTTP/JSON (CORS: configured web origin only)
```

## The authentication path

1. **Challenge.** The browser asks `POST /challenges` for `(vehicle, key, action)`.
   - Issuance refuses keys that obviously can't succeed: unknown, revoked or unbound.
   - It also refuses once the lab has 20 open challenges.
   - Otherwise the server stores a 32-byte nonce with a 30-second server-clock expiry.
2. **Client check.** `auth-flow.ts` refuses to sign a challenge whose vehicle, key or action differs from what the
   user asked for.
3. **Sign.**
   - `encoding.ts` builds the kg-auth-v1 bytes: a domain tag, then seven length-prefixed UTF-8 fields (D-001).
   - Web Crypto signs them with the non-extractable P-256 key, producing a 64-byte P1363 signature.
4. **Decide.** `POST /authenticate` runs `security/authenticate.py` inside **one transaction**:
   1. load the challenge (scoped by `lab_id`);
   2. **consume it with one conditional UPDATE** (`consumed_at IS NULL AND expires_at > now`), so a failed attempt
      also burns it (D-003);
   3. check the key matches the challenge's key;
   4. check the key is active and bound to the vehicle;
   5. rebuild the signed bytes **from the stored row** and verify ECDSA;
   6. only then, commit the vehicle state change.

   Deny decisions commit too (the burn and the event persist). Both allow and deny return 200 with a reason code and
   a six-step trace.
5. **Render.** The UI shows only what the response says. The car graphic, lock state and Inspector all read the
   decision.

The client never sends a lock state, a success flag or the signed bytes. The server rebuilds everything it verifies.

## Isolation boundaries

| Boundary | Mechanism | Enforced by |
|----------|-----------|-------------|
| Lab ↔ lab | Bearer token (SHA-256 stored), uniform `404 LAB_NOT_FOUND`, `lab_id` in every SQL query | matrix MX-11, `test_events_are_scoped_to_the_lab`, e2e "lab is private" |
| Vulnerable ↔ hardened code | `app/lab/` is imported only by `routes/lab.py`; vulnerable code imports no DB layer | AST import-graph test (`test_lab_isolation.py`) |
| Scenario ↔ real lab state | Scenarios run on in-memory state plus a temporary SQLite file; the lab only gets summary rows | `test_scenario_does_not_touch_the_labs_real_state` |
| Private key ↔ everything | `extractable: false`; only the SPKI is sent; strict schema rejects extra fields | e2e export attempt (`InvalidAccessError`), `test_extra_fields_such_as_private_key_are_rejected` |

## Resource controls (D-009)

These are layered so that no single client can exhaust the demo:
- **Rate limits** (the per-lab limit is counted only after authorization):
  - per client, on every request;
  - per client, on lab creation;
  - per lab.
- **Caps:**
  - 5,000 active labs;
  - 10 keys per lab;
  - 20 open challenges per lab;
  - 2,000 retained events per lab.
- **Background TTL cleanup:** labs expire after 24 hours, and dead challenges are pruned after a 5-minute grace period.

## Data model

| Table | Key columns | Notes |
|-------|-------------|-------|
| `labs` | `id`, `token_hash`, `expires_at` | Token returned once, never stored |
| `vehicles` | `id`, `lab_id`, `lock_state` | One fictional vehicle seeded per lab |
| `digital_keys` | `id`, `lab_id`, `vehicle_id`, `public_key` (SPKI DER), `fingerprint`, `status`, `revoked_at` | `UNIQUE(lab_id, fingerprint)` |
| `challenges` | `id`, `lab_id`, `vehicle_id`, `key_id`, `nonce`, `action`, `expires_at`, `consumed_at` | Single use via conditional UPDATE |
| `security_events` | `seq` (order), `id`, `lab_id`, `event_type`, `outcome`, `reason`, `duration_ms` | IDs and reason codes only (T11) |
| `lab_runs` | `id`, `lab_id`, `scenario`, `mode`, `expected_result`, `actual_result` | Attack Lab history |

## Testing layers

| Layer | Tool | What it proves |
|-------|------|----------------|
| Protocol | pytest + shared vectors (`docs/test-vectors/`) | Python and Web Crypto produce and verify identical bytes and signatures |
| Engine and API | pytest (215 tests) | All 11 mandatory matrix rows, concurrency, isolation, limits, cleanup |
| Structured evidence | `app.evidence.matrix` | Spec §7 evidence format, failure classification; fails CI on any non-pass |
| Client logic | node:test (50 tests) | Encoding, Web Crypto interop, byte annotation, query building, API client errors |
| Real browser | Playwright (7 tests) | Full owner journey, in-flight tampering, tab-scoped labs, expiry notice, WCAG A/AA scan, keyboard-only use |
| Packaging | CI `docker` job | Images build, the stack becomes healthy, and lab isolation holds through the containers |

## Known architectural limits

- SQLite only. PostgreSQL is the documented hosted target, but concurrency must be re-verified on it first.
- Rate-limit counters are per process, and the client address is the direct peer (D-009).
- The lab token lives in `sessionStorage`, so any script on the origin can read it. This is an accepted demo limitation
  (D-002 / O-3).
- There are no migrations: a stale schema is refused, and lab data is disposable.
