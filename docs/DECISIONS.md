# KeyGuard — Decision Record

Status legend: **PROPOSED** (awaiting agreement) · **ACCEPTED** · **SUPERSEDED**

The spec (§13) requires agreement on D-001 (signed-message encoding) and D-002
(lab authorization) before code is written. Everything here is proposed until marked otherwise.

---

## D-001 Canonical signed-message encoding (v1) — ACCEPTED (2026-11-05)

**Goal:** domain-separated, unambiguous bytes that the browser (Web Crypto) and the
server (Python `cryptography`) produce identically, with no JSON canonicalization edge cases.

**Format:** a fixed domain tag followed by a fixed, ordered list of length-prefixed fields.

```
message = DOMAIN_TAG || field_1 || field_2 || ... || field_7
DOMAIN_TAG = ASCII "KEYGUARD-AUTH" || 0x00 || 0x01        (tag, NUL separator, format version byte)
field_i    = u32_be(len(bytes_i)) || bytes_i               (bytes_i is UTF-8)
```

| # | Field             | Value / representation                                         |
|---|-------------------|----------------------------------------------------------------|
| 1 | protocol_version  | `"kg-auth-v1"`                                                 |
| 2 | vehicle_id        | opaque server ID string (e.g. `veh_` + 22 base64url chars)     |
| 3 | key_id            | opaque server ID string (`key_…`)                              |
| 4 | challenge_id      | opaque server ID string (`chl_…`)                              |
| 5 | nonce             | 32 random bytes, sent and signed as **unpadded base64url** text |
| 6 | action            | `"unlock"` or `"lock"` (closed enum)                           |
| 7 | expires_at        | integer Unix seconds as base-10 ASCII, no sign/leading zeros   |

Rules:
- Fields are never concatenated without the length prefix (spec §5 invariant).
- The server **rebuilds** the message from its stored challenge row; it never verifies bytes the client sends it.
  The client returns only `challenge_id`, `key_id` and `signature`.
- Any change to field order, count or representation bumps the version byte and `protocol_version`.

**Signature:** ECDSA P-256 / SHA-256. Web Crypto emits IEEE P1363 raw `r||s` (64 bytes);
the wire format is that, base64url. The server checks length == 64, rejects r or s = 0 or ≥ n,
converts to DER, and verifies with `cryptography`. Signature malleability (high/low-S) is harmless here
because single-use is enforced by challenge ID, not by signature uniqueness. This is stated so nobody
"fixes" it later by deduplicating signatures.

**Public key:** SPKI DER, base64url. (Web Crypto can export the public half as `spki` even when the
private key is non-extractable.) The server parses it, requires curve SECP256R1, and stores the SPKI
plus a SHA-256 fingerprint for display.

**Test vectors:** Web Crypto ECDSA is randomized, so vectors are
(a) canonical-bytes vectors: field inputs → exact hex, checked by both Python and TS tests; and
(b) verify-only vectors: fixed public key + message + signature → expected accept/reject.
Stored in `docs/test-vectors/kg-auth-v1.json`, shared by both test suites.

**Rejected alternatives:** JSON + RFC 8785 JCS (more surface, number/Unicode edge cases);
delimiter-joined strings (ambiguous framing, explicitly disallowed by spec).

---

## D-002 Lab authorization — ACCEPTED (2026-11-05)

- `POST /api/labs` creates a lab and returns `{lab_id, lab_token, expires_at}` **once**.
- `lab_token` = 32 bytes from `secrets.token_bytes`, base64url. The server stores only `SHA-256(token)`.
- Every `/api/labs/{id}/…` request needs `Authorization: Bearer <lab_token>`. The server hashes it and
  compares with `hmac.compare_digest` against that lab's stored hash.
- **Unknown lab, wrong token and expired lab all return the same `404 LAB_NOT_FOUND`**, so the API
  can't be used to discover which lab IDs exist (cross-lab threat T7).
- Lab TTL: 24 h. Expired labs and everything in them are deleted by a cleanup task.
- Every query filters by `lab_id` in SQL, as well as in route checks (defense in depth). Vehicle, key and
  challenge lookups always use `WHERE id = ? AND lab_id = ?`.
- Browser storage: token kept in `sessionStorage` (cleared when the tab closes). This is an accepted
  limitation of an educational demo, not a production session design. **ACCEPTED (O-3, 2026-11-05).**
- No user accounts in MVP (F12 is P2).

---

## D-003 Challenge lifecycle and atomic consumption — ACCEPTED (2026-11-05)

- Challenge TTL: **30 seconds**, set and enforced by the server clock only. The `expires_at` in the
  signed message binds the client to the same value, but the server checks the stored row.
- Authenticate flow (hardened):
  1. Load the challenge by `(challenge_id, lab_id)` → else `CHALLENGE_NOT_FOUND`.
  2. Request `key_id` must equal `challenge.key_id` → else `KEY_MISMATCH`.
  3. Key must exist in lab, be `active`, and be bound to `challenge.vehicle_id` → `KEY_UNKNOWN` / `KEY_REVOKED` / `VEHICLE_MISMATCH`.
  4. Rebuild canonical bytes from the row and verify the signature → `SIGNATURE_INVALID`.
  5. In **one transaction**: `UPDATE challenges SET consumed_at = :now WHERE id = :id AND lab_id = :lab
     AND consumed_at IS NULL AND expires_at > :now`. Rowcount must be 1, else
     `CHALLENGE_CONSUMED` / `CHALLENGE_EXPIRED`. Then update the vehicle lock state and write the event. Commit.
- **Burn on failure (recommended):** any authenticate attempt that reaches step 2 for a valid
  challenge consumes it, even if it fails later, so each challenge gets one attempt. **ACCEPTED (O-2, 2026-11-05).**
- **As built (Sprint 3), `app/security/authenticate.py`:** load challenge → **consume immediately**
  (conditional UPDATE) → key matches challenge → key active and bound → verify signature → update vehicle.
  All of this runs in one transaction. Denies still commit, so the burn and the event persist; only an allow
  changes vehicle state. A request rejected *before* the engine (bad lab token, schema error) doesn't burn
  the challenge.
- `/authenticate` returns **200 for both allow and deny**: a deny is a decision, not a transport error.
- The client refuses to sign a challenge whose vehicle, key or action differs from what the user asked for
  (`apps/web/lib/auth-flow.ts`).
- Per-lab cap of 20 open (unconsumed, unexpired) challenges → 429 `CHALLENGE_LIMIT_REACHED`.
- Revocation takes effect immediately: a challenge issued before revocation fails at step 3.
- Expiry and consumption are checked inside the conditional UPDATE, so there is no gap between
  checking and consuming (TOCTOU).

---

## D-004 Identifiers — ACCEPTED (2026-11-05)

Opaque, prefixed, 128-bit random IDs (`veh_`, `key_`, `chl_`, `lab_`, `evt_`), base64url.
No sequential integers are exposed via the API.

---

## D-005 Vulnerable verifier isolation — ACCEPTED (implemented Sprint 5, 2026-11-06)

As built:
- `app/lab/vulnerable/verifier.py` is in-memory only. It verifies real signatures but never consumes challenges
  or checks expiry.
- `app/lab/scenarios.py` runs each scenario twice on **disposable** state: the vulnerable verifier in memory, and the
  **real** hardened engine against a temporary SQLite file that's deleted afterwards. The caller's lab DB only gets
  the `lab_runs` summary rows.
- `tests/test_lab_isolation.py` builds a static import graph and enforces:
  - nothing in `app.security.*` or the auth/keys/labs routes reaches `app.lab` transitively;
  - only `app.routes.lab` imports `app.lab`, and only via `app.lab.scenarios`;
  - the vulnerable package imports no DB layer.
- Scope (Sprint 5): replay only (F05, P0). Tampering scenarios are F09 (P1) and wait until all P0 features are done (spec scope rule).
- 2026-11-09: added the `tamper` scenario (F09). Both verifiers are expected to deny with `SIGNATURE_INVALID`,
  because both rebuild the signed bytes from their stored challenge. Each scenario now carries its own
  `attack_label`, `mode_notes` and `takeaway`, so the UI no longer hard-codes replay copy.
- 2026-11-09: added the `substitute` scenario. Its vulnerable side is a second class, `ClientBytesVerifier`
  (`app/lab/vulnerable/client_bytes.py`), which enforces single use but verifies the signature over signed bytes the
  client sends and acts on their action. Expected: vulnerable `allow`, hardened `deny · SIGNATURE_INVALID`. It shows
  why D-001 rebuilds the bytes from the challenge row. The production `/authenticate` schema has no field for signed
  bytes, and a test checks that sending one is a `422`.

---

## D-006 Tooling — ACCEPTED (2026-11-05)

- Python **3.12** — **ACCEPTED (O-1, 2026-11-05).** Installed as CPython 3.12.16 via uv 0.13.7
  (`~/.local/bin`), since Homebrew isn't present. The backend venv is created with `uv venv --python 3.12`.
- Backend: FastAPI, Pydantic v2, SQLAlchemy 2.x Core, `cryptography`, pytest.
- Frontend: Next.js (App Router), TypeScript strict, Tailwind; npm (already installed).
- SQLite with `BEGIN IMMEDIATE` for writes locally; the conditional-UPDATE pattern ports unchanged to PostgreSQL.
- No Docker requirement for Sprint 1 (Docker is not installed); `docker-compose.yml` comes later.
  **Sprint 8:** `docker-compose.yml` and Dockerfiles added. They're verified in CI (Docker still isn't installed locally).
- **Sprint 8:** Playwright 1.56 (Chromium) for end-to-end tests and `@axe-core/playwright` for WCAG scans.

---

## D-007 Browser key lifecycle — ACCEPTED (2026-11-05, Sprint 2)

Resolves review item 11 (spec §12 "browser key persistence").

- Keys are generated with `crypto.subtle.generateKey({ECDSA, P-256}, extractable=false, ["sign","verify"])`.
  The private key can't be exported by any code, including KeyGuard's own (verified in Chromium:
  `exportKey("pkcs8"|"jwk")` → `InvalidAccessError`).
- Only the SPKI public key is sent. `POST /keys` uses a strict schema, so a stray `private_key` field
  is rejected with 422 instead of being ignored.
- The private `CryptoKey` handle is stored in **IndexedDB** (`keyguard` / `device-keys`), keyed by `key_id`
  and tagged with `lab_id`. IndexedDB stores the opaque handle, so the key survives page refreshes.
- It's saved **only after** the server accepts the public key **and** the server's fingerprint matches the one computed
  locally. On any failure the key pair is discarded.
- Starting a new lab deletes stored keys for every other lab: once the old lab's sessionStorage token is gone,
  those keys can never be used again.
- Limits: one vehicle per key; at most 10 keys per lab (`KEY_LIMIT_REACHED`); the same public key can't be
  enrolled twice in a lab (`KEY_ALREADY_ENROLLED`, backed by a `UNIQUE(lab_id, fingerprint)` constraint).
- Accepted limitation: anyone with script access to this origin can *use* (not export) the key. That's inherent
  to browser keys and is listed under "Explicit non-claims" in the threat model.

---

## D-008 Revocation semantics and evidence runner — ACCEPTED (2026-11-06, Sprint 4)

- `POST /api/labs/{id}/keys/{keyId}/revoke` sets `status=revoked`, `revoked_at=now`. It's **idempotent**: a repeat
  call returns 200 and keeps the first `revoked_at`. An unknown key, or another lab's key, returns 404 `KEY_UNKNOWN`.
- Revocation is immediate with no grace period: open challenges for the key are **not** deleted, but they fail at
  authenticate (`KEY_REVOKED`) because key status is re-checked inside the authenticate transaction.
- The browser keeps the revoked key's private handle in IndexedDB (useful for demonstrating that a valid signature
  from a revoked key is still denied), but the Garage only offers keys that are active on the server.
- The structured matrix runner lives in `app/evidence/` (not `app/lab/`, which is reserved for the deliberately
  vulnerable verifier, D-005). It uses only public API calls plus the engine for the concurrency row.

---

## D-009 Resource controls, event retention and the events API — ACCEPTED (2026-11-09, Sprint 7)

Resolves T12 and the spec §6 rule "apply rate limits and TTL cleanup", plus the §11 release gate on resource limits and
event retention.

- **Rate limits** (`app/security/ratelimit.py`): fixed windows, `429 RATE_LIMITED` with `Retry-After`.
  | Bucket | Key | Default |
  |--------|-----|---------|
  | every `/api/` request | client address | 600 / 60 s |
  | `POST /api/labs` | client address | 20 / 60 s |
  | authorized lab requests | `lab_id` | 120 / 60 s |
  The per-lab bucket is counted **only after** the bearer token checks out, so nobody without the token can spend a
  lab's budget. A 429 returns before any handler runs, so a rate-limited `authenticate` never consumes a challenge.
  Configurable through `KEYGUARD_RATE_CLIENT`, `KEYGUARD_RATE_LAB_CREATE` and `KEYGUARD_RATE_LAB` (`N/seconds` or `off`).
- **Accepted limitation:** the counters live in memory in each process, so N workers allow N× the rate, and the client key
  is the direct peer address (behind a proxy that's the proxy). A hosted deployment needs a shared store and trusted
  forwarding headers first.
- **Capacity:** at most 5,000 unexpired labs. When full, `POST /api/labs` runs a cleanup pass and then, if it's still
  full, returns `503 LAB_CAPACITY`.
- **TTL cleanup** (`app/security/cleanup.py`) runs at startup and every `KEYGUARD_CLEANUP_INTERVAL` seconds (default
  300; 0 turns it off). It deletes:
  - expired labs, with their vehicles, keys, challenges, events and runs (deleted explicitly, not only by cascade);
  - challenges more than 5 minutes past expiry. A pruned challenge then fails as `CHALLENGE_NOT_FOUND` instead of
    `CHALLENGE_EXPIRED`; it's still denied.
  
  It also trims each lab's events to the newest 2,000. You can run it by hand with `python -m app.security.cleanup`.
- **Events API:** `GET /api/labs/{id}/events` (newest first; filter by `category`, `result=pass|fail`, `reason` and
  `q`; `limit` ≤ 200; `offset` ≤ 2000) and `GET /api/labs/{id}/events/summary` (pass/fail per category, failure reasons
  ranked, authentication median/p95 ms).
  - Every filter is applied in SQL inside the lab. `q` is matched as a literal substring, with LIKE wildcards escaped.
  - Events hold IDs, type, outcome and reason code only (T11).
  - Pass outcomes are `allow`, `issued`, `success` and `as_expected`; everything else is a fail.
- **Event order:** `security_events` has an integer surrogate key `seq`, so events written in the same second keep their
  insertion order.
- **No migrations in the MVP:** on startup the schema is checked, and a stale database is refused with a message saying to
  delete it. Lab data is disposable.

---

## D-010 Credential types: phone, key card, key fob (F10, P2) — ACCEPTED (2026-11-12, Sprint 9)

All three are **fictional models**. None of them copies a real card, fob or radio protocol. Every type uses a
non-extractable Web Crypto P-256 key, and the server stores only the public key (F02 unchanged).

| Type | Protocol | Model |
|------|----------|-------|
| `phone` | kg-auth-v1 challenge-response (D-001, D-003) | You choose the action, then the browser signs the server's challenge |
| `card` | kg-auth-v1 challenge-response | **Passive**: a tap signs whatever challenge is presented. The tap asks for the opposite of the current backend lock state |
| `fob` | **kg-fob-v1 rolling counter** (below) | A button press signs `(counter, action)` with no server challenge |

**kg-fob-v1 encoding** uses the same framing as D-001, but a different domain tag, so a fob signature can never verify as
a challenge response or the other way round:
- `DOMAIN_TAG_FOB = b"KEYGUARD-FOB\x00\x01"`;
- then length-prefixed fields: `protocol_version` (`"kg-fob-v1"`), `vehicle_id`, `key_id`, `counter` (decimal,
  1 … 2^53−1) and `action`.

**Server rules for `POST /api/labs/{id}/fob`.** These run in one transaction, in this order:
1. The key exists in this lab.
2. The key is a fob (`KEY_TYPE_MISMATCH` otherwise).
3. It's active and bound to the vehicle.
4. The signature is valid over bytes rebuilt from the stored key ID and vehicle ID plus the request's counter and action.
5. The counter is fresh. A conditional `UPDATE … SET last_counter = :c WHERE last_counter < :c AND :c <= last_counter + 32`
   decides this atomically: `COUNTER_REPLAYED` if `c ≤ last`, `COUNTER_OUT_OF_WINDOW` if `c > last + 32`.
6. Commit the vehicle state.

Only a valid signature can advance the counter. Unsigned junk can't burn a fob's counter.

**Cross-protocol confusion:**
- the challenge endpoint refuses fob keys;
- the authenticate engine denies fob keys (`KEY_TYPE_MISMATCH`, defense in depth);
- the fob endpoint refuses phone and card keys.

**The browser counter** is stored with the key in IndexedDB and incremented *before* signing, so a crash never reuses a
counter. The 32-step window lets a fob recover after presses that never reached the car.

**Known limitation (taught, not hidden):** a fob code captured *before* it reaches the car is still valid later, as
long as its counter is above the last accepted one and within the window. The Attack Lab `fob-capture` scenario shows
the hardened verifier accepting it. Challenge-response credentials don't have this weakness, because each challenge is
server-fresh, single use and expires in 30 s.

## D-011 Proximity is conceptual (F11, P2) — ACCEPTED (2026-11-12, Sprint 9)

- A `/proximity` page, titled "Proximity (conceptual)", shows the car, the owner's card and an optional relay pair.
  - Its distance slider is **purely illustrative**: it is never sent to the server and never changes a decision.
  - The page says so on screen.
- The decision it shows comes from a real backend Attack Lab scenario, **`relay`**. Attacker A, standing by the car,
  asks for a challenge and forwards it to attacker B, who is next to the owner 40 m away. The owner's passive card signs
  it, and the signature travels back.
- **Both the vulnerable verifier and the hardened engine allow it** (expected allow/allow). Nothing in kg-auth-v1 carries
  distance or timing, which restates the threat model's non-claim: a valid signature does not prove proximity.
- Real-world mitigations (distance bounding, UWB time-of-flight, motion or user-presence checks) are described as
  context only. **None is implemented or claimed.**

---

## D-012 Accounts and saved labs, with passkeys (F12, P2) — ACCEPTED (2026-11-12, Sprint 10)

The project owner chose **passkeys** over email and password. Labs stay anonymous and disposable by default. An account is
optional, and only adds the ability to keep labs.

**Sign-in (WebAuthn, via the `py_webauthn` library):**
- **Credentials:** discoverable (resident key **required**), with **user verification required** and attestation `none`.
  Accepted algorithms are ES256 and EdDSA.
- **Usernameless login:** no account lookup endpoint exists, so there's nothing to enumerate.
- **Relying party:** RP ID and origin come from config (`KEYGUARD_RP_ID`, default `localhost`; origin = the first
  `KEYGUARD_WEB_ORIGIN`). WebAuthn binds every assertion to that origin, so a phishing site can't use one.
- **Challenges:** 32 random bytes, stored in `webauthn_challenges` with a purpose (`register` or `login`) and a 5-minute
  TTL. They're consumed with **one conditional UPDATE**, the same pattern as D-003: single use, burned on any verify
  attempt.
- **Sign counter:** stored per passkey. A response whose counter doesn't increase (when either side is non-zero) is
  rejected as `PASSKEY_CLONED`. Many synced passkeys always report 0, and that's allowed.
- **Display name:** 1–40 printable characters, chosen by the user, never an email. It isn't unique and isn't used to sign
  in.
- **One passkey per account in this MVP.** If it's lost, the account and its saved labs are lost. This is an accepted
  limitation; synced passkeys reduce the risk.

**Sessions:**
- A 32-byte random token. The server stores only its SHA-256 and compares with `compare_digest`. Sessions last 12 h,
  signing out revokes them, and deleting the account deletes them.
- Sent as the `kg_session` cookie: `HttpOnly; SameSite=Strict; Path=/api`, plus `Secure` when
  `KEYGUARD_COOKIE_SECURE=1`. Page scripts can never read it, which is unlike the lab token (D-002).
- **CSRF:** every account request that changes state needs the header `X-KeyGuard-CSRF: 1`. Cross-origin pages can't send
  a custom header without a CORS preflight, and CORS allows only the configured web origin (with credentials).
  SameSite=Strict is a second layer.

**Saved labs:**
- `POST /api/labs/{id}/save` needs **both** the lab's bearer token **and** an account session. It sets
  `labs.account_id` and extends `expires_at` to 30 days from now. A lab another account already saved returns
  `409 LAB_ALREADY_SAVED`, so ownership never transfers.
- **Open:** `POST /api/account/labs/{id}/open` issues a **fresh lab token** and replaces the stored hash, so any older
  token for that lab stops working. It also extends expiry by 30 days. Another account, or an unknown lab, gets the same
  `404 LAB_NOT_FOUND`.
- **Unsave:** `POST /api/account/labs/{id}/unsave` clears ownership and caps expiry at 24 h from now.
- At most 10 saved labs per account (`SAVED_LAB_LIMIT`).
- Private keys stay in the browser that made them (D-007). Opening a saved lab in another browser gives you its car,
  history and key list, but you'd enroll new keys there. Starting a new lab no longer purges the local keys of labs
  you've saved.

**Delete account:** `POST /api/account/delete` with `{"confirm": "DELETE"}` deletes the account, its passkeys and
sessions, and **every saved lab with all its data**.

**Rate limits:** the existing per-client limit, plus `auth`: 30 requests per 60 s per client for the four WebAuthn
endpoints.

---

## D-013 Hosting hardening — ACCEPTED (2026-11-12, Sprint 11)

This works through the pre-hosting gates in `DEPLOYMENT.md`. Nothing is deployed yet: choosing a host and creating
accounts is the project owner's call.

**PostgreSQL is proven, not assumed.** `KEYGUARD_TEST_DATABASE_URL` runs the whole pytest suite and the structured matrix
against PostgreSQL, with the schema reset per test. CI runs both on every push (new `api-postgres` job, Postgres 17).
That surfaced two real bugs that SQLite hid, and both are fixed:
- **32-bit columns.** Timestamps and the fob counter were `INTEGER`. PostgreSQL rejects 2^53 fob counters and any time
  after January 2038. All time and counter columns are now `BIGINT`; `security_events.seq` stays `INTEGER` on SQLite so
  it still auto-increments.
- **Limit checks raced.** Counting and then inserting under READ COMMITTED let 20 simultaneous enrollments create 18 keys
  against a limit of 10. Fixed with `SELECT … FOR UPDATE`:
  - on the lab row, for the key limit and the open-challenge limit;
  - on the account row, for the saved-lab limit.

  SQLite already serializes writes with `BEGIN IMMEDIATE`, and SQLAlchemy omits `FOR UPDATE` there.

The single-use conditional UPDATEs (challenges, fob counters, WebAuthn challenges, saved-lab claims) were already
correct on PostgreSQL: a concurrent UPDATE waits for the row lock and then re-checks its `WHERE`.

**Shared rate limiting.**
- `KEYGUARD_RATE_STORE=database` keeps fixed-window counters in a `rate_limit_counters` table. Each hit is one atomic
  `INSERT … ON CONFLICT DO UPDATE … RETURNING`, so all workers and instances share one count.
- Keys are stored as SHA-256 hashes, never raw client addresses. Windows older than an hour are cleaned up.
- No new infrastructure is needed. Redis would only matter at much higher traffic than a demo sees.

**Client address behind proxies.** `KEYGUARD_TRUSTED_PROXIES` takes a comma-separated list of IPs and CIDRs.
- `X-Forwarded-For` is read **only** when the direct peer is in that list.
- It's walked from the right, and the first untrusted hop is the client. Anything to its left came from the client
  itself and is ignored.
- If the nearest hop is malformed, the proxy's address is used instead.

**Security headers.**
- **API:** `nosniff`, `Referrer-Policy: no-referrer` and `X-Frame-Options: DENY`; on `/api/` also
  `CSP: default-src 'none'; frame-ancestors 'none'` and `Cache-Control: no-store`; HSTS when `KEYGUARD_HSTS=1`.
  Interactive API docs are off in production.
- **Web (production builds):**
  - a CSP with `connect-src 'self' <API origin>`, `object-src 'none'`, `base-uri 'none'` and `frame-ancestors 'none'`;
  - `Permissions-Policy`, `nosniff`, `no-referrer` and `DENY`, with no `X-Powered-By`;
  - HSTS when `KEYGUARD_HSTS=1`.
- **Accepted limitation:** `script-src` allows `'unsafe-inline'`, because the App Router inlines its bootstrap scripts
  and a nonce policy needs dynamic rendering. `connect-src` still stops an injected script from *sending* the lab token
  anywhere except the API (an e2e test checks this). A nonce-based CSP is a follow-up.

**Production safety check.** With `KEYGUARD_ENV=production`, the API refuses to start, listing every problem, unless:
- the database is PostgreSQL;
- every web origin is `https://`;
- `KEYGUARD_RP_ID` is the origin's domain (not localhost);
- `KEYGUARD_COOKIE_SECURE=1` and `KEYGUARD_HSTS=1` are set;
- `KEYGUARD_RATE_STORE=database` is set;
- no rate limit is `off`;
- the trusted-proxy list parses.

**Health.** `/api/health` now does a database round trip and returns `503 DATABASE_UNAVAILABLE` (with no error detail)
if it fails. That's what a host's health check and uptime alerting should watch.

**Gate 5 (lab token review):** the lab token stays in `sessionStorage` (D-002). For a public demo the risk is XSS reading
it. Mitigations: the CSP blocks third-party scripts and exfiltration to other hosts; React escapes all rendered data;
labs expire in 24 h and are disposable. Accounts (D-012) already use an HttpOnly cookie. Moving lab tokens into cookies
too would need a CSRF design for every lab endpoint, and it's left as a follow-up.
