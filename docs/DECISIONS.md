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
- **Implementation note (Sprint 1):** to get burn-on-failure without a check-then-act gap, the Sprint 3
  authenticate engine will run the conditional consume (step 5) right after step 2, in the same
  transaction, and then do steps 3–4. Consumption always commits; the vehicle state changes only if every
  check passes. `consume_challenge` already supports this (it is transaction-scoped).
- Revocation takes effect immediately: a challenge issued before revocation fails at step 3.
- Expiry and consumption are checked inside the conditional UPDATE, so there is no gap between
  checking and consuming (TOCTOU).

---

## D-004 Identifiers — ACCEPTED (2026-11-05)

Opaque, prefixed, 128-bit random IDs (`veh_`, `key_`, `chl_`, `lab_`, `evt_`), base64url.
No sequential integers are exposed via the API.

---

## D-005 Vulnerable verifier isolation — PROPOSED (implemented Sprint 5)

The vulnerable verifier lives in `services/api/app/lab/vulnerable/` and works on its own in-memory or
scenario-scoped tables. A test enforces that nothing under `app/security/` or `app/routes/` imports
`app.lab.vulnerable` (an AST import scan in pytest).

---

## D-006 Tooling — ACCEPTED (2026-11-05)

- Python **3.12** — **ACCEPTED (O-1, 2026-11-05).** Installed as CPython 3.12.16 via uv 0.13.7
  (`~/.local/bin`), since Homebrew isn't present. The backend venv is created with `uv venv --python 3.12`.
- Backend: FastAPI, Pydantic v2, SQLAlchemy 2.x Core, `cryptography`, pytest.
- Frontend: Next.js (App Router), TypeScript strict, Tailwind; npm (already installed).
- SQLite with `BEGIN IMMEDIATE` for writes locally; the conditional-UPDATE pattern ports unchanged to PostgreSQL.
- No Docker requirement for Sprint 1 (Docker is not installed); `docker-compose.yml` comes later.
