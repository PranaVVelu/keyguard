# Security Test Evidence

Last run: 2026-11-06 (Sprint 3), local (macOS arm64, Python 3.12.16, Node 24.14, SQLite WAL).
**Backend: 133 passed, 0 failed** (`cd services/api && uv run pytest -v`).
**Web: 35 passed, 0 failed** (`cd apps/web && npm test`).

CI (`.github/workflows/ci.yml`) runs both suites on every push and PR.

## Mandatory hardened matrix (spec §7): status after Sprint 3

All rows are now proven **end-to-end through the HTTP API** (`tests/test_authenticate_api.py`), except
row 8, which runs through the full authentication engine with 16 real threads (no HTTP layer). Revocation
is applied directly in storage until the revoke endpoint lands (Sprint 4).

| # | Scenario | Expected | Observed | Tests |
|---|----------|----------|----------|-------|
| 1 | Active key + fresh challenge | Allow | Allow, lock state changes, 6/6 trace steps pass | `test_row01_*` |
| 2 | Incorrect signature | Deny | Deny `SIGNATURE_INVALID` / `SIGNATURE_MALFORMED`, state unchanged | `test_row02_*` (other key, bit flip, wrong nonce, truncated, all-zero, bad charset) |
| 3 | Revoked key | Deny | Deny `KEY_REVOKED` even for a challenge issued before revocation; issuance refused 403; second active key still allowed | `test_row03_*` |
| 4 | Expired challenge | Deny | Deny `CHALLENGE_EXPIRED` at +30 s, +31 s, +1 h; allowed at +29 s | `test_row04_*` |
| 5 | Consumed challenge replay | Deny | Deny `CHALLENGE_CONSUMED`; a replayed unlock doesn't re-unlock a locked car; a failed attempt burns the challenge (O-2) | `test_row05_*` |
| 6 | Wrong vehicle | Deny | Signature over another vehicle → `SIGNATURE_INVALID`; challenge for an unbound vehicle → 422 `VEHICLE_MISMATCH`; key re-bound after issue → `VEHICLE_MISMATCH` | `test_row06_*` |
| 7 | Wrong requested action | Deny | Unlock signature over a lock challenge, or a lock response reused for unlock → `SIGNATURE_INVALID` | `test_row07_*` |
| 8 | Two concurrent submissions | ≤1 succeeds | Exactly 1 allow, 15 × `CHALLENGE_CONSUMED`, in 5 rounds of 16 threads | `test_row08_*` |
| 9 | Unknown key | Deny | Issuance 404 `KEY_UNKNOWN`; authenticate with a key other than the challenge's → `KEY_MISMATCH` | `test_row09_*` |
| 10 | Malformed payload | Reject safely | 422 `REQUEST_INVALID` for empty, bad IDs, nulls, numbers, oversized, client-asserted `decision`, array, non-JSON; no state change | `test_row10_*` |
| 11 | Cross-lab request | Deny | Other lab's token → uniform 404 (and the challenge isn't burned); a lab-A challenge sent to lab B → `CHALLENGE_NOT_FOUND`; can't get a challenge for another lab's key | `test_row11_*` |

Supporting checks: per-lab open-challenge cap (429), events contain no signatures, nonces or tokens, and the response trace contains no secrets.

### Engine mutation check (Sprint 3, manual)
Each security check in `app/security/authenticate.py` was disabled in turn and the suite re-run:

| Mutation | Caught? |
|----------|---------|
| Skip atomic consume | ✅ replay + concurrency tests fail |
| Skip key-matches-challenge | ✅ `test_row09_*` fail |
| Skip revocation check | ✅ `test_row03_*` fail |
| Skip vehicle binding | ✅ `test_row06_key_rebound_after_issue_is_denied` fails |
| Accept any signature | ✅ `test_row02_*`, `test_row07_*` fail |
| Rebuild bytes with the request's key_id instead of the challenge's | Not caught, and **equivalent**: step 3 already forces them equal |

### Manual end-to-end check in Chromium (2026-11-06)
Start lab → enroll key → Garage "Request unlock" → **ALLOWED · UNLOCKED**, 6/6 PASS, 9 ms server time →
"Request lock" → ALLOWED · LOCKED → recorded the browser's exact `/authenticate` body and re-sent it →
**deny `CHALLENGE_CONSUMED`**, vehicle stayed `locked`.

## Mutation check (does the concurrency test catch a broken implementation?)

Removing `consumed_at IS NULL` from the conditional UPDATE in `app/security/challenges.py` made
**11 tests fail**: the replay test and all 10 concurrency rounds. With the guard restored, all pass.
This was a manual check and is not automated.

## Other evidence

- Encoding: 4 canonical-bytes vectors and 7 verify vectors in `docs/test-vectors/kg-auth-v1.json`.
  This includes a high-S signature form that is accepted on purpose (D-001).
- Framing: `test_framing_prevents_field_boundary_collisions`, `test_every_field_changes_the_message`.
- Lab tokens are stored only as a SHA-256 hash: `test_token_is_stored_only_as_hash`.
- A transaction rollback leaves the challenge usable, so a failed state change can't burn it silently:
  `test_rolled_back_consumption_leaves_challenge_usable`.

## Sprint 2 evidence: enrollment and browser↔server interop

| Property | Evidence |
|----------|----------|
| Server stores the public key only (91-byte SPKI) | `test_server_stores_only_the_public_key` |
| Extra fields such as `private_key` are rejected | `test_extra_fields_such_as_private_key_are_rejected` |
| Non-P-256, RSA and garbage keys rejected, nothing stored | `test_invalid_public_keys_are_rejected[*]` |
| Can't enroll against another lab's vehicle | `test_cannot_enroll_against_another_labs_vehicle` |
| Cross-lab enroll/list denied with uniform 404 | `test_cross_lab_key_listing_and_enrollment_are_denied` |
| Duplicate key / key limit | `test_same_public_key_cannot_be_enrolled_twice`, `test_key_limit_per_lab` |
| Events contain no keys or tokens (T11) | `test_enrollment_events_record_ids_and_reasons_only` |
| TS encoder is byte-identical to Python | `encoding.test.ts`: all 4 vectors |
| Web Crypto accepts and rejects Python signatures correctly | `crypto.test.ts`: all 7 verify vectors |
| **Python verifies a Web Crypto signature** | `test_committed_webcrypto_vector_verifies` (committed vector), `test_fresh_webcrypto_signature_verifies` (new key each run; skipped when Node is missing, as in the CI API job) |
| Private key is non-extractable | `crypto.test.ts` (Node), plus a manual check in Chromium: `exportKey` refused for pkcs8 and jwk |

### Manual end-to-end check (Chromium in the Claude desktop browser pane, 2026-11-05)
Start lab → Garage shows the backend vehicle (`LOCKED`, from the API) → Digital Keys → "Generate & enroll key" →
browser fingerprint `5fd990cb…670c` == server fingerprint → page reload → key still present in IndexedDB,
`extractable: false`, usages `["sign"]`; lab token in sessionStorage, localStorage empty.
This was manual and isn't automated yet (Playwright is planned).

## Known gaps

- No automated real-browser (Playwright) test yet; browser behaviour above was checked manually.
- The CI API job has no Node, so the *fresh* interop test is skipped there; the committed vector still runs.
- The concurrency test is proven on SQLite only. PostgreSQL must be re-verified before hosting.
- Each test does not yet record scenario ID, timing or failure category as structured output (spec §7). The structured runner comes in Sprint 4.
- Revocation is applied directly in storage in the tests; the revoke endpoint comes in Sprint 4.
- Concurrency has been proven on SQLite only; re-verify on PostgreSQL before hosting.
