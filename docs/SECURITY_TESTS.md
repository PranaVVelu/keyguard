# Security Test Evidence

Last run: 2026-11-09 (Sprint 7), local (macOS arm64, Python 3.12.16, Node 24.14, SQLite WAL).
**Backend: 215 passed, 0 failed** (`cd services/api && uv run pytest -v`).
**Web: 46 passed, 0 failed** (`cd apps/web && npm test`).
**Structured matrix: 11/11 pass**: [`docs/evidence/matrix-latest.md`](evidence/matrix-latest.md) (JSON alongside).

CI (`.github/workflows/ci.yml`) runs both suites **and the structured matrix** on every push and PR. The matrix table
goes into the run summary and is uploaded as the `security-matrix` artifact, and any non-pass fails the build.

## Structured matrix runner (spec §7 evidence format)

`uv run python -m app.evidence.matrix --json out.json --markdown out.md`

Each of the 11 scenarios (MX-01 … MX-11) runs against a **fresh app and database** through the real HTTP API and
records: scenario ID, expected decision, observed decision, reason, whether vehicle state changed, outcome and timing.
Outcomes are classified as spec §7 requires:

| Outcome | Meaning |
|---------|---------|
| `pass` | observed matches expected |
| `security_failure` | unauthorized acceptance: a deny/reject row allowed, a deny changed vehicle state, or >1 concurrent allow |
| `functional_failure` | a valid request was denied, or a deny happened for an unexpected reason |
| `infrastructure_failure` | the scenario itself errored, so the result is untrustworthy |

The runner is itself tested (`tests/test_matrix_runner.py`). With replay protection deliberately broken
(consumption always "succeeds"), it reports MX-04, MX-05 and MX-08 as **security_failure** and exits non-zero.
A crashing scenario is reported as **infrastructure_failure**, never as a pass.

## Mandatory hardened matrix (spec §7): status after Sprint 3

All rows are now proven **end-to-end through the HTTP API** (`tests/test_authenticate_api.py`), except
row 8, which runs through the full authentication engine with 16 real threads (no HTTP layer). Since Sprint 4,
revocation uses the real `POST /keys/{id}/revoke` endpoint.

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

### Manual revocation journey in Chromium (Sprint 4, 2026-11-06)
Enrolled "Phone A" and "Phone B" in the UI → requested an unlock challenge for Phone A → **revoked Phone A** in the UI
(two-step confirm) → signed that earlier challenge with Phone A's still-present private key (a valid signature) →
**deny `KEY_REVOKED`** (trace fails at `key_active_and_bound`), vehicle stayed `locked` → a new challenge for Phone A →
**403 `KEY_REVOKED`** → Garage offers only Phone B → unlock **ALLOWED**.

## Sprint 5: Attack Lab (F05) and isolation (T13)

| Property | Evidence |
|----------|----------|
| Replay: vulnerable verifier **accepts**, hardened engine **rejects** (`CHALLENGE_CONSUMED`) | `test_replay_vulnerable_accepts_and_hardened_rejects` |
| Reproducible across runs | `test_replay_comparison_is_reproducible[0-4]` |
| Scenarios don't touch the lab's real vehicles, keys, challenges or labs table | `test_scenario_does_not_touch_the_labs_real_state` |
| Each run records one `lab_runs` row per mode (expected vs actual) | `test_runs_are_recorded_per_mode` |
| Vulnerable verifier still rejects forged signatures (it's replayable, not a no-op) | `test_vulnerable_verifier_still_checks_signatures` |
| **The hardened path can't import `app.lab`** (static AST import graph, transitive) | `test_lab_isolation.py`: 4 tests |

Isolation mutation check: planting `from app.lab.vulnerable.verifier import …` in `app/security/authenticate.py`
made two isolation tests fail, and planting `import sqlalchemy` in the vulnerable verifier made the
database-reach test fail. Both were reverted.

Manual check in Chromium: Attack Lab → Run "Replay a captured unlock" → vulnerable **REPLAY ACCEPTED, car UNLOCKED**;
hardened **REPLAY REJECTED · CHALLENGE_CONSUMED, car stays LOCKED**; results match expectations; history shows both rows.

## Sprint 6: Inspector (F04)

- `lib/annotate.ts` parses signed bytes back into labelled segments and rejects a wrong tag, truncation or
  trailing bytes. `annotate.test.ts` round-trips all 4 encoding vectors back into their exact fields.
- The Garage and the Inspector share one client flow (`performAction` in `lib/auth-flow.ts`), so the Inspector
  shows the same exchange the Garage performs, not a re-enactment.
- The vehicle graphic only mirrors the backend's `lock_state`, and its light flash only plays when that changes.

Manual check in Chromium (2026-11-09): Inspector → Run unlock → all 7 stages DONE with real artifacts (190-byte
message split into tag + 7 length-prefixed fields; r/s halves; request bodies) → **ALLOWED · UNLOCKED** →
"Replay this exact response" → **DENIED · CHALLENGE_CONSUMED**. Garage → Request lock → **ALLOWED · LOCKED**,
graphic shows the closed lock.

## Sprint 7: events, Security Analytics (F08) and resource controls (T12)

| Property | Evidence |
|----------|----------|
| Events are newest first, with category and pass/fail derived on the server | `test_lists_newest_first_with_category_and_result` |
| Events and the summary never contain the lab token, nonce, signature or key bytes | `test_events_never_contain_secrets` |
| Filters, search and LIKE-wildcard escaping (`%` matches nothing, `_` is literal) | `test_filters_and_search[…]` (11 cases) |
| Events are scoped to the lab; another lab's token gets the uniform 404 | `test_events_are_scoped_to_the_lab` |
| Summary counts, failure categories and timing | `test_summary_counts_and_failure_categories`, `test_empty_lab_summary` |
| Bad query parameters get `422 REQUEST_INVALID` | `test_invalid_query_parameters_are_rejected[…]` (8 cases) |
| Lab creation is limited per client; per-lab limit only counts authorized requests | `test_lab_creation_is_limited_per_client`, `test_per_lab_limit_applies_after_authorization_only` |
| Unauthenticated probing is limited per client | `test_per_client_limit_covers_unauthenticated_probing` |
| **A rate-limited authenticate doesn't consume the challenge**, and the same response succeeds in the next window | `test_rate_limited_authenticate_never_reaches_the_engine` |
| Capacity returns `503 LAB_CAPACITY`, and cleanup frees space | `test_lab_capacity_returns_503_and_cleanup_frees_space` |
| Cleanup deletes an expired lab and **every** child row, but not unexpired labs | `test_cleanup_deletes_expired_labs_and_everything_in_them` |
| Dead challenges are pruned after the grace period; a pruned one still fails closed | `test_cleanup_prunes_dead_challenges_but_keeps_live_ones` |
| Event retention keeps the newest N per lab | `test_cleanup_keeps_only_the_newest_events_per_lab` |
| A stale database schema is refused with a clear message | `test_stale_schema_is_refused_with_a_clear_message` |

Mutation check (manual, all reverted). These were each caught by a failing test:
- dropping the `lab_id` clause from the event query;
- removing the LIKE escaping;
- removing the per-lab limit;
- removing the lab-creation limit;
- counting `deny` as a pass;
- removing the 5-minute challenge grace period (caught only after a test for it was added this sprint).

Removing the explicit event delete in cleanup was *not* caught. That's an equivalent mutant on SQLite: `ON DELETE
CASCADE` still removes the rows.

Manual check in Chromium (2026-11-09):
- Started a lab, enrolled a key, ran the Inspector unlock and replay, and ran the Attack Lab scenario.
- Analytics then showed 5 events (4 pass, 1 fail), with `CHALLENGE_CONSUMED` as the only failure reason.
- Clicking that reason filtered the log to the one denied authentication. Searching "scenario" found the scenario run.
- Garage → Request lock showed "Latest event: Authenticate · lock ALLOW".
- Against the live API, the 21st `POST /api/labs` in one minute returned `429 RATE_LIMITED` with `Retry-After`.

## Known gaps

- No automated real-browser (Playwright) test yet; browser behaviour above was checked manually.
- The CI API job has no Node, so the *fresh* interop test is skipped there; the committed vector still runs.
- The concurrency test is proven on SQLite only. PostgreSQL must be re-verified before hosting.
- Rate-limit counters are per process, and the client key is the direct peer address (D-009). Both must change
  before a multi-worker or proxied deployment.
