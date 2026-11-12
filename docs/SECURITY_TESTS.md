# Security Test Evidence

Last run: 2026-11-12 (Sprint 11), local (macOS arm64, Python 3.12.16, Node 24.14, Chromium 141 headless; SQLite WAL and PostgreSQL 16).
**Backend: 397 passed, 0 failed, on SQLite and on PostgreSQL** (`cd services/api && uv run pytest -v`; set
`KEYGUARD_TEST_DATABASE_URL` to a PostgreSQL URL for the second run).
**Web unit: 73 passed, 0 failed** (`cd apps/web && npm test`).
**End-to-end: 17 passed in direct mode, 20 in proxy mode, 0 failed** (`cd apps/web && npm run e2e`, then again with
`KEYGUARD_E2E_MODE=proxy`: real Chromium, real API, production web build under the CSP).
**Structured matrix: 11/11 pass on both databases**: [SQLite](evidence/matrix-latest.md), [PostgreSQL](evidence/matrix-postgres.md).

CI (`.github/workflows/ci.yml`) runs every suite on every push and PR: pytest, **the structured matrix**, the web unit
tests and build, **Playwright end-to-end**, and a **Docker** build and smoke test. The matrix table
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

## Sprint 8: real-browser evidence (Playwright), accessibility, packaging

| Property | Evidence (`apps/web/e2e/`) |
|----------|---------------------------|
| Full owner journey through the real UI: enroll → unlock → lock → replay **DENIED · CHALLENGE_CONSUMED** → Attack Lab (vulnerable accepts, hardened rejects) → revoke → Garage offers no key → Analytics shows the replay | `journey.spec.ts` › owner journey |
| **The stored browser key can't be exported**: the test reads the `CryptoKey` from IndexedDB, `extractable === false`, and `exportKey("pkcs8")` throws `InvalidAccessError` | owner journey |
| A signature altered in flight (one character flipped by request interception) is **DENIED · SIGNATURE_INVALID** and the car stays locked (T2, F09) | `a tampered signature in flight…` |
| A lab is private to its tab: another browser context has no session, and the API returns `404 LAB_NOT_FOUND` for the ID | `a lab is private…` |
| An expired or unknown lab is explained, not silently dropped | `an expired or unknown lab…` |
| WCAG 2.1 A/AA axe scan: 0 violations on all 5 pages, both empty and with real data | `a11y.spec.ts` |
| Keyboard-only start → enroll → unlock | `a11y.spec.ts` |

Mutation check: with replay protection disabled in `authenticate.py` (consume result ignored), the owner-journey e2e
test **failed**. Restored afterwards (no diff).

Packaging: the CI `docker` job builds both images, waits for health checks, then checks through the containers that a
lab is readable with its token and returns 404 without it. Docker isn't installed on the dev machine, so CI is the only
place this runs.

## F09: Attack Lab tamper scenario

The owner locks; the attacker (a) staples that genuine lock signature onto a fresh unlock challenge, then
(b) intercepts the owner's next unlock and flips one signature byte. Both verifiers rebuild the kg-auth-v1 bytes from
their own stored challenge, so both deny both edits and the car stays locked.

| Property | Evidence |
|----------|----------|
| Both verifiers deny both tampered submissions **`SIGNATURE_INVALID`**, car stays `locked`; the owner's genuine lock is allowed | `test_tamper_is_rejected_by_both_verifiers_with_signature_invalid` |
| Reproducible across runs | `test_tamper_comparison_is_reproducible[0-4]` |
| Why: the stapled signature verifies over the lock bytes but not over the unlock bytes the verifier rebuilds | `test_stapled_signature_is_genuine_but_bound_to_the_servers_bytes` |
| A flipped byte is `INVALID` (not `MALFORMED`); the untouched signature still verifies | `test_flipped_signature_byte_is_invalid_not_malformed` |
| One `lab_runs` row per mode; the lab's real state is untouched (parametrised over every scenario) | `test_tamper_runs_are_recorded_per_mode`, `test_scenario_does_not_touch_the_labs_real_state[tamper]` |
| Real UI: both columns show **TAMPERED RESPONSE REJECTED · SIGNATURE_INVALID: car stays LOCKED** and history has two `deny · SIGNATURE_INVALID` rows | `journey.spec.ts` › owner journey |

Mutation check: with the vulnerable verifier's signature check disabled (`if not ok:` → `if False:`), all 9 tamper
tests and `test_vulnerable_verifier_still_checks_signatures` **failed**. Reverted (no diff).

## Attack Lab substitute scenario (client-supplied signed bytes)

The owner unlocks (the attacker captures the signed message and its signature), then locks. Replaying the capture on
its own challenge fails in both verifiers (`CHALLENGE_CONSUMED`). When the owner later requests a lock challenge C2,
the attacker answers it first with C2's ID plus the old unlock bytes and signature. `ClientBytesVerifier`
(`app/lab/vulnerable/client_bytes.py`) enforces single use but verifies the signature over the client's bytes and acts
on their `unlock` action, so it unlocks the car. The hardened engine rebuilds the bytes from C2's row and denies.

| Property | Evidence |
|----------|----------|
| Vulnerable **allows** the substitution and the car ends `unlocked`; hardened **denies `SIGNATURE_INVALID`** and the car stays `locked`; the plain replay is `CHALLENGE_CONSUMED` in both | `test_substitute_vulnerable_unlocks_and_hardened_denies_signature_invalid` |
| Reproducible across runs | `test_substitute_comparison_is_reproducible[0-4]` |
| Why: the old bytes name the old challenge ID and `unlock`; the signature fails over the bytes rebuilt from C2, yet the client-bytes verifier accepts it | `test_substituted_bytes_name_another_challenge_but_still_verify_in_the_vulnerable_verifier` |
| The vulnerable verifier is single use and still rejects forged signatures (the only bug is whose bytes it checks) | `test_client_bytes_verifier_enforces_single_use_and_checks_signatures` |
| Same attack on the production HTTP API: `SIGNATURE_INVALID`, car `locked`; a `signed_message` field is refused `422 REQUEST_INVALID` | `test_substitution_through_the_real_api_is_denied_and_signed_bytes_are_not_accepted` |
| Malformed kg-auth-v1 framing (no tag, truncated, trailing bytes) is rejected by the lab parser | `test_parse_signed_message_rejects_malformed_framing[*]` |
| One `lab_runs` row per mode; the lab's real state is untouched; the vulnerable module imports no DB layer and is unreachable from the hardened path | `test_substitute_runs_are_recorded_per_mode`, `test_scenario_does_not_touch_the_labs_real_state[substitute]`, `test_lab_isolation.py` |
| Real UI: vulnerable column shows **SUBSTITUTED MESSAGE ACCEPTED: car is UNLOCKED**, hardened shows **SUBSTITUTED MESSAGE REJECTED · SIGNATURE_INVALID: car stays LOCKED** | `journey.spec.ts` › owner journey |

Mutation check: with `ClientBytesVerifier` changed to verify over `encode_signed_message(issued.fields)` (the
hardened behaviour), 8 substitute tests **failed** (the scenario, its 5 reproducibility runs, the run-history test and
the root-cause test). Reverted (no diff).

## Sprint 9: credential types (F10) and proximity (F11)

| Property | Evidence |
|----------|----------|
| kg-fob-v1 encoding is framed and domain-separated; Python and Web Crypto agree byte for byte and on signatures | `test_fob_encoding_*`, `test_fob_vectors_match_the_python_encoder`, `apps/web/tests/fob.test.ts` (shared `docs/test-vectors/kg-fob-v1.json`) |
| A press is allowed only with a rising counter; replays and lower counters get `COUNTER_REPLAYED` | `test_replaying_an_accepted_press_is_denied`, `test_lower_counter_is_denied_even_if_never_used` |
| 32-step resync window; beyond it `COUNTER_OUT_OF_WINDOW`, and the counter doesn't move | `test_window_allows_resync_after_missed_presses_but_not_beyond` |
| **An invalid signature never advances the counter**, so junk can't lock a fob out | `test_invalid_signature_never_advances_the_counter` |
| The signature binds the action, counter and vehicle | `test_signature_binds_action_counter_and_vehicle[…]` |
| Revoked, wrong vehicle, unknown and other-lab keys are denied | `test_revoked_fob_is_denied`, `test_fob_for_another_vehicle_is_denied`, `test_unknown_key_is_denied`, `test_another_labs_fob_is_unknown_here` |
| **No protocol confusion:** fob keys get no challenges, a planted challenge still fails `KEY_TYPE_MISMATCH`, phone and card keys are refused at `/fob`, and a fob-domain signature fails as a challenge response | four cross-protocol tests in `test_fob_api.py` |
| 16 concurrent identical presses → exactly one allow (×3 rounds) | `test_concurrent_identical_presses_at_most_one_allows` |
| Attack Lab: `fob-replay` (vulnerable allows, hardened denies), `fob-capture` (both allow, a labelled known limitation), `relay` (both allow) | `test_new_scenarios_through_the_api[…]`, reproducibility ×3 each |
| Browser: fob unlock and lock with counters 1 and 2; replaying the captured request byte for byte is denied; a card tap toggles; the proximity slider value is never sent | `apps/web/e2e/credentials.spec.ts` |
| A browser fob that reused its counter is caught by e2e (mutation: counter fixed at 1 → test failed) | manual mutation, reverted |

Engine mutation check (manual, all reverted). These were each caught by failing tests:
- removing the replay check (10 tests failed);
- removing the window check;
- removing the `key_is_fob` check;
- removing the vehicle binding;
- removing the signature check;
- letting the authenticate engine accept fobs;
- issuing challenges for fobs;
- giving fobs the same domain tag as kg-auth-v1.

Removing `status == 'active'` from the counter UPDATE was not caught. That's an equivalent mutant: status is checked earlier
in the same `BEGIN IMMEDIATE` transaction, so a revoke can't interleave on SQLite.

## Sprint 10: passkey accounts and saved labs (F12)

Backend tests use a **software authenticator** (`tests/webauthn_sim.py`) that builds real WebAuthn responses: CBOR
`none` attestations, COSE ES256 keys, authenticator data with UP/UV/AT flags and counters, and ECDSA assertions. The
`py_webauthn` library verifies them unmodified. E2E tests use **Chromium's virtual CTAP2 authenticator**.

| Property | Evidence |
|----------|----------|
| Registration needs a resident key and user verification, with attestation `none`, ES256 or EdDSA | `test_registration_options_require_resident_key_and_user_verification` |
| Login options list no credentials, so there's nothing to enumerate | `test_login_options_reveal_no_accounts` |
| Wrong origin (phishing), wrong RP ID or missing UV is rejected at registration and login, with no cookie set (T19) | `test_registration_rejects_*[…]`, `test_login_rejects_*[…]` (6 cases) |
| WebAuthn challenges are single use, purpose-bound and expire after 5 min; a failed verify burns the challenge (T20) | `test_registration_response_cannot_be_replayed`, `test_failed_verification_burns_the_challenge`, `test_login_challenge_cannot_be_used_for_registration`, `test_expired_challenge_is_rejected` |
| An assertion signed by another key, an unknown credential or a mismatched user handle is rejected | `test_login_signature_from_another_key_is_rejected`, `test_unknown_passkey_is_rejected`, `test_user_handle_must_match_the_credentials_account` |
| A sign-counter regression is rejected as `PASSKEY_CLONED`; always-zero counters are allowed (T24) | `test_sign_count_regression_is_rejected`, `test_always_zero_counters_are_allowed` |
| Session: HttpOnly, SameSite=Strict, Path=/api cookie; token stored only as SHA-256; logout revokes it server-side; 12 h expiry; forged cookies rejected (T21) | `test_register_creates_account_passkey_and_session_cookie`, `test_session_token_is_stored_only_as_a_hash`, `test_logout_revokes_the_session_server_side`, `test_session_expires`, `test_forged_session_cookie_is_rejected` |
| Every account write needs `X-KeyGuard-CSRF` (T22) | `test_state_changes_require_the_csrf_header[…]` (9 endpoints) |
| Saving needs both the lab token and a session; another account can't take, open, unsave or list a saved lab (T23) | `test_saving_needs_the_lab_token_too`, `test_saving_needs_an_account`, `test_saved_labs_are_private_to_their_account` |
| Opening issues a fresh lab token and the old one stops working; unsaving caps retention at 24 h; there's a 10-lab limit | `test_save_open_and_rotate_the_lab_token`, `test_unsave_caps_retention_and_releases_ownership`, `test_saving_twice_is_idempotent_and_the_limit_is_enforced` |
| Saved labs survive the 24 h TTL and expire at 30 days | `test_saved_labs_outlive_the_normal_lab_ttl` |
| Deleting the account removes the account, passkeys, sessions and saved labs, but leaves unsaved labs | `test_delete_account_removes_everything_it_owns` |
| Auth endpoints are rate limited; expired challenges and ended sessions are cleaned up | `test_auth_endpoints_are_rate_limited`, `test_cleanup_removes_expired_challenges_and_ended_sessions` |
| Browser: register, then the authenticator holds a resident credential; the cookie isn't visible to `document.cookie`; save, sign out, usernameless sign-in (counter rises), reopen with a rotated token; another account sees nothing; typed-confirmation delete | `apps/web/e2e/account.spec.ts` |
| Account page: 0 axe WCAG A/AA violations | `a11y.spec.ts` |

Mutation check (manual, all reverted). These were each caught:
- reusable challenges;
- challenges that never expire;
- purpose ignored;
- UV not required;
- clone detection off;
- user handle unchecked;
- revocation ignored;
- sessions that never expire;
- opening or unsaving any lab;
- deletion keeping labs;
- CSRF off;
- cookie not HttpOnly;
- SameSite=Lax.

Removing only the up-front ownership check in `save_lab` was not caught, because the atomic claim
(`WHERE account_id IS NULL`) still blocks a takeover. Removing both was caught.

## Sprint 11: hosting hardening (D-013)

| Property | Evidence |
|----------|----------|
| **Whole suite on PostgreSQL** (386 tests) and **matrix 11/11 on PostgreSQL, incl. MX-08** (16 concurrent submissions → 1 allow) | CI job `api-postgres`; local run on PostgreSQL 16 ([evidence](evidence/matrix-postgres.md)) |
| Fob counters up to 2^53 − 1 and timestamps after 2038 are stored (**both failed on PostgreSQL before the BIGINT fix**) | `test_fob_counter_holds_values_up_to_2_pow_53`, `test_timestamps_after_2038_are_stored` |
| Key, open-challenge and saved-lab limits hold under 15–40 concurrent requests (**18 keys against a limit of 10 on PostgreSQL before the row locks**) | `test_*_limit_holds_under_concurrent_*` (3 tests). With either lock removed, its test fails on PostgreSQL |
| Trusted proxies: `X-Forwarded-For` is read only from trusted peers, right to left; prepended fake hops are ignored; malformed chains fall back to the proxy | `test_resolve_client[…]` (10 cases), `test_rate_limit_key_comes_from_the_trusted_chain` |
| Database rate limiter: shared between two limiter instances, exact under 40-way concurrency, hashed keys only, old windows cleaned | `test_database_limiter_*` (4 tests), `test_app_with_database_rate_store_enforces_limits` |
| API security headers on every response (errors included); HSTS only when enabled; no interactive docs in production | `test_api_responses_carry_security_headers`, `test_hsts_when_enabled`, `test_production_disables_interactive_docs` |
| The production check refuses each unsafe setting individually and lists all of them at once; development is never blocked | `test_each_unsafe_setting_is_reported[…]` (7), `test_development_defaults_are_refused_in_production`, `test_app_refuses_to_start_with_unsafe_production_config` |
| Health returns 503 without leaking details when the database is down | `test_health_reports_a_broken_database_as_503` |
| Web production build sends a CSP and related headers; **the whole app runs under it with zero CSP violations**; an injected `fetch` to another host is blocked | `apps/web/e2e/headers.spec.ts`; every other e2e test also runs under the CSP |

| **Free-subdomain proxy mode:** the API refuses requests without the proxy secret (except health) and refuses forged secrets; the proxy-vouched IP is the rate-limit key; `X-Forwarded-For` is ignored in this mode | `test_requests_that_skip_the_proxy_are_refused`, `test_proxy_vouched_ip_is_the_rate_limit_key`, `test_a_non_ip_client_header_falls_back_to_the_peer` |
| The web proxy forwards only plain path segments to the fixed API origin and only allow-listed headers, and replaces client-sent proxy headers | `apps/web/tests/proxy.test.ts` (4 tests) |
| **The whole e2e suite passes in proxy mode** (browser → web origin → API with secret): 20 tests, including passkeys and cookies through the proxy. The page contacts only its own origin; path tricks get 400; direct API calls get 403 | `KEYGUARD_E2E_MODE=proxy npm run e2e`; CI runs e2e in both modes |

| **Vercel Services mode:** the edge's `x-real-ip` is the rate-limit key and `X-Forwarded-For` is ignored; an invalid header falls back to the peer; the cron cleanup endpoint is inert without `CRON_SECRET` and refuses a wrong bearer; `DATABASE_URL` fallback; the Vercel production config passes only with `CRON_SECRET`; the ASGI entry point boots | `test_platform_ip_header_is_the_rate_limit_key`, `test_invalid_platform_header_falls_back_to_the_peer`, `test_cron_cleanup_requires_the_secret`, `test_database_url_falls_back_to_neons_variable`, `test_vercel_production_config`, `test_asgi_entrypoint_builds_the_app` |
| `vercel.json` services and routing work: checked with `vercel dev --local` (CLI 65.15). Both services start, `/api/*` reaches FastAPI with the original path, and start lab → enroll → unlock is ALLOWED with the page contacting only its own origin | manual, 2026-11-12 |

Mutation check (manual, all reverted). These were each caught:
- trusting `X-Forwarded-For` from any peer;
- reading it left to right;
- an off-by-one in the database limiter;
- storing raw keys;
- HSTS always on;
- allowing the memory store in production;
- removing the lab-row lock (on PostgreSQL);
- removing the account-row lock (on PostgreSQL).

## Known gaps

- Usability sessions with real participants (spec §11 targets) have not been run; see `USABILITY.md`.
- The CI API job has no Node, so the *fresh* interop test is skipped there; the committed vector still runs.
- The web CSP still allows inline scripts (`'unsafe-inline'`); a nonce-based policy is a follow-up (D-013).
- Alerting is the host's job and isn't configured, because nothing is deployed yet.
