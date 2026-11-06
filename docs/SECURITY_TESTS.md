# Security Test Evidence

Last run: 2026-11-05, local (macOS arm64, Python 3.12.16, SQLite WAL). **67 passed, 0 failed.**
Command: `cd services/api && uv run pytest -v`

CI (`.github/workflows/ci.yml`) runs the same suite. First green run: 2026-11-06, run 42150651689 (API + web jobs passed).

## Mandatory hardened matrix (spec §7): status after Sprint 1

"Layer" says where the property is currently proven. Most rows can only be fully proven end-to-end once
`POST /api/labs/{id}/authenticate` exists (Sprint 3). Until then, a row proven at the protocol or store
layer is **not** an end-to-end result.

| Scenario | Expected | Sprint 1 evidence | Layer | End-to-end |
|----------|----------|-------------------|-------|------------|
| Active key + fresh challenge | Allow | `test_round_trip_then_replay_rejected` (verify + consume) | protocol + store | Sprint 3 |
| Incorrect signature | Deny | `test_signature_from_other_key_is_rejected`, `test_verify_vectors[tampered-signature]` | protocol | Sprint 3 |
| Revoked key | Deny | none yet | — | Sprint 4 |
| Expired challenge | Deny | `test_expired_challenge_cannot_be_consumed` | store | Sprint 3 |
| Consumed challenge replay | Deny | `test_round_trip_then_replay_rejected` | store | Sprint 3 |
| Wrong vehicle | Deny | `test_signature_for_other_vehicle_is_rejected` | protocol | Sprint 4 |
| Wrong requested action | Deny | `test_signature_for_lock_does_not_authorize_unlock` | protocol | Sprint 4 |
| Two concurrent submissions | ≤1 succeeds | `test_concurrent_consumers_at_most_one_succeeds[0-9]` (16 threads × 10 rounds) | store (SQLite) | Sprint 4 |
| Unknown key | Deny | none yet | — | Sprint 3 |
| Malformed payload | Reject safely | `test_encoder_rejects_invalid_fields`, `test_verify_vectors[truncated/r-equals-n/all-zero]`, `test_rejects_unsupported_or_invalid_keys`, `test_errors_never_echo_input` | protocol + API | Sprint 3 |
| Cross-lab request | Deny | `test_cross_lab_request_is_denied_identically`, `test_consumption_is_lab_scoped`, `test_expired_lab_is_indistinguishable_from_unknown` | API + store | ✅ for the endpoints that exist |

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

## Known gaps

- No TypeScript or Web Crypto interop test yet. The vectors exist, but the browser encoder comes in Sprint 2.
- The concurrency test is proven on SQLite only. PostgreSQL must be re-verified before hosting.
- Each test does not yet record scenario ID, timing or failure category (spec §7). That structured runner comes in Sprint 4.
