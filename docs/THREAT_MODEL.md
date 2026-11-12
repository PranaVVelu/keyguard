# KeyGuard — Threat Model (drafted Sprint 1, evidence updated through Sprint 8)

Scope: the educational simulator described in the v1.0 spec. Fictional vehicles and simulated
credentials only. This document describes what the system is *designed* to resist; nothing here
counts as demonstrated until a passing test is linked in `SECURITY_TESTS.md`.

## System and trust boundaries

```
[Browser]  ──TB1 (HTTPS, untrusted client)──▶  [FastAPI]  ──TB2──▶  [DB]
  Web Crypto key (non-extractable)               auth engine          vehicles, keys,
  lab_token in sessionStorage                    lab isolation        challenges, events
                                                 attack lab ──TB3 (isolated state)
```

- **TB1:** everything the client sends is untrusted, including IDs, actions, state and success flags.
- **TB2:** the DB is trusted. Every query is scoped by `lab_id`.
- **TB3:** vulnerable-verifier code and state never reach the hardened path (D-005).

## Assets

| ID | Asset | Property |
|----|-------|----------|
| A1 | Vehicle lock state | Integrity: changes only through a verified decision |
| A2 | Public-key registry and key status | Integrity: revocation is immediate |
| A3 | Challenges (nonce, binding, expiry, consumed flag) | Freshness, single use |
| A4 | Lab boundary (`lab_token`) | Confidentiality and integrity across labs |
| A5 | Security events and test results | Integrity, no sensitive material |
| A6 | Client private key | Never leaves the browser (out of server control) |

## Adversaries

- **Adv-1, remote API client:** can send arbitrary HTTP requests, may hold its own valid lab token and
  may have seen earlier traffic for the target lab (replay material).
- **Adv-2, curious lab user:** has a valid token for lab X and wants to read or modify lab Y.
- Out of scope: browser or OS compromise, malicious server operator, network attacker breaking TLS,
  physical relay or proximity attacks, side channels.

## Threats (STRIDE-tagged) → mitigation → required test

| ID | Threat | STRIDE | Mitigation | Test (matrix row) |
|----|--------|--------|-----------|-------------------|
| T1 | Replay a previously valid response | S/T | Conditional-UPDATE single use (D-003) | Consumed challenge replay → Deny |
| T2 | Forged or tampered signature | S/T | ECDSA verify over server-rebuilt bytes (D-001) | Incorrect signature → Deny |
| T3 | Revoked or unknown key | S | Status checked at authenticate time | Revoked / Unknown key → Deny |
| T4 | Expired challenge | S | Server-clock expiry inside the UPDATE | Expired challenge → Deny |
| T5 | Cross-vehicle confusion | E | Key↔vehicle binding; vehicle is in signed bytes | Wrong vehicle → Deny |
| T6 | Cross-action confusion (lock sig reused for unlock) | E | Action is in signed bytes and in the challenge row | Wrong action → Deny |
| T7 | Access to another lab | I/E | Bearer token hash, uniform 404, `lab_id` in all SQL | Cross-lab → Deny |
| T8 | Double-spend via concurrent submissions | T | Atomic conditional UPDATE in one transaction | Concurrent ×N → ≤1 Allow |
| T9 | Malformed input crashes or confuses the parser | D/T | Pydantic strict schemas; length and charset limits; fail closed | Malformed → 4xx, no state change |
| T10 | Client-asserted success or state | T | Server ignores client state; the UI renders only API decisions | Strict schemas reject extra fields; e2e in-flight tamper test shows the UI follows the server's deny |
| T11 | Sensitive data in logs | I | Log IDs and reason codes only; never tokens, nonces, keys or signatures | `test_events_never_contain_secrets` |
| T12 | Resource exhaustion (challenge/lab spam) | D | Rate limits (per client, per lab, lab creation), lab capacity, TTL cleanup, event retention cap, max keys/open challenges per lab (D-009) | `tests/test_limits_and_cleanup.py` |
| T13 | Vulnerable lab code reachable from the hardened path | E | Physical module separation + import-graph test (D-005) | `tests/test_lab_isolation.py` |
| T14 | Weak curve or invalid public key enrolled | S | SPKI must parse as P-256; reject other curves and invalid points | Enrollment negative tests |
| T15 | Replayed key-fob press (F10) | S | kg-fob-v1 counter must rise; advanced only by a valid signature, in one conditional UPDATE (D-010) | `test_fob_api.py` (replay, window, concurrency, junk can't burn the counter); Attack Lab `fob-replay` |
| T16 | Protocol confusion between credential types | S/E | Separate domain tags; the challenge endpoint and engine refuse fob keys, and the fob endpoint refuses phone and card keys | `test_fob_api.py` cross-protocol tests |
| T17 | Fob press captured before it reached the car | S | **Not mitigated by design.** Counters can't detect it; challenge-response credentials avoid it (D-010) | Attack Lab `fob-capture` shows the engine accepting it |
| T19 | Passkey phishing or a credential replayed on another site | S | WebAuthn origin and RP ID checks (D-012) | `test_accounts_api.py`: wrong origin and wrong RP ID rejected |
| T20 | Replayed WebAuthn response | S | Single-use, 5-minute, purpose-bound challenges (conditional UPDATE) | replay and wrong-purpose tests |
| T21 | Session theft or reuse | S/I | HttpOnly cookie, hashed token, 12 h expiry, logout revokes | session tests; e2e checks the cookie isn't readable by script |
| T22 | CSRF on account actions | T | SameSite=Strict, required `X-KeyGuard-CSRF` header, CORS limited to the web origin | `test_state_changes_require_the_csrf_header` |
| T23 | Cross-account access to saved labs | I/E | Ownership checked in SQL; uniform `404`; ownership never transfers | `test_saved_labs_are_private_to_their_account` |
| T24 | Cloned authenticator | S | Sign-counter regression → `PASSKEY_CLONED` | `test_sign_count_regression_is_rejected` |
| T25 | Going around the web proxy (and per-visitor rate limits) by calling the API directly | D/S | With `KEYGUARD_PROXY_SECRET` set, the API refuses requests without the secret; client-sent proxy headers are stripped; only valid IPs are accepted (D-013) | `test_requests_that_skip_the_proxy_are_refused`, `e2e/proxy.spec.ts` |
| T26 | Using the proxy to reach other hosts or paths (SSRF or path tricks) | E | Fixed upstream origin; only plain path segments; allow-listed headers; 64 KB body cap | `apps/web/tests/proxy.test.ts`, `e2e/proxy.spec.ts` |
| T18 | Relay of a passive card (F11) | S | **Out of scope** (non-claim below). Distance bounding and UWB aren't implemented (D-011) | Attack Lab `relay` shows the engine accepting it |

## Explicit non-claims

- Key fob counters do not stop a press that was captured before the car received it (T17).

- A valid signature does **not** prove physical proximity. Relay attacks are out of scope.
- Browser non-extractable keys are **not** equivalent to hardware-backed automotive credentials.
- Passing the curated test matrix does not prove the system is secure in general.

## Failure classification (for test evidence)

- **Security failure:** unauthorized acceptance (any Deny row observed as Allow).
- **Functional failure:** a valid request is denied.
- **Infrastructure failure:** the test result is untrustworthy or incomplete (timeout, setup error).
