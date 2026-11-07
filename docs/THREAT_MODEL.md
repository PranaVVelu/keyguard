# KeyGuard — Threat Model (Sprint 1 draft)

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
| T10 | Client-asserted success or state | T | Server ignores client state; the UI renders only API decisions | Covered by API design and review |
| T11 | Sensitive data in logs | I | Log IDs and reason codes only; never tokens or signatures in full | Log-scrubbing unit test |
| T12 | Resource exhaustion (challenge/lab spam) | D | Rate limits, TTL cleanup, max entities per lab | Sprint 7 |
| T13 | Vulnerable lab code reachable from the hardened path | E | Physical module separation + import-graph test (D-005) | `tests/test_lab_isolation.py` |
| T14 | Weak curve or invalid public key enrolled | S | SPKI must parse as P-256; reject other curves and invalid points | Enrollment negative tests |

## Explicit non-claims

- A valid signature does **not** prove physical proximity. Relay attacks are out of scope.
- Browser non-extractable keys are **not** equivalent to hardware-backed automotive credentials.
- Passing the curated test matrix does not prove the system is secure in general.

## Failure classification (for test evidence)

- **Security failure:** unauthorized acceptance (any Deny row observed as Allow).
- **Functional failure:** a valid request is denied.
- **Infrastructure failure:** the test result is untrustworthy or incomplete (timeout, setup error).
