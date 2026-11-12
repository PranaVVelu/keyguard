# KeyGuard: Product Requirements (as built)

This is the PRD from the spec (§1–3), annotated with what the MVP actually delivers. The source of truth for
requirements is still `KeyGuard_Product_and_Engineering_Specification.pdf`. This file records the status.

## Vision and boundary

Make digital vehicle authentication understandable, testable and measurable. The interface only ever shows
decisions made by the backend.

**Fictional vehicles and simulated credentials only.** That means:
- no real vehicle integration;
- no RF, BLE or NFC;
- no copies of proprietary protocols;
- no claim that a signature proves physical proximity.

## Users

| Persona | Need | Where the MVP serves it |
|---------|------|-------------------------|
| Security student | Understand the protocol and test attacks | Inspector (7 stages, byte-level signed message), Attack Lab replay comparison |
| Security engineer | Repeatable authentication validation | 11-row structured matrix in CI, pytest + Playwright suites, `docs/SECURITY_TESTS.md` |
| Vehicle enthusiast | Understand digital access without crypto expertise | Garage flow, plain-language denial reasons, car graphic that mirrors backend state |

## Journeys

| Journey | Status | Automated evidence |
|---------|--------|--------------------|
| Normal: create lab → enroll → challenge → sign locally → verify → unlock → inspect | Done | `e2e/journey.spec.ts` (owner journey), `test_row01_*` |
| Replay: vulnerable verifier may accept; hardened rejects a consumed challenge | Done | Attack Lab in e2e, `test_replay_vulnerable_accepts_and_hardened_rejects` |
| Revocation: two keys, revoke one; revoked key is denied even with a valid signature | Done | `test_row03_*`, revoke step in the e2e journey |

## Backlog status

| ID | Priority | Feature | Status |
|----|----------|---------|--------|
| F01 | P0 | Garage dashboard | ✅ State reflects backend-authorized changes only |
| F02 | P0 | Key enrollment | ✅ Non-extractable Web Crypto key; server stores the SPKI public key only |
| F03 | P0 | Challenge-response | ✅ kg-auth-v1 (D-001), atomic single-use challenges (D-003) |
| F04 | P0 | Protocol inspector | ✅ Challenge, signed bytes, signature, request and 6-check decision trace |
| F05 | P0 | Replay lab | ✅ Isolated vulnerable verifier vs real engine, reproducible (D-005) |
| F06 | P0 | Revocation | ✅ Immediate and idempotent (D-008) |
| F07 | P0 | Automated tests | ✅ pytest, node:test, Playwright, structured matrix; all run in CI and block merges |
| F08 | P1 | Security event dashboard | ✅ Security Analytics: searchable log, pass/fail, failure categories (D-009) |
| F09 | P1 | Tampering scenarios | ✅ Attack Lab `tamper` scenario: stapled and byte-flipped signatures are denied `SIGNATURE_INVALID` by both verifiers (server rebuilds the signed bytes); also matrix MX-02 and the e2e in-flight tamper test |
| F10 | P2 | Key card / fob simulations | ✅ Three fictional credential types (D-010): phone and passive key card (challenge-response), and key fob (kg-fob-v1 rolling counter). Plus Attack Lab `fob-replay` and `fob-capture` |
| F11 | P2 | Proximity visualization | ✅ `/proximity` (conceptual, D-011): an illustrative slider that's never sent, plus the real backend `relay` scenario, which both verifiers accept |
| F12 | P2 | Accounts and saved labs | ✅ Optional passkey accounts (WebAuthn, no passwords, D-012). Save up to 10 labs for 30 days and reopen them in any browser (with a fresh token). HttpOnly session cookie, CSRF header, ownership checked in SQL. Deleting the account removes everything it owns |

## Success metrics (spec §11): where we are

| Metric | Target | Current |
|--------|--------|---------|
| Mandatory security tests | 100% passing | 11/11 matrix rows pass, in CI |
| Unauthorized unlocks in required cases | 0 | 0 observed |
| Usability task completion | ≥ 80% across 5–8 testers | **Not measured yet.** Sessions need real participants (plan in `USABILITY.md`) |
| User-rated clarity | ≥ 4/5 | **Not measured yet** |
| Local median simulated auth response | < 300 ms | Server-side median ≈ 1 ms, p95 ≈ 11 ms (Analytics, local SQLite). Browser round trip not formally benchmarked |

These are targets, not achieved outcomes. A passing curated suite does not prove the system is secure in general.
