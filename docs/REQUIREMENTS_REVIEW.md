# Requirements Review: KeyGuard spec v1.0

Reviewed: 2026-11-05. Source: `KeyGuard_Product_and_Engineering_Specification.pdf`
(the extracted text is in `SPEC_EXTRACTED.txt`).

## Summary

The spec is well scoped: P0 features are clear, the threat matrix maps directly onto tests, and the safety
boundary is explicit. The gaps are mostly protocol and session details that the spec deliberately leaves
open (§12, §13). The proposals for those are in `DECISIONS.md`.

## Ambiguities and gaps

| # | Spec ref | Issue | Proposal |
|---|----------|-------|----------|
| 1 | §5 | No signed-message byte format | D-001: length-prefixed fields with a domain tag |
| 2 | §5 | Signature encoding between Web Crypto and Python not specified (P1363 vs DER) | D-001: P1363 on the wire, converted server-side |
| 3 | §6, §12 | Lab token issuance, storage and expiry undefined | D-002: bearer token, hash stored, 24 h TTL, uniform 404 |
| 4 | §5 | Does a *failed* attempt consume the challenge? | D-003: burn on any attempt (open decision **O-2**) |
| 5 | §5 | Challenge TTL not given | 30 s |
| 6 | §5 | Which timestamp is authoritative for expiry? | Server stored `expires_at`; the client copy is only bound in the signature |
| 7 | §6 | Is a key bound to one vehicle, and which actions does it authorize? | One vehicle per key (matches the `digital_keys.vehicle_id` field); lock and unlock both allowed |
| 8 | §6 | `/authenticate` request body undefined | `{challenge_id, key_id, signature}`; nothing else is trusted |
| 9 | §6 | `lab_runs` / `security_events` lack a `latency_ms` field, but §7 requires timing | Add `duration_ms` to both |
| 10 | §6 | `digital_keys` has no fingerprint or label | Add `fingerprint` (SHA-256 of SPKI) and `label` |
| 11 | §12 | Browser key persistence across refreshes | Sprint 2: IndexedDB (non-extractable CryptoKey survives refresh), scoped to the lab |
| 12 | §6 | Lab seeding: who creates the vehicle? | `POST /api/labs` creates a lab with one fictional vehicle |
| 13 | §7 | "Malformed payload → reject safely" is open-ended | Pydantic strict mode, max lengths, stable `error.code`, no state change, fuzz a few shapes |
| 14 | §9 | Python version unspecified; system has 3.9.6 (EOL) | Python 3.12 (open decision **O-1**) |
| 15 | §10 vs §13 | Week 1 includes the Garage shell; the Sprint-1 checklist also requires CI | Include both; CI runs on GitHub Actions once the repo is pushed |
| 16 | §11 | "Under 300 ms" target has no measurement method | Record `duration_ms` per request; report the median from the test run |

## Open decisions (need your call)

- **O-1:** ✅ Accepted: Python 3.12, installed via uv (3.12.16).
- **O-2:** ✅ Accepted: burn a challenge on any failed attempt.
- **O-3:** ✅ Accepted: lab token in `sessionStorage`.
- **O-4:** ✅ Accepted: D-001 encoding and D-002 lab authorization as written.

## Sprint 1 plan (Week 1 + spec §13 checklist)

Scope: the authentication protocol core and tests come first; UI is a mocked shell.

1. **Repo scaffold:** `apps/web` (Next.js + TS + Tailwind), `services/api` (FastAPI), `docs/`, README, `.gitignore`.
2. **Protocol module** `services/api/app/security/protocol.py`: canonical encoder, signature parsing (P1363→DER),
   SPKI parsing with a P-256 check, verify function.
3. **Test vectors** `docs/test-vectors/kg-auth-v1.json`, generated once and checked by pytest
   (and by the TS encoder in Sprint 2).
4. **Standalone protocol test** (the §13 acceptance item): generate key → issue challenge → sign → verify → mark consumed →
   replay rejected. Plus tamper, wrong-vehicle and wrong-action byte-binding tests.
5. **Challenge store with atomic consume** on SQLite, including a threaded concurrency test (N parallel → exactly 1 succeeds).
6. **Minimal API:** `POST /api/labs` (token issuance) and `GET /api/labs/{id}/vehicles`, with a cross-lab 404 test.
7. **Garage shell:** a single page with a visible "MOCK STATE: not backend-verified" banner.
8. **CI:** a GitHub Actions workflow running pytest and the web lint/build.
9. **Docs:** README setup, `SECURITY_TESTS.md` mapping each passing test to a matrix row.

Exit criteria: every §13 checklist item is met, with test output recorded in `SECURITY_TESTS.md`.
Anything not finished is listed as not finished.

## Deferred (not Sprint 1)

Browser signing integration (S2), full authenticate endpoint and revocation (S3–4), vulnerable verifier (S5),
inspector UI (S6), rate limits and analytics (S7). P1/P2 features wait until all P0 features pass (spec scope rule).
