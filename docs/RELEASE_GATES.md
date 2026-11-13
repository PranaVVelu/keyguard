# Release gates (spec §11): status at end of Sprint 11 (deployed 2026-11-13)

| Gate | Status | Evidence |
|------|--------|----------|
| All seven P0 features work end-to-end and the backend is authoritative | ✅ Met | [PRD.md](PRD.md) backlog; Playwright owner journey drives F01–F06 through the real UI and API |
| No known unauthorized unlock in the mandatory suite; concurrency and cross-lab isolation verified | ✅ Met (SQLite **and PostgreSQL**) | 11/11 matrix rows on both ([SQLite](evidence/matrix-latest.md), [PostgreSQL](evidence/matrix-postgres.md)); MX-08 concurrency, MX-11 cross-lab, e2e "lab is private". CI runs both |
| Attack lab is isolated from the hardened authentication path | ✅ Met | AST import-graph test; scenarios run on disposable state ([ARCHITECTURE.md](ARCHITECTURE.md)) |
| Automated tests run in CI and failures block release | ✅ Met | CI jobs: API + matrix, web, Playwright e2e, Docker smoke test |
| Threat model, architecture, test evidence and limitations are documented | ✅ Met | [THREAT_MODEL.md](THREAT_MODEL.md), [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY_TESTS.md](SECURITY_TESTS.md), [DECISIONS.md](DECISIONS.md) |
| Hosted demo has session isolation, resource limits and event retention controls | ✅ Met (hosted) | Controls tested (D-009) and hardened for production (D-013). Live at https://keyguard-six.vercel.app (Vercel Services + Neon Postgres), with a production smoke test of isolation, limits, headers and the core flows ([SECURITY_TESTS.md](SECURITY_TESTS.md#live-deployment-smoke-test)). Alerting beyond Vercel's built-in logs isn't set up |

## Success metrics

| Metric | Status |
|--------|--------|
| Mandatory security tests 100% passing | ✅ |
| 0 unauthorized unlocks in required cases | ✅ |
| ≥ 80% task completion, 5–8 testers | ❌ Not run (needs participants; plan in [USABILITY.md](USABILITY.md)) |
| Clarity ≥ 4/5 | ❌ Not run |
| Local median auth response < 300 ms | ◐ Server-side median ≈ 1 ms; full browser round trip not formally measured |

**Verdict:** the MVP is a hosted, portfolio-grade demo. The remaining steps are outside the code:
- run the usability sessions;
- optionally, add alerting on top of Vercel's logs.
