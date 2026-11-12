# Release gates (spec §11): status at end of Sprint 11

| Gate | Status | Evidence |
|------|--------|----------|
| All seven P0 features work end-to-end and the backend is authoritative | ✅ Met | [PRD.md](PRD.md) backlog; Playwright owner journey drives F01–F06 through the real UI and API |
| No known unauthorized unlock in the mandatory suite; concurrency and cross-lab isolation verified | ✅ Met (SQLite **and PostgreSQL**) | 11/11 matrix rows on both ([SQLite](evidence/matrix-latest.md), [PostgreSQL](evidence/matrix-postgres.md)); MX-08 concurrency, MX-11 cross-lab, e2e "lab is private". CI runs both |
| Attack lab is isolated from the hardened authentication path | ✅ Met | AST import-graph test; scenarios run on disposable state ([ARCHITECTURE.md](ARCHITECTURE.md)) |
| Automated tests run in CI and failures block release | ✅ Met | CI jobs: API + matrix, web, Playwright e2e, Docker smoke test |
| Threat model, architecture, test evidence and limitations are documented | ✅ Met | [THREAT_MODEL.md](THREAT_MODEL.md), [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY_TESTS.md](SECURITY_TESTS.md), [DECISIONS.md](DECISIONS.md) |
| Hosted demo has session isolation, resource limits and event retention controls | ◐ Ready, not hosted | Controls tested (D-009), and production hardening done (D-013): PostgreSQL, shared limiter, trusted proxies, security headers, startup safety check. Remaining: pick a host, set up alerting, run usability sessions ([DEPLOYMENT.md](DEPLOYMENT.md)) |

## Success metrics

| Metric | Status |
|--------|--------|
| Mandatory security tests 100% passing | ✅ |
| 0 unauthorized unlocks in required cases | ✅ |
| ≥ 80% task completion, 5–8 testers | ❌ Not run (needs participants; plan in [USABILITY.md](USABILITY.md)) |
| Clarity ≥ 4/5 | ❌ Not run |
| Local median auth response < 300 ms | ◐ Server-side median ≈ 1 ms; full browser round trip not formally measured |

**Verdict:** the MVP is ready as a local, portfolio-grade demo, and the code is ready to host. The remaining steps are
outside the code:
- choose a host and configure it with the production environment in DEPLOYMENT.md;
- set up alerting;
- run the usability sessions.
