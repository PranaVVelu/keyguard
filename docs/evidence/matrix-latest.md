Matrix `keyguard-hardened-v1` · commit `930873c` · 2026-11-12T22:29:58Z · Python 3.12.16 · Darwin arm64 · database **sqlite**

| ID | Scenario | Expected | Observed | Reason | Outcome | ms |
|----|----------|----------|----------|--------|---------|----|
| MX-01 | Active key + fresh challenge | allow | allow | — | ✅ pass | 298.3 |
| MX-02 | Incorrect signature | deny | deny | SIGNATURE_INVALID | ✅ pass | 26.3 |
| MX-03 | Revoked key | deny | deny | KEY_REVOKED | ✅ pass | 37.3 |
| MX-04 | Expired challenge | deny | deny | CHALLENGE_EXPIRED | ✅ pass | 60.4 |
| MX-05 | Consumed challenge replay | deny | deny | CHALLENGE_CONSUMED | ✅ pass | 65.2 |
| MX-06 | Wrong vehicle | deny | deny | SIGNATURE_INVALID | ✅ pass | 26.5 |
| MX-07 | Wrong requested action | deny | deny | SIGNATURE_INVALID | ✅ pass | 26.4 |
| MX-08 | Two+ concurrent submissions (16 threads) | at_most_one_allow | multi | 1 allow / 15 deny | ✅ pass | 90.2 |
| MX-09 | Unknown key | deny | deny | KEY_UNKNOWN | ✅ pass | 20.9 |
| MX-10 | Malformed payload (client-asserted decision field) | reject | reject | REQUEST_INVALID | ✅ pass | 24.6 |
| MX-11 | Cross-lab request | deny | deny | LAB_NOT_FOUND | ✅ pass | 26.6 |

**11/11 passed.** Curated scenarios only; passing does not prove universal security. Relay/proximity attacks are out of scope. Concurrency is proven on the database named in 'database'; CI runs the matrix on both SQLite and PostgreSQL.
