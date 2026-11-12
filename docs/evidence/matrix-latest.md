Matrix `keyguard-hardened-v1` · commit `a9c6379` · 2026-11-12T21:54:03Z · Python 3.12.16 · Darwin arm64

| ID | Scenario | Expected | Observed | Reason | Outcome | ms |
|----|----------|----------|----------|--------|---------|----|
| MX-01 | Active key + fresh challenge | allow | allow | — | ✅ pass | 196.2 |
| MX-02 | Incorrect signature | deny | deny | SIGNATURE_INVALID | ✅ pass | 25.3 |
| MX-03 | Revoked key | deny | deny | KEY_REVOKED | ✅ pass | 26.3 |
| MX-04 | Expired challenge | deny | deny | CHALLENGE_EXPIRED | ✅ pass | 23.5 |
| MX-05 | Consumed challenge replay | deny | deny | CHALLENGE_CONSUMED | ✅ pass | 38.0 |
| MX-06 | Wrong vehicle | deny | deny | SIGNATURE_INVALID | ✅ pass | 23.9 |
| MX-07 | Wrong requested action | deny | deny | SIGNATURE_INVALID | ✅ pass | 24.3 |
| MX-08 | Two+ concurrent submissions (16 threads) | at_most_one_allow | multi | 1 allow / 15 deny | ✅ pass | 231.9 |
| MX-09 | Unknown key | deny | deny | KEY_UNKNOWN | ✅ pass | 31.7 |
| MX-10 | Malformed payload (client-asserted decision field) | reject | reject | REQUEST_INVALID | ✅ pass | 57.2 |
| MX-11 | Cross-lab request | deny | deny | LAB_NOT_FOUND | ✅ pass | 28.7 |

**11/11 passed.** Curated scenarios only; passing does not prove universal security. Relay/proximity attacks are out of scope. Concurrency proven on SQLite.
