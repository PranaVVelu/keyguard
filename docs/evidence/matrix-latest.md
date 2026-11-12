Matrix `keyguard-hardened-v1` · commit `766f556` · 2026-11-12T22:07:38Z · Python 3.12.16 · Darwin arm64

| ID | Scenario | Expected | Observed | Reason | Outcome | ms |
|----|----------|----------|----------|--------|---------|----|
| MX-01 | Active key + fresh challenge | allow | allow | — | ✅ pass | 411.7 |
| MX-02 | Incorrect signature | deny | deny | SIGNATURE_INVALID | ✅ pass | 32.0 |
| MX-03 | Revoked key | deny | deny | KEY_REVOKED | ✅ pass | 41.0 |
| MX-04 | Expired challenge | deny | deny | CHALLENGE_EXPIRED | ✅ pass | 34.2 |
| MX-05 | Consumed challenge replay | deny | deny | CHALLENGE_CONSUMED | ✅ pass | 76.0 |
| MX-06 | Wrong vehicle | deny | deny | SIGNATURE_INVALID | ✅ pass | 32.0 |
| MX-07 | Wrong requested action | deny | deny | SIGNATURE_INVALID | ✅ pass | 31.8 |
| MX-08 | Two+ concurrent submissions (16 threads) | at_most_one_allow | multi | 1 allow / 15 deny | ✅ pass | 169.3 |
| MX-09 | Unknown key | deny | deny | KEY_UNKNOWN | ✅ pass | 24.5 |
| MX-10 | Malformed payload (client-asserted decision field) | reject | reject | REQUEST_INVALID | ✅ pass | 27.9 |
| MX-11 | Cross-lab request | deny | deny | LAB_NOT_FOUND | ✅ pass | 31.3 |

**11/11 passed.** Curated scenarios only; passing does not prove universal security. Relay/proximity attacks are out of scope. Concurrency proven on SQLite.
