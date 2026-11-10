Matrix `keyguard-hardened-v1` · commit `86195ce` · 2026-11-10T02:00:39Z · Python 3.12.16 · Darwin arm64

| ID | Scenario | Expected | Observed | Reason | Outcome | ms |
|----|----------|----------|----------|--------|---------|----|
| MX-01 | Active key + fresh challenge | allow | allow | — | ✅ pass | 285.0 |
| MX-02 | Incorrect signature | deny | deny | SIGNATURE_INVALID | ✅ pass | 31.2 |
| MX-03 | Revoked key | deny | deny | KEY_REVOKED | ✅ pass | 33.8 |
| MX-04 | Expired challenge | deny | deny | CHALLENGE_EXPIRED | ✅ pass | 30.6 |
| MX-05 | Consumed challenge replay | deny | deny | CHALLENGE_CONSUMED | ✅ pass | 48.6 |
| MX-06 | Wrong vehicle | deny | deny | SIGNATURE_INVALID | ✅ pass | 29.8 |
| MX-07 | Wrong requested action | deny | deny | SIGNATURE_INVALID | ✅ pass | 30.2 |
| MX-08 | Two+ concurrent submissions (16 threads) | at_most_one_allow | multi | 1 allow / 15 deny | ✅ pass | 122.8 |
| MX-09 | Unknown key | deny | deny | KEY_UNKNOWN | ✅ pass | 23.0 |
| MX-10 | Malformed payload (client-asserted decision field) | reject | reject | REQUEST_INVALID | ✅ pass | 27.9 |
| MX-11 | Cross-lab request | deny | deny | LAB_NOT_FOUND | ✅ pass | 56.3 |

**11/11 passed.** Curated scenarios only; passing does not prove universal security. Relay/proximity attacks are out of scope. Concurrency proven on SQLite.
