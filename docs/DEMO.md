# Demo script (about 8 minutes)

A walkthrough that shows every P0 feature, plus Analytics, using only real backend decisions. Start the stack (`docker
compose up --build`, or the two dev servers from the README) and open http://localhost:3000 in a fresh tab.

| # | Do | Point out |
|---|----|-----------|
| 1 | **Garage → Start a lab** | The lab is a disposable sandbox with one fictional car. Its token is in this tab only, and it expires in 24 h. |
| 2 | **Digital Keys → label "Phone A" → Generate & enroll key** | The key pair is made in the browser and is **non-extractable**. Only the public key goes to the server. The server's fingerprint is checked against the browser's before the key is saved. |
| 3 | Enroll a second key, "Phone B" | It sets up the revocation story later. |
| 4 | **Garage → Request unlock** | **ALLOWED · UNLOCKED**, with the six server checks listed. The car graphic changes *after* the decision. "A valid signature doesn't prove you're physically near the car." |
| 5 | **Inspector → lock → Run lock exchange** | Walk the 7 stages: the challenge (30-second countdown), the client-side binding check, the exact signed bytes split into tag and fields, r‖s, the request and the decision. |
| 6 | **Replay this exact response** | Same bytes, same signature: **DENIED · CHALLENGE_CONSUMED**. The challenge was spent atomically the first time. |
| 7 | **Attack Lab → Run scenario** | Side by side: the isolated **vulnerable** verifier accepts the replay (car unlocked); the **hardened** engine rejects it (car stays locked). Your lab's own car is never touched. |
| 8 | **Digital Keys → Phone A → Revoke → Confirm revoke** | Revocation is immediate. |
| 9 | **Garage** | Only Phone B is offered, and Request unlock is **ALLOWED** with Phone B. |
| 10 | **Analytics** | Pass/fail per category. Failure reasons in plain language. Click `CHALLENGE_CONSUMED` to filter the log to the replay. Search for a key ID. |
| 11 | **Digital Keys → Key fob → enroll**, then **Garage → Press unlock / Press lock** | No challenge: the trace shows the counter rising (0 → 1 → 2). The car remembers the highest counter it has seen. |
| 12 | **Attack Lab → fob replay, then fob capture** | A replayed press is refused (`COUNTER_REPLAYED`). A press captured before the car saw it is **accepted** by the real engine, labelled as a known limitation. That's why phones and cards use challenges. |
| 13 | **Proximity → Run the relay on the real backend** | Drag the slider anywhere: the server allows the relayed card unlock regardless. A valid signature doesn't prove the key is near the car. |
| 14 | (Optional) the evidence | `docs/evidence/matrix-latest.md`: 11/11 mandatory rows with timing. In GitHub Actions, the matrix table is in the run summary. |

## Talking points on limits (say these out loud)

- This is a simulator. There's no real vehicle, no radio and no proprietary protocol.
- Browser keys are not hardware-backed automotive credentials.
- A curated test suite passing is evidence for those cases, not proof the system is secure in general.
- Relay attacks are out of scope by design.
