# Usability and accessibility

Spec §11 targets **≥ 80% task completion across 5–8 testers** and **average clarity ≥ 4/5**. Those need real
participants and **have not been run yet**. This page has the session plan, plus what has been verified so far without
participants.

## Automated and heuristic checks done (Sprint 8)

| Check | Result | Evidence |
|-------|--------|----------|
| WCAG 2.1 A/AA automated scan (axe-core) of all 5 pages, empty and with real data | 0 violations after one fix | `apps/web/e2e/a11y.spec.ts` |
| Keyboard-only: start lab → enroll → unlock | Works | `the core journey works with the keyboard alone` |
| Reduced motion | Car light flash and lock transition are disabled under `prefers-reduced-motion` | `VehicleVisual.tsx` |
| Live regions | Lock state, decision panel and event log use `aria-live`; errors use `role="alert"` | code review |

**Found and fixed in this pass:**
1. **Links shown by colour only** (axe `link-in-text-block`, serious): "All events →" in the Garage and "Enroll a key"
   inline links are now underlined.
2. **Expired lab disappeared silently.** After the 24 h TTL (or cleanup), pages dropped back to "No lab yet" with no
   explanation. They now say the lab expired or was removed and what to do (e2e test added).
3. **Rate-limit errors didn't say when to retry.** The client now appends "try again in N s" from `Retry-After`
   (unit-tested; non-numeric values are ignored).
4. **The Analytics timing stat was cryptic** ("1/11 ms"). It's now labelled "Server check time (median · p95)".

Automated scans catch only a subset of accessibility problems. Screen-reader passes (VoiceOver, NVDA) are still to
do.

## Session plan (5–8 participants, ~25 min each)

Recruit across the three personas: security student, security engineer, and vehicle enthusiast with no crypto
background. Use a fresh browser profile and the local stack. Think-aloud; the facilitator doesn't help unless the
participant is stuck for 2 minutes.

| Task | Success criterion |
|------|-------------------|
| T1. Start a lab and add a phone key | Key shows ACTIVE / "in this browser" without help |
| T2. Unlock the car | Unlock decision ALLOWED; participant can say who decided (the server) |
| T3. Find out why a replayed response fails | Uses the Inspector replay or Attack Lab; explains "the challenge can only be used once" |
| T4. Stop a lost phone from working | Revokes the right key; confirms the other key still works |
| T5. Find how many attempts failed and why | Uses Analytics; names the top failure reason |

After the session, the participant rates clarity from 1 to 5 for each page and overall, and is asked "What does a valid
signature *not* prove?" (expected: physical proximity).

Record per task: completed (Y/N), time, number of errors, and quotes. Report completion %, mean clarity, and the top 5
issues with severity. File fixes before any public release ([DEPLOYMENT.md](DEPLOYMENT.md), gate 7).
