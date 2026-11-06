# Design Direction

Status: **draft** (2026-11-05). This file guides UI work in Sprints 2–8. The spec's rules still win:
dark automotive styling, the backend is authoritative, accessible labels and keyboard navigation, and
no UI-only "success".

## References (from the project owner)

Use these for the qualities listed below, not as templates to copy. KeyGuard keeps its own identity.

- **nithinved.me:** dark engineering portfolio.
  - Large bold sans headline with a muted second line, and a **monospace** subtitle/metadata line.
  - One dominant **hero panel** holding an interactive 3D model, with a spec label in the corner
    (`421 × 414 × 417 mm`) and small **pill segmented toggles** (`3D CAD · Demo · Render`).
  - Numbered sections (`01 / 03`), short captions under media, and generous vertical rhythm.
  - Quiet controls (pause, reset, fullscreen) tucked into the panel corners.
- **amjeff.com:** light, minimal product-design portfolio.
  - A loading counter as the intro moment.
  - A clean **card grid**: each card is a large media tile above a two-column meta row
    (title + date on the left, type + award on the right) with small colour-square markers.
  - Its *GauchoClass* card shows a strong dark dashboard: big numeric tiles, a highlighted title chip
    and a simple bar chart. This is a good pattern for **Security Analytics**.

## What KeyGuard takes from them

| Pattern | Where in KeyGuard |
|---------|-------------------|
| Bold sans headline + monospace meta line | Page headers ("Garage", then a mono line: `lab_… · expires 23:59 · kg-auth-v1`) |
| Hero panel with a corner spec label and pill toggles | **Garage**: the vehicle in one large panel; toggles `Vehicle · Keys · Last decision`; corner label shows the lock state *as returned by the API* |
| Numbered stepper (`01 / 07`) | **Inspector**: one step per protocol stage (challenge → sign → verify key → verify binding → verify signature → consume → decision) |
| Card grid with a two-column meta row | **Attack Lab**: one card per scenario; meta row shows expected vs. observed, with coloured markers |
| Dark numeric tiles + bar chart | **Security Analytics**: allow/deny counts, failure categories, latency median |
| Monospace for machine values | IDs, nonces, fingerprints, hex bytes, reason codes |

## Visual tokens (direction, finalized in Sprint 6)

- Background near-black (`#0b0d10`), panels one step lighter, hairline borders. Already in `globals.css`.
- Type: a modern grotesk for headings and body, plus a monospace for data. Both self-hosted, so the
  build needs no network.
- Colour stays restrained. One accent for focus and interaction, and status colours used *only* for
  backend decisions: allow = green, deny = red, mock/unverified = amber.
- Motion is subtle: vehicle lock/unlock transitions run **only after** an API decision arrives, never
  optimistically.

## Guardrails

- The 3D/vehicle visual is decoration. It must never be the thing that "shows" an unlock happened; the
  decision text and inspector trace are the source of truth.
- Every interactive control works with the keyboard and has a visible focus ring.
- Status is never conveyed by colour alone. Always pair it with text (`DENIED · CHALLENGE_CONSUMED`).
- No 3D model or animation work before the P0 features pass (spec scope rule). A static vehicle
  illustration is fine until Sprint 6.
