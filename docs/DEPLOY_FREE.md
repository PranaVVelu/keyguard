# Free hosting on Vercel (no domain needed)

One Vercel project runs both apps with [Vercel Services](https://vercel.com/docs/services), which is in beta and on
every plan. Neon Postgres is added from Vercel's Storage tab. There's no domain to buy and no second hosting account.
The design is in D-013.

```
browser ──https──▶ <project>.vercel.app
                     ├─ /api/*  ──▶ service "api"  (FastAPI, Vercel Function, Python 3.12) ──▶ Neon Postgres
                     └─ /*      ──▶ service "web"  (Next.js)
```

Everything is configured in [`vercel.json`](../vercel.json) at the repository root:
- the two services;
- the routing (`/api/*` goes to FastAPI and receives the original path);
- a daily cleanup cron.

**Why this is safe:**
- **One origin.** The website and API share one address, so the passkey session cookie is first-party and the CSP is
  `connect-src 'self'`.
- **One way in.** The API service has **no public route of its own**. Requests reach it only through Vercel's edge,
  which sets `x-real-ip` and overwrites any value a client sends. The API uses that header as the rate-limit key
  (`KEYGUARD_CLIENT_IP_HEADER`). This is only safe because the edge is the only way in; never set that variable on a
  host where clients can reach the API directly.
- **Startup check.** The production check refuses to start without PostgreSQL, HTTPS origins, a Secure cookie, HSTS,
  the database rate store and `CRON_SECRET`.

This was checked locally with `vercel dev --local` (CLI 65.15). Both services started from `vercel.json`, `/api/*`
reached FastAPI, and a full start-lab → enroll → unlock flow passed with the page contacting only its own origin.

## Steps

**1. Create the project.**
In Vercel: **Add New → Project** → import `PranaVVelu/keyguard`, and keep the **root directory at the repository
root**. Vercel reads `vercel.json` and sets up both services. Pick the project name now, because it becomes
`<project>.vercel.app` and the passkeys will be bound to it.

**2. Add the database.**
In the project: **Storage → Create Database → Neon** (free plan) → connect it to the project. Vercel injects
`DATABASE_URL`, which the API uses automatically.
- This creates a Neon account linked to your Vercel account.
- You'll accept Neon's terms in that dialog yourself.

**3. Set environment variables** (Settings → Environment Variables → Production):

| Variable | Value |
|---|---|
| `KEYGUARD_ENV` | `production` |
| `KEYGUARD_WEB_ORIGIN` | `https://<project>.vercel.app` |
| `KEYGUARD_RP_ID` | `<project>.vercel.app` |
| `KEYGUARD_COOKIE_SECURE` | `1` |
| `KEYGUARD_HSTS` | `1` |
| `KEYGUARD_RATE_STORE` | `database` |
| `KEYGUARD_CLIENT_IP_HEADER` | `x-real-ip` |
| `KEYGUARD_CLEANUP_INTERVAL` | `0` (serverless: cleanup runs from the daily cron instead) |
| `CRON_SECRET` | 32+ random characters (`openssl rand -base64 32`) |
| `NEXT_PUBLIC_API_URL` | `same-origin` |

**4. Deploy.**
Redeploy so the variables take effect. Pushes to `main` deploy automatically after that. GitHub shows the deployment
next to CI, and branch protection can make CI required.

**5. Smoke test.**
- `https://<project>.vercel.app/api/health` → `{"status":"ok","database":"postgresql"}`. If the API fails to start, the
  function log lists every production setting that's wrong.
- In the app: start a lab, enroll a key, unlock, create a passkey on the Account page, and save the lab.

## Free-tier notes

- **Python functions cold-start** in a second or two after idle; there's no 15-minute sleep like some free hosts.
- **Hobby cron jobs run at most once a day.** That's enough: labs already stop working at expiry, and the cron only
  deletes their data.
- **Neon free** pauses when idle and wakes in about a second. `pool_pre_ping` handles dropped connections.
- **Passkeys are bound to `<project>.vercel.app`.** Renaming the project or moving to your own domain later means
  creating new passkeys.
- **Preview deployments** get different URLs, so passkeys created on production won't work there. Everything else does.
- **Services is a beta feature.** If it changes, the alternative below needs no code changes.

## Alternative: Render (API) + Vercel (web) + Neon

If you'd rather not use Services, `render.yaml` deploys the API's Docker image to Render's free plan.
- The web app's server-side `/api` proxy (`app/api/[...path]/route.ts`) forwards to it with a shared
  `KEYGUARD_PROXY_SECRET`, and the API refuses anything without that secret.
- Web settings: `NEXT_PUBLIC_API_URL=same-origin`, `KEYGUARD_API_INTERNAL_URL=https://<api>.onrender.com`,
  `KEYGUARD_PROXY_SECRET=<same value as Render>`.
- API settings: as in the table above, but with `KEYGUARD_PROXY_SECRET` instead of `KEYGUARD_CLIENT_IP_HEADER`, and a
  Neon connection string in `KEYGUARD_DATABASE_URL`.
- Render's free instances sleep after about 15 minutes idle. The proxy waits up to 60 s for the first request.

The whole e2e suite runs in this proxy mode in CI (`KEYGUARD_E2E_MODE=proxy`).
