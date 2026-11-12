# Free hosting: Vercel + Render + Neon

This setup runs KeyGuard on free subdomains, with no domain purchase. It satisfies every code gate in
[DEPLOYMENT.md](DEPLOYMENT.md). The design is in D-013.

```
browser ──https──▶  <project>.vercel.app          (Next.js web app)
                     └─ /api/* route ──https──▶  keyguard-api.onrender.com   (FastAPI, Docker)
                        + X-KeyGuard-Proxy-Secret      └──▶  Neon PostgreSQL
                        + X-KeyGuard-Client-IP
```

**Why a proxy?**
- The browser only ever sees the Vercel origin, so the passkey session cookie is first-party and the CSP is
  `connect-src 'self'`.
- The API refuses anything that doesn't carry the proxy's secret (`403 PROXY_REQUIRED`). That means nobody can go
  around the web app, or around per-visitor rate limits.
- Vercel's edge sets `x-real-ip` and overwrites any value a client sends, and the proxy passes that IP to the API.

## What you'll need to do yourself

Creating accounts and connecting GitHub happen in your own browser, on each provider's sign-up page. Claude won't
create accounts or enter passwords for you.

1. Sign up for **[Neon](https://neon.tech)** (free Postgres), **[Render](https://render.com)** and
   **[Vercel](https://vercel.com)**. Signing in with GitHub is easiest.
2. Allow Render and Vercel to read the `PranaVVelu/keyguard` repository when they ask.

## Steps

**1. Database (Neon)**
- Create a project. Any region close to Render's (for example US West) works.
- Copy the **pooled** connection string (`postgresql://…?sslmode=require`). The API accepts it as-is.

**2. API (Render)**
- New → **Blueprint** → choose this repository. Render reads `render.yaml` and creates `keyguard-api`.
- Fill in the three prompted values:

| Variable | Value |
|---|---|
| `KEYGUARD_DATABASE_URL` | the Neon connection string |
| `KEYGUARD_WEB_ORIGIN` | `https://<your-project>.vercel.app` (pick the Vercel project name first, in step 3) |
| `KEYGUARD_RP_ID` | `<your-project>.vercel.app` |

- After the first deploy, open the service's **Environment** tab and copy the generated `KEYGUARD_PROXY_SECRET`.
- Check that `https://keyguard-api.onrender.com/api/health` returns `{"status":"ok","database":"postgresql"}`. If the API
  refuses to start, the log lists exactly which production setting is wrong.

**3. Web app (Vercel)**
- Add New → Project → import the repository, and set **Root Directory** to `apps/web`.
- Environment variables (Production):

| Variable | Value |
|---|---|
| `NEXT_PUBLIC_API_URL` | `same-origin` |
| `KEYGUARD_API_INTERNAL_URL` | `https://keyguard-api.onrender.com` |
| `KEYGUARD_PROXY_SECRET` | the value copied from Render |
| `KEYGUARD_HSTS` | `1` |

- Deploy, then open `https://<your-project>.vercel.app`.

**4. Smoke test**
- Start a lab, enroll a key and unlock.
- Create a passkey on the Account page.
- Check that `curl -X POST https://keyguard-api.onrender.com/api/labs` returns `403 PROXY_REQUIRED`.

## Free-tier behaviour to know about

- **Render free instances sleep after about 15 minutes idle.** The first request afterwards can take up to a minute.
  The proxy waits up to 60 s (`maxDuration`), and if it still times out it says the API "may be waking up".
- **Neon free** pauses compute when idle and resumes in about a second. `pool_pre_ping` handles the dropped connections.
- **Passkeys are bound to `<your-project>.vercel.app`.** Renaming the Vercel project, or later moving to your own
  domain, means creating new passkeys. That's by design.
- **Alerting:** Render emails on failed deploys and health checks. For uptime alerts, point a free monitor at
  `/api/health`.
