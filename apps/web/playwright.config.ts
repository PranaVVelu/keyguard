import { tmpdir } from "node:os";
import { join } from "node:path";

import { defineConfig, devices } from "@playwright/test";

import { API_PORT, PROXY_MODE, WEB_PORT } from "./e2e/ports";

// End-to-end suite: real Chromium against a real API and a production build of the web app.
// Separate ports and a throwaway database, so it never touches a dev server or your local keyguard.db.
const DB = join(tmpdir(), `keyguard-e2e-${Date.now()}.db`);
// Proxy mode (free-subdomain hosting): a per-run secret shared by the web proxy and the API.
const PROXY_SECRET = `e2e-${Date.now()}-${Math.random().toString(36).slice(2)}-padding-to-32`;
const proxyApiEnv: Record<string, string> = PROXY_MODE ? { KEYGUARD_PROXY_SECRET: PROXY_SECRET } : {};
const webEnv: Record<string, string> = PROXY_MODE
  ? {
      NEXT_PUBLIC_API_URL: "same-origin",
      KEYGUARD_API_INTERNAL_URL: `http://localhost:${API_PORT}`,
      KEYGUARD_PROXY_SECRET: PROXY_SECRET,
      NEXT_DIST_DIR: ".next-e2e-proxy",
    }
  : { NEXT_PUBLIC_API_URL: `http://localhost:${API_PORT}`, NEXT_DIST_DIR: ".next-e2e" };

export default defineConfig({
  testDir: "e2e",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  forbidOnly: !!process.env.CI,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  timeout: 60_000,
  use: {
    baseURL: `http://localhost:${WEB_PORT}`,
    trace: "retain-on-failure",
    ...devices["Desktop Chrome"],
  },
  webServer: [
    {
      command: `uv run uvicorn app.main:create_app --factory --port ${API_PORT} --no-proxy-headers`,
      cwd: "../../services/api",
      url: `http://localhost:${API_PORT}/api/health`,
      env: {
        KEYGUARD_DATABASE_URL: `sqlite:///${DB}`,
        KEYGUARD_WEB_ORIGIN: `http://localhost:${WEB_PORT}`,
        ...proxyApiEnv,
      },
      reuseExistingServer: false,
      timeout: 60_000,
    },
    {
      command: `npm run build && npx next start -p ${WEB_PORT}`,
      url: `http://localhost:${WEB_PORT}`,
      env: webEnv,
      reuseExistingServer: false,
      timeout: 240_000,
    },
  ],
});
