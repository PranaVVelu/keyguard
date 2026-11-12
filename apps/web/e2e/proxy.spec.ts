import { expect, test } from "@playwright/test";

import { API_DIRECT_URL, PROXY_MODE } from "./ports";

// Free-subdomain hosting (D-013): only meaningful when the suite runs with KEYGUARD_E2E_MODE=proxy.
test.skip(!PROXY_MODE, "proxy mode only");

test("the API refuses requests that bypass the web proxy", async ({ request }) => {
  const direct = await request.post(`${API_DIRECT_URL}/api/labs`);
  expect(direct.status()).toBe(403);
  expect((await direct.json()).error.code).toBe("PROXY_REQUIRED");
  // A forged secret doesn't help either.
  const forged = await request.post(`${API_DIRECT_URL}/api/labs`, {
    headers: { "X-KeyGuard-Proxy-Secret": "guess".repeat(10), "X-KeyGuard-Client-IP": "198.51.100.1" },
  });
  expect(forged.status()).toBe(403);
  // The host's health check is the one exception.
  expect((await request.get(`${API_DIRECT_URL}/api/health`)).status()).toBe(200);
});

test("the same request through the web origin works, and path tricks are refused", async ({ request }) => {
  const viaWeb = await request.post("/api/labs");
  expect(viaWeb.status()).toBe(201);
  expect((await viaWeb.json()).lab_id).toMatch(/^lab_/);
  for (const bad of ["/api/labs/..%2F..%2Fhealth", "/api/labs/evil.example", "/api/a/b/c/d/e/f/g/h/i"]) {
    expect((await request.get(bad)).status(), bad).toBe(400);
  }
  // Client-sent proxy headers are stripped and replaced, so nobody can pick their own rate-limit identity.
  const spoof = await request.post("/api/labs", { headers: { "X-KeyGuard-Proxy-Secret": "x", "X-KeyGuard-Client-IP": "1.1.1.1" } });
  expect(spoof.status()).toBe(201);
});

test("the page only ever talks to its own origin", async ({ page }) => {
  const hosts = new Set<string>();
  page.on("request", (r) => hosts.add(new URL(r.url()).host));
  await page.goto("/");
  await page.getByRole("button", { name: "Start a lab" }).click();
  await expect(page.getByRole("button", { name: "End lab" })).toBeVisible();
  expect([...hosts]).toEqual([new URL(page.url()).host]);
});
