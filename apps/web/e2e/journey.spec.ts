import { expect, test, type Page } from "@playwright/test";

// The whole owner journey through the real UI, API and Web Crypto, in one lab.
// Every assertion reads what the backend decided, as rendered by the app.

/** Navigate with the primary nav (in-page links can share a name, e.g. "Step through it in the Inspector"). */
async function nav(page: Page, name: string) {
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name, exact: true }).click();
}

async function startLab(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Start a lab" }).click();
  await expect(page.getByRole("button", { name: "End lab" })).toBeVisible();
}

async function enroll(page: Page, label: string) {
  await nav(page, "Digital Keys");
  await page.getByLabel("Label").fill(label);
  await page.getByRole("button", { name: "Generate & enroll key" }).click();
  const card = page.getByRole("listitem").filter({ hasText: label });
  await expect(card.getByText("active", { exact: true })).toBeVisible();
  await expect(card.getByText("in this browser")).toBeVisible();
}

test("owner journey: enroll, unlock, replay blocked, attack lab (replay + tamper + substitute), revoke, analytics", async ({ page }) => {
  await startLab(page);
  await enroll(page, "Phone A");

  // The private key really is non-extractable: read the stored CryptoKey from IndexedDB and try to export it.
  const exportResult = await page.evaluate(async () => {
    const db: IDBDatabase = await new Promise((res, rej) => {
      const r = indexedDB.open("keyguard");
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    const rows: { privateKey: CryptoKey }[] = await new Promise((res, rej) => {
      const r = db.transaction("device-keys").objectStore("device-keys").getAll();
      r.onsuccess = () => res(r.result);
      r.onerror = () => rej(r.error);
    });
    const key = rows[0].privateKey;
    try {
      await crypto.subtle.exportKey("pkcs8", key);
      return { extractable: key.extractable, exported: true };
    } catch (e) {
      return { extractable: key.extractable, exported: false, error: (e as Error).name };
    }
  });
  expect(exportResult).toEqual({ extractable: false, exported: false, error: "InvalidAccessError" });

  // Garage: unlock is decided by the backend and the state shown comes from it.
  await nav(page, "Garage");
  await page.getByRole("button", { name: "Request unlock" }).click();
  await expect(page.getByText("ALLOWED · UNLOCKED")).toBeVisible();
  await expect(page.getByRole("region", { name: "KG Coupe (fictional)" }).getByText("unlocked", { exact: true })).toBeVisible();
  await expect(page.getByText(/Latest event: Authenticate · unlock/)).toBeVisible();

  // Inspector: run a lock exchange, then replay the exact same signed response.
  await nav(page, "Inspector");
  await page.getByRole("radio", { name: "lock", exact: true }).click();
  await page.getByRole("button", { name: "Run lock exchange" }).click();
  await expect(page.getByText("ALLOWED · LOCKED")).toBeVisible();
  await page.getByRole("button", { name: "Replay this exact response" }).click();
  await expect(page.getByText("DENIED · CHALLENGE_CONSUMED")).toBeVisible();

  // Attack Lab: the isolated vulnerable verifier accepts the replay; the real engine rejects it.
  await nav(page, "Attack Lab");
  await page.getByRole("button", { name: "Run scenario: Replay a captured unlock" }).click();
  await expect(page.getByText(/REPLAY ACCEPTED/)).toBeVisible();
  await expect(page.getByText(/REPLAY REJECTED · CHALLENGE_CONSUMED/)).toBeVisible();

  // Tamper (F09): an edited signed response fails in BOTH verifiers, because each rebuilds the signed bytes
  // from its own stored challenge. The car stays locked and both history rows say SIGNATURE_INVALID.
  await page.getByRole("button", { name: "Run scenario: Tamper with a signed response" }).click();
  await expect(page.getByRole("heading", { name: /Tamper with a signed response: results match expectations/ })).toBeVisible();
  for (const mode of ["Vulnerable verifier", "Hardened verifier"]) {
    await expect(
      page.getByRole("region", { name: mode }).getByText("TAMPERED RESPONSE REJECTED · SIGNATURE_INVALID: car stays LOCKED"),
    ).toBeVisible();
  }
  await expect(page.getByRole("cell", { name: "deny · SIGNATURE_INVALID" })).toHaveCount(2);

  // Substitute: old unlock bytes + signature attached to a fresh lock challenge. The verifier that checks the
  // client's bytes unlocks the car; the real engine rebuilds the bytes from the challenge row and denies.
  await page.getByRole("button", { name: "Run scenario: Substitute old signed bytes on a fresh challenge" }).click();
  await expect(
    page.getByRole("heading", { name: /Substitute old signed bytes on a fresh challenge: results match expectations/ }),
  ).toBeVisible();
  await expect(
    page.getByRole("region", { name: "Vulnerable verifier" }).getByText("SUBSTITUTED MESSAGE ACCEPTED: car is UNLOCKED"),
  ).toBeVisible();
  await expect(
    page
      .getByRole("region", { name: "Hardened verifier" })
      .getByText("SUBSTITUTED MESSAGE REJECTED · SIGNATURE_INVALID: car stays LOCKED"),
  ).toBeVisible();
  await expect(page.getByRole("cell", { name: "deny · SIGNATURE_INVALID" })).toHaveCount(3);

  // Revoke (two-step) and confirm the Garage no longer offers the key.
  await nav(page, "Digital Keys");
  await page.getByRole("button", { name: "Revoke", exact: true }).click();
  await page.getByRole("button", { name: "Confirm revoke" }).click();
  const card = page.getByRole("listitem").filter({ hasText: "Phone A" });
  await expect(card.getByText("revoked", { exact: true })).toBeVisible();
  await nav(page, "Garage");
  await expect(page.getByText("No usable key in this browser.")).toBeVisible();

  // Analytics reflects exactly what happened above.
  await nav(page, "Analytics");
  const failures = page.getByRole("region", { name: "Failure categories" });
  await expect(failures.getByText("CHALLENGE_CONSUMED")).toBeVisible();
  await failures.getByRole("button", { name: /CHALLENGE_CONSUMED/ }).click();
  const log = page.getByRole("table", { name: "Security events, newest first" });
  await expect(log.getByRole("row")).toHaveCount(2); // header + the one replay denial
  await expect(log.getByText("Authenticate · lock")).toBeVisible();
});

test("a tampered signature in flight is denied and leaves the car locked", async ({ page }) => {
  await startLab(page);
  await enroll(page, "Phone B");
  await nav(page, "Garage");

  // Flip one character of the signature on its way to the server (a man-in-the-middle edit).
  await page.route("**/authenticate", async (route) => {
    const body = route.request().postDataJSON();
    const sig: string = body.signature;
    body.signature = sig.slice(0, 10) + (sig[10] === "A" ? "B" : "A") + sig.slice(11);
    await route.continue({ postData: JSON.stringify(body) });
  });
  await page.getByRole("button", { name: "Request unlock" }).click();
  await expect(page.getByText("DENIED · SIGNATURE_INVALID")).toBeVisible();
  await expect(page.getByRole("region", { name: "KG Coupe (fictional)" }).getByText("locked", { exact: true })).toBeVisible();
});

test("a lab is private to the tab that created it", async ({ page, browser }) => {
  await startLab(page);
  const labId = await page.evaluate(() => {
    const raw = sessionStorage.getItem("keyguard.lab");
    return raw ? (JSON.parse(raw).labId as string) : null;
  });
  expect(labId).toMatch(/^lab_/);

  // A different browser context (another person) has no token: it sees no lab, and the API refuses the ID.
  const other = await browser.newContext();
  const stranger = await other.newPage();
  await stranger.goto("/");
  await expect(stranger.getByRole("button", { name: "Start a lab" })).toBeVisible();
  const status = await stranger.evaluate(async (id) => {
    const r = await fetch(`http://localhost:8100/api/labs/${id}/vehicles`);
    return { status: r.status, code: (await r.json()).error.code };
  }, labId);
  expect(status).toEqual({ status: 404, code: "LAB_NOT_FOUND" });
  await other.close();
});

test("an expired or unknown lab is explained, not silently dropped", async ({ page }) => {
  await page.goto("/");
  // A well-formed session for a lab the server doesn't know (as after the 24 h TTL cleanup).
  await page.evaluate(() =>
    sessionStorage.setItem(
      "keyguard.lab",
      JSON.stringify({ labId: "lab_AAAAAAAAAAAAAAAAAAAAAA", labToken: "x".repeat(43), expiresAt: Date.now() / 1000 + 3600 }),
    ),
  );
  for (const path of ["/", "/keys", "/analytics"]) {
    await page.goto(path);
    await expect(page.getByRole("status")).toContainText("expired or was removed");
    await expect(page.getByRole("button", { name: "Start a lab" })).toBeVisible();
    await page.evaluate(() =>
      sessionStorage.setItem(
        "keyguard.lab",
        JSON.stringify({ labId: "lab_AAAAAAAAAAAAAAAAAAAAAA", labToken: "x".repeat(43), expiresAt: Date.now() / 1000 + 3600 }),
      ),
    );
  }
  await page.getByRole("button", { name: "Start a lab" }).click();
  await expect(page.getByRole("status")).toHaveCount(0);
});
