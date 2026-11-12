import { expect, test, type Page } from "@playwright/test";

// F12: passkey accounts and saved labs (D-012), with Chromium's virtual WebAuthn authenticator.
// The authenticator is a real CTAP2 implementation inside the browser: resident keys, user verification,
// signature counters. Nothing about the server side is mocked.

async function addAuthenticator(page: Page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}

async function nav(page: Page, name: string) {
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name, exact: true }).click();
}

async function startLab(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Start a lab" }).click();
  await expect(page.getByRole("button", { name: "End lab" })).toBeVisible();
}

async function createAccount(page: Page, name: string) {
  await nav(page, "Account");
  await page.getByLabel("Display name (not an email)").fill(name);
  await page.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("heading", { name: `Signed in as ${name}` })).toBeVisible();
}

test("passkey account: register, save a lab, sign out, sign back in, reopen the lab", async ({ page, context }) => {
  const { cdp, authenticatorId } = await addAuthenticator(page);
  await startLab(page);
  const labId = await page.evaluate(() => JSON.parse(sessionStorage.getItem("keyguard.lab")!).labId as string);

  await createAccount(page, "Pranav");

  // The authenticator now holds a discoverable credential with user verification.
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(credentials).toHaveLength(1);
  expect(credentials[0].isResidentCredential).toBe(true);
  expect(credentials[0].rpId).toBe("localhost");

  // The session cookie is HttpOnly and SameSite=Strict: page scripts can't see it.
  const cookie = (await context.cookies()).find((c) => c.name === "kg_session");
  expect(cookie).toMatchObject({ httpOnly: true, sameSite: "Strict", path: "/api" });
  expect(await page.evaluate(() => document.cookie)).not.toContain("kg_session");

  // Save the current lab.
  await page.getByRole("button", { name: /Save current lab/ }).click();
  const saved = page.getByRole("region", { name: /Saved labs/ });
  await expect(saved.getByText(labId, { exact: false })).toBeVisible();
  await expect(page.getByText("(open in this tab)")).toBeVisible();

  // Sign out, then sign back in with the same passkey (usernameless).
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("heading", { name: "Signed in as Pranav" })).toBeVisible();
  const after = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(after.credentials[0].signCount).toBeGreaterThan(credentials[0].signCount);

  // End the lab in this tab, then reopen it from the account: a fresh token is issued.
  const oldToken = await page.evaluate(() => JSON.parse(sessionStorage.getItem("keyguard.lab")!).labToken as string);
  await nav(page, "Garage");
  await page.getByRole("button", { name: "End lab" }).click();
  await nav(page, "Account");
  await page.getByRole("button", { name: `Open saved lab ${labId}` }).click();
  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText(labId).first()).toBeVisible();
  const newToken = await page.evaluate(() => JSON.parse(sessionStorage.getItem("keyguard.lab")!).labToken as string);
  expect(newToken).not.toBe(oldToken);
});

test("saved labs are private to their account, and deleting an account removes them", async ({ page, browser }) => {
  await addAuthenticator(page);
  await startLab(page);
  const labId = await page.evaluate(() => JSON.parse(sessionStorage.getItem("keyguard.lab")!).labId as string);
  await createAccount(page, "Owner");
  await page.getByRole("button", { name: /Save current lab/ }).click();
  await expect(page.getByText("(1 of 10)")).toBeVisible();

  // Another person, another browser, another passkey: sees none of it.
  const other = await browser.newContext();
  const stranger = await other.newPage();
  await addAuthenticator(stranger);
  await stranger.goto("/account");
  await stranger.getByLabel("Display name (not an email)").fill("Stranger");
  await stranger.getByRole("button", { name: "Create passkey" }).click();
  await expect(stranger.getByRole("heading", { name: "Signed in as Stranger" })).toBeVisible();
  await expect(stranger.getByText("(0 of 10)")).toBeVisible();
  await expect(stranger.getByText(labId)).toHaveCount(0);
  await other.close();

  // Delete the owner's account (typed confirmation).
  const del = page.getByRole("button", { name: "Delete account and saved labs" });
  await expect(del).toBeDisabled();
  await page.getByLabel("Confirmation").fill("DELETE");
  await del.click();
  await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
  // The saved lab is gone server-side: this tab's lab now reads as expired/removed.
  await nav(page, "Garage");
  await expect(page.getByRole("status")).toContainText("expired or was removed");
});
