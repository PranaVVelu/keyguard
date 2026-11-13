// Live passkey smoke test (D-012) with Chromium's virtual WebAuthn authenticator: no real device credential is used.
// Registers two throwaway accounts on the target, exercises saved labs, then deletes both accounts.
// Usage: BASE=https://<project>.vercel.app node scripts/smoke/passkey-live.mjs
import { createRequire } from "node:module";
const require = createRequire(new URL("../../apps/web/package.json", import.meta.url));
const { chromium } = require("playwright");
const BASE = process.env.BASE ?? "https://keyguard-six.vercel.app";
const RP_ID = new URL(BASE).hostname;
const T = 20000;
const log = (ok, msg) => { console.log(`${ok ? "PASS" : "FAIL"}  ${msg}`); if (!ok) process.exitCode = 1; };
async function authenticator(page) {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true } });
  return { cdp, authenticatorId };
}
const nav = (p, name) => p.getByRole("navigation", { name: "Primary" }).getByRole("link", { name, exact: true }).click();
const seen = (loc) => loc.first().waitFor({ state: "visible", timeout: T }).then(() => true, () => false);
const lab = (p) => p.evaluate(() => JSON.parse(sessionStorage.getItem("keyguard.lab") || "null"));

const browser = await chromium.launch();
const ctx = await browser.newContext();
const page = await ctx.newPage();
const { cdp, authenticatorId } = await authenticator(page);
try {
  await page.goto(BASE + "/");
  await page.getByRole("button", { name: "Start a lab" }).click();
  await seen(page.getByRole("button", { name: "End lab" }));
  const { labId, labToken: oldToken } = await lab(page);

  await nav(page, "Account");
  await page.getByLabel("Display name (not an email)").fill("Live smoke owner");
  await page.getByRole("button", { name: "Create passkey" }).click();
  log(await seen(page.getByRole("heading", { name: "Signed in as Live smoke owner" })), "register a passkey (resident key, UV) on the live site");
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  log(credentials.length === 1 && credentials[0].isResidentCredential && credentials[0].rpId === RP_ID,
      `credential is discoverable and bound to rpId ${credentials[0]?.rpId}`);
  const cookie = (await ctx.cookies()).find((c) => c.name === "kg_session");
  log(cookie && cookie.httpOnly && cookie.secure && cookie.sameSite === "Strict" && cookie.path === "/api",
      `session cookie: HttpOnly=${cookie?.httpOnly} Secure=${cookie?.secure} SameSite=${cookie?.sameSite} Path=${cookie?.path}`);
  log(!(await page.evaluate(() => document.cookie)).includes("kg_session"), "page scripts can't read the session cookie");

  await page.getByRole("button", { name: /Save current lab/ }).click();
  log(await seen(page.getByText("(1 of 10)")), "save the current lab to the account");

  await page.getByRole("button", { name: "Sign out" }).click();
  await seen(page.getByRole("button", { name: "Sign in with a passkey" }));
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  log(await seen(page.getByRole("heading", { name: "Signed in as Live smoke owner" })), "sign out, then usernameless sign-in with the passkey");
  const after = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  log(after.credentials[0].signCount > credentials[0].signCount, `signature counter advanced (${credentials[0].signCount} → ${after.credentials[0].signCount})`);

  await nav(page, "Garage");
  await page.getByRole("button", { name: "End lab" }).click();
  await nav(page, "Account");
  await page.getByRole("button", { name: `Open saved lab ${labId}` }).click();
  await page.waitForURL(BASE + "/", { timeout: T });
  await seen(page.getByRole("button", { name: "End lab" }));
  const reopened = await lab(page);
  console.log("      reopened lab", reopened?.labId === labId ? "matches" : `differs (${reopened?.labId})`, "· token rotated:", reopened?.labToken !== oldToken);
  log(reopened?.labId === labId && reopened.labToken !== oldToken, "reopen the saved lab: same lab, fresh token");
  const oldTokenStatus = await page.evaluate(async ({ id, tok }) =>
    (await fetch(`/api/labs/${id}`, { headers: { Authorization: `Bearer ${tok}` } })).status, { id: labId, tok: oldToken });
  log(oldTokenStatus === 404, `the old lab token no longer works (${oldTokenStatus})`);

  // A stranger with another passkey sees none of it.
  const other = await browser.newContext();
  const stranger = await other.newPage();
  await authenticator(stranger);
  await stranger.goto(BASE + "/account");
  await stranger.getByLabel("Display name (not an email)").fill("Live smoke stranger");
  await stranger.getByRole("button", { name: "Create passkey" }).click();
  await seen(stranger.getByRole("heading", { name: "Signed in as Live smoke stranger" }));
  log(await seen(stranger.getByText("(0 of 10)")) && (await stranger.getByText(labId).count()) === 0, "a second account can't see the first account's saved lab");
  await stranger.getByLabel("Confirmation").fill("DELETE");
  await stranger.getByRole("button", { name: "Delete account and saved labs" }).click();
  log(await seen(stranger.getByRole("button", { name: "Sign in with a passkey" })), "delete the second test account");
  await other.close();

  // Clean up the owner account.
  await nav(page, "Account");
  await page.getByLabel("Confirmation").fill("DELETE");
  await page.getByRole("button", { name: "Delete account and saved labs" }).click();
  log(await seen(page.getByRole("button", { name: "Sign in with a passkey" })), "delete the owner test account and its saved lab");
  const me = await page.evaluate(async () => (await fetch("/api/account", { credentials: "include" })).status);
  log(me === 401 || me === 404, `the old session no longer works (${me})`);
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  const failed = page.getByRole("alert").filter({ hasText: /\S/ });
  const shown = await seen(failed);
  const text = shown ? (await failed.first().textContent()) : "";
  const stillOut = await page.getByRole("button", { name: "Sign in with a passkey" }).isVisible();
  log(shown && stillOut, `the deleted account's passkey can no longer sign in: "${text?.trim()}"`);
} catch (e) { log(false, String(e)); await page.screenshot({ path: "passkey-live-failure.png" }); }
await browser.close();
