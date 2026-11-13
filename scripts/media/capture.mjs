// Captures the README screenshots and GIF frames by driving the real app with Playwright.
// Usage: node scripts/media/capture.mjs <out-dir>   (BASE=http://localhost:3000 for a local run; default is the live demo)
// Then:  uv run --with pillow python scripts/media/build.py <out-dir> docs/media
// It creates one short-lived lab on the target, which expires on its own.
import { createRequire } from "node:module";
const require = createRequire(new URL("../../apps/web/package.json", import.meta.url));
const { chromium } = require("playwright");
const BASE = process.env.BASE ?? "https://keyguard-six.vercel.app";
const OUT = process.argv[2];
const scheme = process.env.SCHEME ?? "light";
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1280, height: 800 }, deviceScaleFactor: 2, colorScheme: scheme });
const page = await ctx.newPage();
let f = 0;
const frame = async (name) => { await page.waitForTimeout(400); await page.screenshot({ path: `${OUT}/frame-${String(++f).padStart(2,"0")}-${name}.png` }); };
const full = async (name) => { await page.waitForTimeout(400); await page.screenshot({ path: `${OUT}/${name}.png`, fullPage: true }); };
const nav = (name) => page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name, exact: true }).click();
const vis = (loc) => loc.first().waitFor({ state: "visible", timeout: 20000 });

await page.goto(BASE + "/");
await vis(page.getByRole("button", { name: "Start a lab" }));
await frame("start");
await page.getByRole("button", { name: "Start a lab" }).click();
await vis(page.getByRole("button", { name: "End lab" }));
await frame("lab");

await nav("Digital Keys");
const enroll = page.getByRole("button", { name: "Generate & enroll key" });
await page.waitForFunction(() => [...document.querySelectorAll("button")].some(b => b.textContent?.includes("Generate & enroll key") && !b.disabled));
await page.getByLabel("Label").fill("Owner's phone");
await frame("enroll");
await enroll.click();
await vis(page.getByText("in this browser", { exact: true }));
await frame("enrolled");

await nav("Garage");
await page.getByRole("button", { name: "Request unlock" }).click();
await vis(page.getByText("ALLOWED · UNLOCKED"));
await page.evaluate(() => window.scrollBy(0, 380));
await frame("unlocked");
await page.evaluate(() => window.scrollTo(0, 0));
await full("garage");

await nav("Inspector");
await page.getByRole("button", { name: "Run unlock exchange" }).click();
await vis(page.getByRole("button", { name: "Replay this exact response" }));
await frame("exchange");
await page.getByRole("button", { name: "Replay this exact response" }).click();
await vis(page.getByText("DENIED · CHALLENGE_CONSUMED"));
await page.getByText("DENIED · CHALLENGE_CONSUMED").first().evaluate((el) => el.scrollIntoView({ block: "center" }));
await frame("replay-denied");
await page.evaluate(() => window.scrollTo(0, 0));
await full("inspector");

await nav("Attack Lab");
await page.getByRole("button", { name: "Run scenario: Replay a captured unlock" }).click();
await vis(page.getByText(/REPLAY REJECTED/));
await page.getByText(/REPLAY REJECTED/).first().evaluate((el) => el.scrollIntoView({ block: "center" }));
await frame("attack-lab");
await full("attack-lab");

// add card + fob for the keys page
for (const [type, label] of [["Key card", "Valet card"], ["Key fob", "Spare fob"]]) {
  await nav("Digital Keys");
  await page.getByRole("radio", { name: type }).check();
  await page.getByLabel("Label").fill(label);
  await page.getByRole("button", { name: "Generate & enroll key" }).click();
  await vis(page.getByRole("listitem").filter({ hasText: label }).getByText("in this browser", { exact: true }));
}
await full("keys");

await nav("Proximity");
await page.getByRole("button", { name: "Run the relay on the real backend" }).click();
await vis(page.getByText("relayed unlock ACCEPTED"));
await full("proximity");

await nav("Analytics");
await vis(page.getByText("CHALLENGE_CONSUMED"));
await frame("analytics");
await full("analytics");

await page.goto(BASE + "/account");
await vis(page.getByRole("button", { name: "Sign in with a passkey" }));
await full("account");
await browser.close();
console.log("done", f, "frames");
