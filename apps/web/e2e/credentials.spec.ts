import { API_URL } from "./ports";
import { expect, test, type Page } from "@playwright/test";

// F10 credential types and F11 proximity, through the real UI, API and Web Crypto.

async function nav(page: Page, name: string) {
  await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name, exact: true }).click();
}

async function startLab(page: Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Start a lab" }).click();
  await expect(page.getByRole("button", { name: "End lab" })).toBeVisible();
}

async function enroll(page: Page, type: "Phone key" | "Key card" | "Key fob", label: string) {
  await nav(page, "Digital Keys");
  await page.getByRole("radio", { name: type }).check();
  await page.getByLabel("Label").fill(label);
  await page.getByRole("button", { name: "Generate & enroll key" }).click();
  await expect(page.getByRole("listitem").filter({ hasText: label }).getByText("in this browser", { exact: true })).toBeVisible();
}

const vehicle = (page: Page) => page.getByRole("region", { name: "KG Coupe (fictional)" });

test("key fob: rolling counter unlocks and locks; a replayed press is refused", async ({ page }) => {
  await startLab(page);
  await enroll(page, "Key fob", "Fob A");

  // Capture what the browser sends, so we can replay it byte for byte afterwards.
  const sent: string[] = [];
  page.on("request", (r) => {
    if (r.url().endsWith("/fob") && r.method() === "POST") sent.push(r.postData() ?? "");
  });

  await nav(page, "Garage");
  await page.getByRole("button", { name: "Press unlock button" }).click();
  await expect(page.getByText("ALLOWED · UNLOCKED")).toBeVisible();
  await expect(page.getByText(/fob counter 1 \(car's last accepted: 1\)/)).toBeVisible();
  await expect(vehicle(page).getByText("unlocked", { exact: true })).toBeVisible();

  await page.getByRole("button", { name: "Press lock button" }).click();
  await expect(page.getByText("ALLOWED · LOCKED")).toBeVisible();
  await expect(page.getByText(/fob counter 2/)).toBeVisible();

  // Replay the first (unlock) press exactly as it was sent.
  expect(sent).toHaveLength(2);
  const replay = await page.evaluate(async ({ body, api }) => {
    const s = JSON.parse(sessionStorage.getItem("keyguard.lab")!);
    const r = await fetch(`${api}/api/labs/${s.labId}/fob`, {
      method: "POST",
      headers: { Authorization: `Bearer ${s.labToken}`, "Content-Type": "application/json" },
      body,
    });
    return r.json();
  }, { body: sent[0], api: API_URL });
  expect([replay.decision, replay.reason, replay.lock_state]).toEqual(["deny", "COUNTER_REPLAYED", "locked"]);

  // The server-side counter is visible on the key, and the Inspector explains why fobs aren't there.
  await nav(page, "Digital Keys");
  await expect(page.getByText("last accepted by the car: 2")).toBeVisible();
  await nav(page, "Inspector");
  await expect(page.getByText(/Key fobs don't use server challenges/)).toBeVisible();
});

test("key card: a tap toggles the car based on the backend state", async ({ page }) => {
  await startLab(page);
  await enroll(page, "Key card", "Card A");
  await nav(page, "Garage");
  await page.getByRole("button", { name: "Tap card on reader (unlock)" }).click();
  await expect(page.getByText("ALLOWED · UNLOCKED")).toBeVisible();
  await page.getByRole("button", { name: "Tap card on reader (lock)" }).click();
  await expect(page.getByText("ALLOWED · LOCKED")).toBeVisible();
});

test("proximity page: relay is accepted by the real engine and the slider is never sent", async ({ page }) => {
  await startLab(page);
  await nav(page, "Proximity");
  await expect(page.getByRole("note")).toContainText("never reach the server");

  const bodies: (string | null)[] = [];
  page.on("request", (r) => {
    if (r.url().includes("/api/")) bodies.push(r.url() + " " + (r.postData() ?? ""));
  });
  await page.getByLabel(/Owner's distance from the car/).fill("73");
  await page.getByRole("button", { name: "Run the relay on the real backend" }).click();
  const result = page.getByRole("region", { name: /Backend result/ });
  await expect(result.getByText("relayed unlock ACCEPTED")).toHaveCount(2);
  await expect(result).toContainText("The slider was at 73 m");
  expect(bodies.some((b) => b!.includes("73"))).toBe(false);
  expect(bodies.some((b) => b!.includes("/scenarios/relay"))).toBe(true);
});

test("attack lab: fob replay is blocked, a captured unused press is a labelled known limitation", async ({ page }) => {
  await startLab(page);
  await nav(page, "Attack Lab");
  await page.getByRole("button", { name: "Run scenario: Replay a recorded key-fob press" }).click();
  await expect(page.getByText(/FOB REPLAY REJECTED · COUNTER_REPLAYED/)).toBeVisible();
  await page.getByRole("button", { name: "Run scenario: Use a fob press the car never received" }).click();
  await expect(page.getByText("results match expectations")).toBeVisible();
  await expect(page.getByText(/Known limitation: the production engine accepts this by design/)).toBeVisible();
});
