import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

// Automated WCAG 2.1 A/AA scan of every page, both before a lab exists and with real data on screen.
// Automated checks catch only part of what matters for accessibility; see docs/USABILITY.md for the manual pass.

const PAGES = ["/", "/keys", "/inspector", "/lab", "/analytics"];

async function scan(page: import("@playwright/test").Page) {
  const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"]).analyze();
  return results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    nodes: v.nodes.map((n) => n.target.join(" ")).slice(0, 5),
  }));
}

test("no WCAG A/AA violations before a lab exists", async ({ page }) => {
  for (const path of PAGES) {
    await page.goto(path);
    await expect(page.getByRole("button", { name: "Start a lab" })).toBeVisible();
    expect(await scan(page), path).toEqual([]);
  }
});

test("no WCAG A/AA violations with real data on every page", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Start a lab" }).click();
  const nav = (name: string) =>
    page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name, exact: true }).click();

  await nav("Digital Keys");
  await page.getByLabel("Label").fill("Phone A");
  await page.getByRole("button", { name: "Generate & enroll key" }).click();
  await expect(page.getByText("in this browser", { exact: true })).toBeVisible();
  expect(await scan(page), "/keys").toEqual([]);

  await nav("Garage");
  await page.getByRole("button", { name: "Request unlock" }).click();
  await expect(page.getByText("ALLOWED · UNLOCKED")).toBeVisible();
  expect(await scan(page), "/").toEqual([]);

  await nav("Inspector");
  await page.getByRole("button", { name: "Run unlock exchange" }).click();
  await page.getByRole("button", { name: "Replay this exact response" }).click();
  await expect(page.getByText("DENIED · CHALLENGE_CONSUMED")).toBeVisible();
  expect(await scan(page), "/inspector").toEqual([]);

  await nav("Attack Lab");
  await page.getByRole("button", { name: "Run scenario: Replay a captured unlock" }).click();
  await expect(page.getByText(/REPLAY REJECTED/)).toBeVisible();
  expect(await scan(page), "/lab").toEqual([]);

  await nav("Analytics");
  await expect(page.getByText("CHALLENGE_CONSUMED").first()).toBeVisible();
  expect(await scan(page), "/analytics").toEqual([]);
});

test("the core journey works with the keyboard alone", async ({ page }) => {
  await page.goto("/");
  // Tab to "Start a lab" and press Enter.
  for (let i = 0; i < 15; i++) {
    await page.keyboard.press("Tab");
    if (await page.getByRole("button", { name: "Start a lab" }).evaluate((el) => el === document.activeElement)) break;
  }
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "End lab" })).toBeVisible();

  const focusAndPress = async (locator: import("@playwright/test").Locator, key = "Enter") => {
    await locator.focus();
    await expect(locator).toBeFocused();
    await page.keyboard.press(key);
  };
  await focusAndPress(page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Digital Keys" }));
  await page.getByLabel("Label").focus();
  await page.keyboard.type("Keyboard key");
  await page.keyboard.press("Enter"); // submits the enrollment form
  await expect(page.getByText("in this browser", { exact: true })).toBeVisible();
  await focusAndPress(page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Garage" }));
  await focusAndPress(page.getByRole("button", { name: "Request unlock" }), "Space");
  await expect(page.getByText("ALLOWED · UNLOCKED")).toBeVisible();
});
