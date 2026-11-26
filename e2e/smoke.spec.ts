/**
 * Lightweight Playwright smoke tests for the portal shell.
 * Run with: pnpm exec playwright test (requires browsers installed).
 */
import { test, expect } from "@playwright/test";

const base = process.env.E2E_BASE_URL || "http://127.0.0.1:3000";

test.describe("Ghoststrike smoke", () => {
  test("home loads", async ({ page }) => {
    await page.goto(base + "/");
    await expect(page.locator("body")).toBeVisible();
  });

  test("login page renders", async ({ page }) => {
    await page.goto(base + "/login");
    await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();
  });

  test("metrics endpoint", async ({ request }) => {
    const res = await request.get(base + "/metrics");
    expect(res.ok()).toBeTruthy();
    const text = await res.text();
    expect(text).toContain("ghoststrike_info");
  });

  test("oidc enabled probe", async ({ request }) => {
    const res = await request.get(base + "/api/oidc/enabled");
    expect(res.ok()).toBeTruthy();
    const json = await res.json();
    expect(json).toHaveProperty("enabled");
  });
});
