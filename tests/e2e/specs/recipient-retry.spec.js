const { test, expect } = require("@playwright/test");
const { monitorPage } = require("../helpers");

test("wrong link password can be retried without reloading", async ({ page, request, baseURL }, testInfo) => {
  const monitor = await monitorPage(page, baseURL);
  const projectOctet = 20 + ([...testInfo.project.name].reduce((sum, character) => sum + character.charCodeAt(0), 0) % 180);
  const forwardedFor = `192.0.2.${projectOctet}`;
  await page.context().setExtraHTTPHeaders({ "X-Forwarded-For": forwardedFor });
  const marker = `recipient-retry-${testInfo.project.name}-${Date.now()}`;
  const password = "correct-recipient-password";
  const createdResponse = await request.post("/api/v1/secret-links", {
    headers: {
      Authorization: `Bearer ${process.env.TEST_SECURESHARE_ADMIN_API_KEY || "test-admin-api-key-change-me"}`,
      "X-Forwarded-For": forwardedFor,
    },
    data: {
      title: `Recipient retry ${marker}`,
      recipient_reference: marker,
      expires_in_seconds: 900,
      password,
      max_failed_attempts: 5,
      payload: { type: "text", text: marker },
    },
  });
  expect(createdResponse.status()).toBe(201);
  const created = await createdResponse.json();

  const fragment = new URL(created.url).hash;
  expect(fragment.length).toBeGreaterThan(1);

  await page.goto(`/s${fragment}`, { waitUntil: "domcontentloaded" });
  await expect(page).toHaveURL(/\/s$/);
  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "ready");
  await page.locator("#link-password").fill("wrong-password");
  await page.locator("#reveal-button").click();

  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "password_error");
  await expect(page.locator("#password-error")).toHaveText("The link password is incorrect. Try again.");
  await expect(page.locator("#reveal-button")).toBeEnabled();
  await expect(page.locator("#link-password")).toBeFocused();
  await expect(page.locator('[data-recipient-state-panel]:visible')).toHaveCount(1);

  await page.locator("#link-password").fill(password);
  await page.locator("#reveal-button").click();
  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "revealed");
  await expect(page.locator("#revealed-secret")).toHaveText(marker);
  await expect(page.locator("#ready-state")).toBeHidden();
  await expect(page.locator("#link-password")).toBeHidden();
  await expect(page.locator("#reveal-button")).toBeHidden();
  await expect(page.locator('[data-recipient-state-panel]:visible')).toHaveCount(1);

  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "unavailable");
  await expect(page.locator("#unavailable-message")).toContainText("this link is not stored in the browser");
  await expect(page.locator("#reveal-button")).toBeHidden();

  await page.goto("about:blank");
  await page.goto(`/s${fragment}`, { waitUntil: "domcontentloaded" });
  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "unavailable");
  await expect(page.locator("#unavailable-title")).toHaveText("This link is no longer available");
  await expect(page.locator("#password-wrap")).toBeHidden();
  await expect(page.locator("#reveal-button")).toBeHidden();
  monitor.assertClean();
});
