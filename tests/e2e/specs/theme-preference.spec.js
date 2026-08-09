const { test, expect, request } = require("@playwright/test");
const { gotoPage, monitorPage } = require("../helpers");

test.beforeEach(async ({}, testInfo) => {
  test.skip(testInfo.project.name === "roles", "covered by the role-specific suite");
});

test("account theme preference survives navigation reload new tabs and fresh sessions", async ({ page, context, browser, baseURL }, testInfo) => {
  const monitor = await monitorPage(page, baseURL);
  await gotoPage(page, "/admin");
  const toggle = page.locator("[data-theme-toggle]");
  const themes = ["system", "light", "dark"];
  const targetByProject = {
    "desktop-1280": "dark",
    "desktop-1366": "light",
    "desktop-1440": "system",
  };
  const expected = targetByProject[testInfo.project.name] || "dark";
  expect(themes).toContain(await page.locator("html").getAttribute("data-theme"));
  for (let attempt = 0; attempt < themes.length; attempt += 1) {
    if ((await page.locator("html").getAttribute("data-theme")) === expected) break;
    const saved = page.waitForResponse((response) => response.url().endsWith("/api/v1/me/preferences/theme") && response.request().method() === "PUT");
    await toggle.click();
    expect((await saved).status()).toBe(200);
  }
  await expect(page.locator("html")).toHaveAttribute("data-theme", expected);
  await expect(toggle).toContainText(expected.charAt(0).toUpperCase() + expected.slice(1));

  await gotoPage(page, "/admin/secrets");
  await expect(page.locator("html")).toHaveAttribute("data-theme", expected);
  await page.reload({ waitUntil: "domcontentloaded" });
  await expect(page.locator("html")).toHaveAttribute("data-theme", expected);
  const secondPage = await context.newPage();
  const secondMonitor = await monitorPage(secondPage, baseURL);
  await gotoPage(secondPage, "/admin/secrets");
  await expect(secondPage.locator("html")).toHaveAttribute("data-theme", expected);
  secondMonitor.assertClean();
  await secondPage.close();

  if (testInfo.project.name === "desktop-1280") {
    const freshRequest = await request.newContext({
      baseURL,
      storageState: { cookies: [], origins: [] },
    });
    const login = await freshRequest.post("/api/v1/auth/login", {
      data: {
        login: process.env.E2E_ADMIN_USERNAME || "test-admin",
        password: process.env.E2E_ADMIN_PASSWORD || "test-admin-password-change-me",
      },
    });
    expect(login.status()).toBe(200);
    const freshContext = await browser.newContext({ storageState: await freshRequest.storageState() });
    const freshPage = await freshContext.newPage();
    const freshMonitor = await monitorPage(freshPage, baseURL);
    await gotoPage(freshPage, "/admin/account");
    await expect(freshPage.locator("html")).toHaveAttribute("data-theme", expected);

    await freshPage.locator("[data-user-menu] summary").click();
    await freshPage.locator('form[action="/logout"] button[type="submit"]').click();
    await expect(freshPage).toHaveURL(/\/login$/);
    await freshPage.locator('input[name="login"]').fill(process.env.E2E_ADMIN_USERNAME || "test-admin");
    await freshPage.locator('input[name="password"]').fill(process.env.E2E_ADMIN_PASSWORD || "test-admin-password-change-me");
    await freshPage.locator('[data-login-form] button[type="submit"]').click();
    await expect(freshPage).toHaveURL(/\/admin$/);
    await expect(freshPage.locator("html")).toHaveAttribute("data-theme", expected);
    freshMonitor.assertClean();
    await freshContext.close();
    await freshRequest.dispose();
  }
  monitor.assertClean();
});
