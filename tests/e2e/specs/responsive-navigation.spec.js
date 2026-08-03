const { test, expect } = require("@playwright/test");
const { assertNavigation, fixtures, gotoPage, monitorPage, navigationByRole } = require("../helpers");

test.beforeEach(({}, testInfo) => {
  test.skip(!testInfo.project.name.startsWith("desktop-") && !testInfo.project.name.startsWith("mobile-") && !testInfo.project.name.startsWith("tablet-"), "Responsive checks use viewport projects.");
});

test("desktop sidebar remains stable without clipping or horizontal overflow", async ({ page, baseURL }, testInfo) => {
  test.skip(!testInfo.project.name.startsWith("desktop-"), "Desktop-only layout check.");
  const fixture = fixtures();
  const monitor = await monitorPage(page, baseURL);
  const geometry = [];
  for (const [route, active] of [["/admin", "dashboard"], ["/admin/secrets", "secret-links"], [`/admin/secrets/${fixture.secretID}`, "secret-links"], ["/docs", "api-docs"], ["/admin/account", "account"]]) {
    await gotoPage(page, route);
    await assertNavigation(page, "admin", active);
    const layout = await page.evaluate(() => {
      const sidebar = document.querySelector("#app-sidebar").getBoundingClientRect();
      const workspace = document.querySelector(".workspace").getBoundingClientRect();
      const content = document.querySelector("#main-content").getBoundingClientRect();
      return {
        sidebarWidth: sidebar.width,
        sidebarHeight: sidebar.height,
        workspaceLeft: workspace.left,
        contentWidth: content.width,
        viewportWidth: document.documentElement.clientWidth,
        scrollWidth: document.documentElement.scrollWidth,
      };
    });
    expect(layout.sidebarWidth).toBeGreaterThanOrEqual(251);
    expect(layout.sidebarWidth).toBeLessThanOrEqual(253);
    expect(layout.sidebarHeight).toBeGreaterThanOrEqual(page.viewportSize().height - 1);
    expect(layout.workspaceLeft).toBeGreaterThanOrEqual(251);
    expect(layout.contentWidth).toBeLessThanOrEqual(1521);
    expect(layout.scrollWidth).toBeLessThanOrEqual(layout.viewportWidth + 1);
    geometry.push(layout);
    await expect(page.locator(".sidebar-account")).toBeVisible();
    for (const id of navigationByRole.admin) {
      const item = page.locator(`[data-nav-item-id="${id}"]`);
      await item.scrollIntoViewIfNeeded();
      await expect(item).toBeVisible();
    }
  }
  expect(new Set(geometry.map((value) => Math.round(value.sidebarWidth))).size).toBe(1);
  expect(new Set(geometry.map((value) => Math.round(value.workspaceLeft))).size).toBe(1);
  monitor.assertClean();
});

test("mobile drawer preserves navigation, traps focus, and closes safely", async ({ page, baseURL }, testInfo) => {
  test.skip(!testInfo.project.name.startsWith("mobile-") && !testInfo.project.name.startsWith("tablet-"), "Mobile and tablet interaction check.");
  const fixture = fixtures();
  const monitor = await monitorPage(page, baseURL);
  for (const [route, active] of [["/admin", "dashboard"], ["/admin/secrets/new", "create-secret"], ["/admin/secrets", "secret-links"], [`/admin/secrets/${fixture.secretID}`, "secret-links"], ["/admin/api-clients", "api-clients"], ["/admin/users", "users"], ["/admin/settings/email", "email-settings"], ["/admin/system", "system-status"], ["/docs", "api-docs"], ["/admin/account", "account"]]) {
    await gotoPage(page, route);
    await assertNavigation(page, "admin", active);
    await page.locator("[data-menu-toggle]").click();
    await expect(page.locator("#app-sidebar")).toHaveClass(/open/);
    await expect(page.locator("#app-sidebar")).toBeVisible();
    await expect(page.locator("#app-sidebar")).toHaveCSS("transform", "matrix(1, 0, 0, 1, 0, 0)");
    expect(await page.locator("[data-nav-item-id]").evaluateAll((nodes) => nodes.map((node) => node.dataset.navItemId))).toEqual(navigationByRole.admin);
    const overflow = await page.evaluate(() => {
      const clientWidth = document.documentElement.clientWidth;
      return {
        amount: document.documentElement.scrollWidth - clientWidth,
        elements: [...document.querySelectorAll("body *")]
          .map((element) => {
            const rect = element.getBoundingClientRect();
            return {
              selector: `${element.tagName.toLowerCase()}${element.id ? `#${element.id}` : ""}${[...element.classList].map((name) => `.${name}`).join("")}`,
              left: Math.round(rect.left),
              right: Math.round(rect.right),
              width: Math.round(rect.width),
              scrollWidth: element.scrollWidth,
            };
          })
          .filter((element) => element.right > clientWidth + 1 || element.left < -1)
          .slice(0, 12),
      };
    });
    expect(overflow.amount, JSON.stringify(overflow.elements, null, 2)).toBeLessThanOrEqual(1);
    await page.keyboard.press("Escape");
    await expect(page.locator("#app-sidebar")).not.toHaveClass(/open/);
    await expect(page.locator("[data-menu-toggle]")).toBeFocused();
  }

  await page.locator("[data-menu-toggle]").click();
  await expect(page.locator("[data-menu-close]")).toBeFocused();
  await page.keyboard.press("Shift+Tab");
  expect(await page.evaluate(() => document.querySelector("#app-sidebar").contains(document.activeElement))).toBe(true);
  await page.keyboard.press("Tab");
  await expect(page.locator("[data-menu-close]")).toBeFocused();

  const viewport = page.viewportSize();
  await page.locator("[data-nav-backdrop]").click({ position: { x: viewport.width - 8, y: 100 } });
  await expect(page.locator("#app-sidebar")).not.toHaveClass(/open/);
  await expect(page.locator("[data-menu-toggle]")).toBeFocused();

  await page.locator("[data-menu-toggle]").click();
  await page.locator('[data-nav-item-id="secret-links"]').click();
  await expect(page).toHaveURL(/\/admin\/secrets$/);
  await expect(page.locator("#app-sidebar")).not.toHaveClass(/open/);

  monitor.assertClean();
});

test("mobile logout uses the single POST action and returns to login", async ({ browser, baseURL }, testInfo) => {
  test.skip(!testInfo.project.name.startsWith("mobile-"), "Mobile-only logout check.");
  const viewport = testInfo.project.name === "mobile-375"
    ? { width: 375, height: 812 }
    : { width: 390, height: 844 };
  const context = await browser.newContext({
    baseURL,
    viewport,
    storageState: { cookies: [], origins: [] },
  });
  const page = await context.newPage();
  await page.goto(`${baseURL}/login`);
  await expect(page).toHaveURL(/\/login$/);
  await page.locator('input[name="login"]').fill("test-admin");
  await page.locator('input[name="password"]').fill("test-admin-password-change-me");
  await page.locator('[data-login-form] button[type="submit"]').click();
  await expect(page).toHaveURL(/\/admin$/);
  await gotoPage(page, "/admin");
  await page.locator("[data-user-menu] summary").click();
  await page.getByRole("menuitem", { name: "Logout" }).click();
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.locator("[data-login-form]")).toBeVisible();
  await context.close();
});
