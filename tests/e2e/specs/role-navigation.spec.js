const { test, expect } = require("@playwright/test");
const { assertNavigation, authState, fixtures, gotoPage, monitorPage } = require("../helpers");

test.beforeEach(({}, testInfo) => {
  test.skip(testInfo.project.name !== "roles", "Role matrix runs once at the reference desktop viewport.");
});

test("admin navigation stays ordered and active across every protected area", async ({ browser, baseURL }) => {
  const fixture = fixtures();
  const context = await browser.newContext({ storageState: authState("admin"), baseURL, viewport: { width: 1366, height: 768 } });
  const page = await context.newPage();
  const monitor = await monitorPage(page, baseURL);
  const routes = [
    ["/admin", "dashboard"],
    ["/admin/secrets/new", "create-secret"],
    ["/admin/secrets", "secret-links"],
    [`/admin/secrets/${fixture.secretID}`, "secret-links"],
    ["/admin/api-clients", "api-clients"],
    [`/admin/api-clients/${fixture.clientID}`, "api-clients"],
    ["/admin/users", "users"],
    [`/admin/users/${fixture.developerID}`, "users"],
    ["/admin/settings/email", "email-settings"],
    ["/admin/system", "system-status"],
    ["/docs", "api-docs"],
    ["/admin/help", "help"],
    ["/admin/account", "account"],
  ];
  for (const [route, active] of routes) {
    await gotoPage(page, route);
    await assertNavigation(page, "admin", active);
  }
  monitor.assertClean();
  await context.close();
});

test("developer navigation excludes admin-only areas and remains stable after 403", async ({ browser, baseURL }) => {
  const fixture = fixtures();
  const context = await browser.newContext({ storageState: authState("developer"), baseURL, viewport: { width: 1366, height: 768 } });
  const page = await context.newPage();
  const monitor = await monitorPage(page, baseURL);
  for (const [route, active] of [
    ["/admin", "dashboard"], ["/admin/secrets/new", "create-secret"], ["/admin/secrets", "secret-links"],
    [`/admin/secrets/${fixture.secretID}`, "secret-links"], ["/docs", "api-docs"], ["/admin/help", "help"], ["/admin/account", "account"],
  ]) {
    await gotoPage(page, route);
    await assertNavigation(page, "developer", active);
  }
  for (const route of ["/admin/users", "/admin/api-clients", "/admin/settings/email", "/admin/system"]) {
    await gotoPage(page, route, 403);
    await assertNavigation(page, "developer", "");
  }
  await gotoPage(page, "/admin");
  await assertNavigation(page, "developer", "dashboard");
  monitor.assertClean();
  await context.close();
});

test("viewer stays read-only and direct writes remain backend-rejected", async ({ browser, baseURL }) => {
  const fixture = fixtures();
  const context = await browser.newContext({ storageState: authState("viewer"), baseURL, viewport: { width: 1366, height: 768 } });
  const page = await context.newPage();
  const monitor = await monitorPage(page, baseURL);
  for (const [route, active] of [
    ["/admin", "dashboard"], ["/admin/secrets", "secret-links"], [`/admin/secrets/${fixture.secretID}`, "secret-links"],
    ["/admin/system", "system-status"], ["/docs", "api-docs"], ["/admin/help", "help"], ["/admin/account", "account"],
  ]) {
    await gotoPage(page, route);
    await assertNavigation(page, "viewer", active);
    await expect(page.locator('a[href="/admin/secrets/new"]')).toHaveCount(0);
    await expect(page.locator("[data-revoke-id]")).toHaveCount(0);
  }
  await gotoPage(page, "/admin/secrets/new", 403);
  await assertNavigation(page, "viewer", "");
  const writeResponse = await context.request.post("/api/v1/secret-links", { data: { secret: "blocked-viewer-write", expires_in_seconds: 600 } });
  expect(writeResponse.status()).toBe(401);
  await gotoPage(page, "/admin");
  await assertNavigation(page, "viewer", "dashboard");
  monitor.assertClean();
  await context.close();
});
