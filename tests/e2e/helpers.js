const fs = require("node:fs");
const path = require("node:path");
const { expect } = require("@playwright/test");

const authDir = process.env.PLAYWRIGHT_AUTH_DIR || path.join(__dirname, ".auth");
const navigationByRole = {
  admin: ["dashboard", "create-secret", "secret-links", "api-clients", "users", "email-settings", "public-experience", "system-status", "api-docs", "help", "account"],
  developer: ["dashboard", "create-secret", "secret-links", "api-docs", "help", "account"],
  viewer: ["dashboard", "secret-links", "system-status", "api-docs", "help", "account"],
};

function authState(role) {
  return path.join(authDir, `${role}.json`);
}

function fixtures() {
  return JSON.parse(fs.readFileSync(path.join(authDir, "fixtures.json"), "utf8"));
}

async function monitorPage(page, baseURL) {
  const problems = [];
  const origin = new URL(baseURL).origin;
  page.on("pageerror", (error) => problems.push(`page error: ${error.message}`));
  page.on("console", (message) => {
    if (message.type() !== "error") return;
    const text = message.text();
    if (text.startsWith("Failed to load resource:")) return;
    if (text.startsWith("Blocked script execution in 'about:blank'") && text.includes("sandboxed")) return;
    problems.push(`console error: ${text}`);
  });
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (!["http:", "https:"].includes(url.protocol)) return;
    if (url.origin !== origin) problems.push(`external request: ${request.url()}`);
  });
  page.on("requestfailed", (request) => problems.push(`request failed: ${request.url()} (${request.failure()?.errorText || "unknown"})`));
  page.on("response", (response) => {
    const request = response.request();
    const type = request.resourceType();
    const responseURL = new URL(response.url());
    if (new URL(response.url()).origin === origin && response.status() === 401 && responseURL.pathname !== "/api/v1/secret-links/consume") {
      problems.push(`unexpected authenticated 401: ${response.url()}`);
    }
    if (["stylesheet", "script", "font", "image"].includes(type) && response.status() >= 400) {
      problems.push(`static asset HTTP ${response.status()}: ${response.url()}`);
    }
    if (responseURL.origin === origin && responseURL.pathname.endsWith(".woff2") && !response.headers()["content-type"]?.startsWith("font/woff2")) {
      problems.push(`invalid WOFF2 content type: ${response.url()} (${response.headers()["content-type"] || "missing"})`);
    }
  });
  await page.addInitScript(() => {
    window.addEventListener("securitypolicyviolation", (event) => {
      console.error(`SecureShare CSP violation: ${event.violatedDirective}`);
    });
  });
  return {
    assertClean() {
      expect(problems, problems.join("\n")).toEqual([]);
    },
  };
}

async function assertNavigation(page, role, activeID = "") {
  const items = page.locator("[data-nav-item-id]");
  await expect(items).toHaveCount(navigationByRole[role].length);
  expect(await items.evaluateAll((nodes) => nodes.map((node) => node.dataset.navItemId))).toEqual(navigationByRole[role]);
  const active = page.locator('[data-nav-item-id][aria-current="page"]');
  if (activeID) {
    await expect(active).toHaveCount(1);
    await expect(active).toHaveAttribute("data-nav-item-id", activeID);
  } else {
    await expect(active).toHaveCount(0);
  }
  await expect(page.locator('form[action="/logout"]')).toHaveCount(1);
  await expect(page.locator(".user-menu-role")).toContainText(role);
  const duplicateIDs = await page.locator("[id]").evaluateAll((nodes) => {
    const ids = nodes.map((node) => node.id).filter(Boolean);
    return ids.filter((id, index) => ids.indexOf(id) !== index);
  });
  expect(duplicateIDs).toEqual([]);
}

async function gotoPage(page, path, status = 200) {
  const response = await page.goto(path, { waitUntil: "domcontentloaded" });
  expect(response?.status()).toBe(status);
  await expect(page.locator("#main-content")).toBeVisible();
}

module.exports = { assertNavigation, authState, fixtures, gotoPage, monitorPage, navigationByRole };
