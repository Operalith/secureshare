const path = require("node:path");
const { defineConfig } = require("@playwright/test");

const authDir = process.env.PLAYWRIGHT_AUTH_DIR || path.join(__dirname, ".auth");
const adminState = path.join(authDir, "admin.json");
const artifactRoot = process.env.PLAYWRIGHT_OUTPUT_DIR || path.join(__dirname, "test-results");

module.exports = defineConfig({
  testDir: path.join(__dirname, "specs"),
  globalSetup: require.resolve("./global-setup"),
  outputDir: path.join(artifactRoot, "results"),
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 45_000,
  expect: { timeout: 8_000 },
  forbidOnly: true,
  reporter: [
    ["line"],
    ["html", { outputFolder: path.join(artifactRoot, "report"), open: "never" }],
  ],
  use: {
    baseURL: process.env.BASE_URL || "http://app-test:8080",
    browserName: "chromium",
    channel: process.env.E2E_BROWSER_CHANNEL || "chrome",
    colorScheme: "light",
    locale: "en-US",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "off",
  },
  projects: [
    { name: "roles", use: { viewport: { width: 1366, height: 768 } } },
    { name: "desktop-1280", use: { storageState: adminState, viewport: { width: 1280, height: 720 } } },
    { name: "desktop-1366", use: { storageState: adminState, viewport: { width: 1366, height: 768 } } },
    { name: "desktop-1440", use: { storageState: adminState, viewport: { width: 1440, height: 900 } } },
    { name: "desktop-1920", use: { storageState: adminState, viewport: { width: 1920, height: 1080 } } },
    { name: "desktop-2560", use: { storageState: adminState, viewport: { width: 2560, height: 1440 } } },
    { name: "tablet-768", use: { storageState: adminState, viewport: { width: 768, height: 1024 }, hasTouch: true } },
    { name: "mobile-375", use: { storageState: adminState, viewport: { width: 375, height: 812 }, isMobile: true, hasTouch: true } },
    { name: "mobile-390", use: { storageState: adminState, viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true } },
  ],
});
