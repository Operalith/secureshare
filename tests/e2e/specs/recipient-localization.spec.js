const { test, expect } = require("@playwright/test");
const { gotoPage, monitorPage } = require("../helpers");

const requiredProjects = new Set([
  "desktop-1366",
  "desktop-1440",
  "desktop-1920",
  "tablet-768",
  "mobile-375",
  "mobile-390",
]);

test.beforeEach(({}, testInfo) => {
  test.skip(!requiredProjects.has(testInfo.project.name), "Recipient locale QA uses the required six viewport matrix.");
});

async function saveLocale(page, locale) {
  await gotoPage(page, "/admin/settings/public-experience");
  await page.locator('[name="public_locale"]').selectOption(locale);
  const saved = page.waitForResponse((response) => response.url().endsWith("/api/v1/settings/public-experience") && response.request().method() === "PUT");
  await page.locator("[data-public-experience-settings] button[type=submit]").click();
  expect((await saved).status()).toBe(200);
  await expect(page.locator("[data-public-experience-status]")).toHaveText("Public recipient language saved.");
}

async function assertRecipientLayout(page) {
  await expect(page.locator('[data-recipient-state-panel]:visible')).toHaveCount(1);
  const layout = await page.evaluate(() => {
    const viewportWidth = document.documentElement.clientWidth;
    const card = document.querySelector(".recipient-card").getBoundingClientRect();
    return {
      overflow: document.documentElement.scrollWidth - viewportWidth,
      cardLeft: card.left,
      cardRight: card.right,
      cardWidth: card.width,
      viewportWidth,
    };
  });
  expect(layout.overflow).toBeLessThanOrEqual(1);
  expect(layout.cardLeft).toBeGreaterThanOrEqual(-1);
  expect(layout.cardRight).toBeLessThanOrEqual(layout.viewportWidth + 1);
  expect(layout.cardWidth).toBeLessThanOrEqual(layout.viewportWidth);
}

test("English and Persian recipient states remain localized secure and responsive", async ({ page, request, baseURL }, testInfo) => {
  const monitor = await monitorPage(page, baseURL);
  const fontRequests = [];
  page.on("request", (resource) => {
    if (resource.resourceType() === "font") fontRequests.push(resource.url());
  });
  const projectOctet = 30 + ([...testInfo.project.name].reduce((sum, character) => sum + character.charCodeAt(0), 0) % 170);
  const forwardedFor = `203.0.113.${projectOctet}`;
  await page.context().setExtraHTTPHeaders({ "X-Forwarded-For": forwardedFor });

  const createFixture = async ({ locale, password, payload }) => {
    const marker = `recipient-${locale}-${testInfo.project.name}-${Date.now()}`;
    const response = await request.post("/api/v1/secret-links", {
      headers: {
        Authorization: `Bearer ${process.env.TEST_SECURESHARE_ADMIN_API_KEY || "test-admin-api-key-change-me"}`,
        "X-Forwarded-For": forwardedFor,
      },
      data: {
        title: `Recipient locale QA ${marker}`,
        recipient_reference: marker,
        expires_in_seconds: 900,
        password,
        max_failed_attempts: 5,
        payload,
      },
    });
    expect(response.status()).toBe(201);
    return response.json();
  };

  try {
    await saveLocale(page, "en");
    const englishPassword = "english-recipient-password";
    const englishValue = `english-recipient-secret-${testInfo.project.name}-${Date.now()}`;
    const english = await createFixture({
      locale: "en",
      password: englishPassword,
      payload: { type: "text", text: englishValue },
    });
    const englishFragment = new URL(english.url).hash;
    expect(englishFragment.length).toBeGreaterThan(1);

    await page.goto(`/s${englishFragment}`, { waitUntil: "domcontentloaded" });
    await expect(page).toHaveURL(/\/s$/);
    await expect(page.locator("html")).toHaveAttribute("lang", "en");
    await expect(page.locator("html")).toHaveAttribute("dir", "ltr");
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "ready");
    await expect(page.locator("#recipient-title")).toHaveText("A secure secret has been shared with you");
    await assertRecipientLayout(page);

    await page.locator("#link-password").fill("wrong-english-password");
    await page.locator("#reveal-button").click();
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "password_error");
    await expect(page.locator("#password-error")).toHaveText("The link password is incorrect. Try again.");
    await expect(page.locator("#reveal-button")).toBeEnabled();
    await expect(page.locator("#unavailable-wrap")).toBeHidden();
    await assertRecipientLayout(page);

    await page.locator("#link-password").fill(englishPassword);
    await page.locator("#reveal-button").click();
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "revealed");
    await expect(page.locator("#revealed-secret")).toHaveText(englishValue);
    await expect(page.getByText(englishValue, { exact: true })).toHaveCount(1);
    await expect(page.locator("#password-wrap")).toBeHidden();
    await expect(page.locator("#reveal-button")).toBeHidden();
    await expect(page.getByRole("button", { name: "Revealing..." })).toHaveCount(0);
    await assertRecipientLayout(page);

    await page.reload({ waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "unavailable");
    await expect(page.locator("#unavailable-title")).toHaveText("Reopen the original secure link");
    await expect(page.locator("#reveal-button")).toBeHidden();
    await page.goto("about:blank");
    await page.goto(`/s${englishFragment}`, { waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "unavailable");
    await expect(page.locator("#unavailable-title")).toHaveText("This link is no longer available");
    await expect(page.locator("#password-wrap")).toBeHidden();
    await assertRecipientLayout(page);

    await saveLocale(page, "fa");
    const persianPassword = "persian-recipient-password";
    const usernameValue = `qa.user.${testInfo.project.name}`;
    const apiKeyValue = `QA_KEY_${testInfo.project.name}_${Date.now()}`;
    const persian = await createFixture({
      locale: "fa",
      password: persianPassword,
      payload: {
        type: "structured",
        fields: [
          { name: "username", label: "Username", value: usernameValue, sensitive: false, multiline: false },
          { name: "api_key", label: "API Key", value: apiKeyValue, sensitive: true, multiline: false },
        ],
      },
    });
    const persianFragment = new URL(persian.url).hash;

    await page.goto(`/s${persianFragment}`, { waitUntil: "domcontentloaded" });
    await expect(page.locator("html")).toHaveAttribute("lang", "fa");
    await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "ready");
    await expect(page.locator("#recipient-title")).toHaveText("یک اطلاعات محرمانه برای شما ارسال شده است");
    await expect(page.locator("#reveal-button")).toHaveText("نمایش اطلاعات");
    await assertRecipientLayout(page);

    await page.locator("#link-password").fill("wrong-persian-password");
    await page.locator("#reveal-button").click();
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "password_error");
    await expect(page.locator("#password-error")).toHaveText("رمز لینک صحیح نیست. دوباره تلاش کنید.");
    await expect(page.locator("#reveal-button")).toBeEnabled();
    await expect(page.locator("#unavailable-wrap")).toBeHidden();

    await page.locator("#link-password").fill(persianPassword);
    await page.locator("#reveal-button").click();
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "revealed");
    await expect(page.getByRole("heading", { name: "اطلاعات محرمانه نمایش داده شد" })).toBeVisible();
    await expect(page.locator("#password-wrap")).toBeHidden();
    await expect(page.locator("#reveal-button")).toBeHidden();
    const values = page.locator(".revealed-field .secret-value");
    await expect(values.nth(0)).toHaveText(usernameValue);
    expect(await values.nth(0).evaluate((element) => ({ direction: getComputedStyle(element).direction, bidi: getComputedStyle(element).unicodeBidi }))).toEqual({ direction: "ltr", bidi: "isolate" });
    const apiKeyRow = page.locator(".revealed-field").nth(1);
    await expect(apiKeyRow.locator(".secret-value")).not.toHaveText(apiKeyValue);
    await apiKeyRow.getByRole("button", { name: "نمایش" }).click();
    await expect(apiKeyRow.locator(".secret-value")).toHaveText(apiKeyValue);
    expect(await apiKeyRow.locator(".secret-value").evaluate((element) => getComputedStyle(element).direction)).toBe("ltr");
    await assertRecipientLayout(page);

    await page.goto("about:blank");
    await page.goto(`/s${persianFragment}`, { waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "unavailable");
    await expect(page.locator("#unavailable-title")).toHaveText("این لینک دیگر در دسترس نیست");
    await expect(page.locator("#reveal-button")).toBeHidden();
    await expect(page.locator("#password-wrap")).toBeHidden();
    await assertRecipientLayout(page);

    await page.evaluate(() => document.fonts.ready);
    const fontFamily = await page.locator(".recipient-card").evaluate((element) => getComputedStyle(element).fontFamily);
    expect(fontFamily).toContain("Vazirmatn");
    expect(fontFamily).toContain("Tahoma");
    expect(fontRequests.every((url) => new URL(url).origin === new URL(baseURL).origin)).toBe(true);
  } finally {
    if (!page.isClosed()) await saveLocale(page, "en");
  }

  monitor.assertClean();
});
