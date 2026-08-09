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

async function assertRecipientTypography(page, locale, state) {
  const metrics = await page.evaluate(({ expectedLocale, expectedState }) => {
    const visible = (element) => element && getComputedStyle(element).display !== "none" && element.getClientRects().length > 0;
    const card = document.querySelector(".recipient-card").getBoundingClientRect();
    const title = document.querySelector("#recipient-title");
    const titleStyle = getComputedStyle(title);
    const titleRect = title.getBoundingClientRect();
    const secondaryTitle = document.querySelector('[data-recipient-state-panel]:not(.hidden) h2');
    const secondaryStyle = secondaryTitle ? getComputedStyle(secondaryTitle) : null;
    const controls = [...document.querySelectorAll(".recipient-card button, .recipient-card input")]
      .filter(visible)
      .map((element) => element.getBoundingClientRect().height);
    return {
      locale: document.documentElement.lang,
      state: document.body.dataset.recipientState,
      viewportWidth: document.documentElement.clientWidth,
      viewportHeight: document.documentElement.clientHeight,
      cardHeight: card.height,
      titleVisible: visible(title),
      titleSize: Number.parseFloat(titleStyle.fontSize),
      titleWeight: titleStyle.fontWeight,
      titleLineHeight: Number.parseFloat(titleStyle.lineHeight),
      titleLetterSpacing: titleStyle.letterSpacing,
      titleLines: titleRect.height / Number.parseFloat(titleStyle.lineHeight),
      titleCardRatio: titleRect.height / card.height,
      secondarySize: secondaryStyle ? Number.parseFloat(secondaryStyle.fontSize) : null,
      controlHeights: controls,
      expectedLocale,
      expectedState,
    };
  }, { expectedLocale: locale, expectedState: state });

  expect(metrics.locale).toBe(locale);
  expect(metrics.state).toBe(state);
  expect(metrics.controlHeights.every((height) => height >= 44)).toBe(true);
  if (metrics.titleVisible) {
    const limits = locale === "fa" ? [28, 33.6] : [28.8, 36];
    expect(metrics.titleSize).toBeGreaterThanOrEqual(limits[0] - 0.1);
    expect(metrics.titleSize).toBeLessThanOrEqual(limits[1] + 0.1);
    expect(metrics.titleWeight).toBe("700");
    expect(metrics.titleLetterSpacing === "normal" || metrics.titleLetterSpacing === "0px").toBe(true);
    expect(metrics.titleCardRatio).toBeLessThanOrEqual(0.25);
    if (locale === "fa") {
      expect(metrics.titleLineHeight / metrics.titleSize).toBeGreaterThanOrEqual(1.54);
      expect(metrics.titleLineHeight / metrics.titleSize).toBeLessThanOrEqual(1.56);
      if (metrics.viewportWidth >= 1366) expect(metrics.titleLines).toBeLessThanOrEqual(2.1);
    }
  }
  if (metrics.secondarySize !== null) {
    expect(metrics.secondarySize).toBeGreaterThanOrEqual(22.4 - 0.1);
    expect(metrics.secondarySize).toBeLessThanOrEqual(28 + 0.1);
  }
  expect(metrics.cardHeight).toBeLessThanOrEqual(metrics.viewportHeight + 1);
}

test("English and Persian recipient states remain localized secure and responsive", async ({ page, request, baseURL }, testInfo) => {
  const monitor = await monitorPage(page, baseURL);
  const fontRequests = [];
  const fontResponses = [];
  page.on("request", (resource) => {
    if (resource.resourceType() === "font") fontRequests.push(resource.url());
  });
  page.on("response", (response) => {
    if (response.request().resourceType() !== "font") return;
    fontResponses.push({
      url: response.url(),
      status: response.status(),
      contentType: response.headers()["content-type"] || "",
    });
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
    await assertRecipientTypography(page, "en", "ready");

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
    await assertRecipientTypography(page, "en", "revealed");

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
    await assertRecipientTypography(page, "en", "unavailable");
    expect(fontRequests).toEqual([]);

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

    const persianPageResponse = await page.goto(`/s${persianFragment}`, { waitUntil: "domcontentloaded" });
    expect(persianPageResponse.status()).toBe(200);
    expect(persianPageResponse.headers()["content-security-policy"]).toContain("font-src 'self'");
    await expect(page.locator("html")).toHaveAttribute("lang", "fa");
    await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "ready");
    await expect(page.locator("#recipient-title")).toHaveText("یک اطلاعات محرمانه برای شما ارسال شده است");
    await expect(page.locator("#reveal-button")).toHaveText("نمایش اطلاعات");
    await assertRecipientLayout(page);
    await assertRecipientTypography(page, "fa", "ready");

    await page.evaluate(() => document.fonts.ready);
    const fontVerification = await page.locator("#recipient-title").evaluate((element) => {
      const family = getComputedStyle(element).fontFamily;
      const faces = [...document.fonts]
        .filter((face) => face.family.replaceAll('"', "") === "Vazirmatn")
        .map((face) => ({ status: face.status, weight: face.weight }));
      return {
        family,
        primaryFamily: family.split(",")[0].trim().replaceAll('"', ""),
        available: document.fonts.check('700 32px "Vazirmatn"', element.textContent),
        faces,
      };
    });
    expect(fontVerification.primaryFamily).toBe("Vazirmatn");
    expect(fontVerification.available).toBe(true);
    expect(fontVerification.faces).toContainEqual({ status: "loaded", weight: "100 900" });
    expect(fontVerification.family).toContain("Vazirmatn");

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
    await assertRecipientTypography(page, "fa", "revealed");

    await page.goto("about:blank");
    await page.goto(`/s${persianFragment}`, { waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "unavailable");
    await expect(page.locator("#unavailable-title")).toHaveText("این لینک دیگر در دسترس نیست");
    await expect(page.locator("#reveal-button")).toBeHidden();
    await expect(page.locator("#password-wrap")).toBeHidden();
    await assertRecipientLayout(page);
    await assertRecipientTypography(page, "fa", "unavailable");

    expect(fontRequests.length).toBeGreaterThan(0);
    expect(fontRequests.every((url) => new URL(url).origin === new URL(baseURL).origin)).toBe(true);
    expect(fontRequests.every((url) => new URL(url).pathname === "/static/fonts/Vazirmatn-Variable.woff2")).toBe(true);
    expect(fontResponses.length).toBeGreaterThan(0);
    expect(fontResponses.every((response) => response.status === 200)).toBe(true);
    expect(fontResponses.every((response) => response.contentType.startsWith("font/woff2"))).toBe(true);
  } finally {
    if (!page.isClosed()) await saveLocale(page, "en");
  }

  monitor.assertClean();
});
