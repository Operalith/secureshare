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

const previewExpirationUTC = "2026-08-10T13:03:00Z";

const recipientCopy = {
  en: {
    direction: "ltr",
    readyTitle: "View confidential information",
    intro: "Please note that this information can only be viewed once. Before revealing it, make sure you are in a secure environment and save the information in a trusted location to avoid losing access to it.",
    readyStatus: "The information remains available until you choose “Reveal information”.",
    readyWarning: "Make sure you save the information. After it is revealed, leaving or refreshing this page will permanently remove your access to it.",
    revealedTitle: "Confidential information revealed",
    revealedDescription: "Copy all of the information now and store it only in a secure location you trust.",
    revealedWarning: "Once you leave or refresh this page, this information cannot be viewed again.",
    unavailableTitle: "This link is no longer available",
    unavailableMessage: "This link has expired, was revoked, or has already been viewed.",
    dateLocale: "en",
  },
  fa: {
    direction: "rtl",
    readyTitle: "مشاهده اطلاعات محرمانه",
    intro: "توجه داشته باشید این اطلاعات فقط یک‌بار قابل نمایش است. پیش از اقدام برای مشاهده از امنیت محیط اطمینان حاصل کنید و حتما اطلاعات را برای پیشگیری از فراموشی در یک جای امن ذخیره کنید.",
    readyStatus: "اطلاعات فقط تا پیش از انتخاب «نمایش اطلاعات» قابل مشاهده است.",
    readyWarning: "اطلاعات را حتما ذخیره کنید. پس از نمایش، یا خروج یا بارگذاری مجدد صفحه دیگر به آن دسترسی ندارید.",
    revealedTitle: "نمایش اطلاعات محرمانه",
    revealedDescription: "همه اطلاعات را همین حالا کپی و فقط در محل امن مورد تأیید خودتان حفظ و نگهداری کنید.",
    revealedWarning: "پس از خروج از این صفحه یا بارگذاری مجدد آن، امکان مشاهده دوباره این اطلاعات وجود ندارد.",
    unavailableTitle: "این لینک دیگر در دسترس نیست",
    unavailableMessage: "این لینک منقضی شده، لغو شده یا قبلاً مشاهده شده است.",
    dateLocale: "fa-IR-u-ca-persian",
  },
};

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
    const heading = document.querySelector(".recipient-heading").getBoundingClientRect();
    const intro = document.querySelector("#recipient-intro").getBoundingClientRect();
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
      headingWidth: heading.width,
      introWidth: intro.width,
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
  if (state === "ready") {
    expect(Math.abs(metrics.headingWidth - metrics.introWidth)).toBeLessThanOrEqual(1);
  }
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

async function assertRecipientDate(page, rawUTC, locale) {
  const expected = await page.evaluate(({ value, dateLocale }) => new Intl.DateTimeFormat(dateLocale, {
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value)), { value: rawUTC, dateLocale: recipientCopy[locale].dateLocale });
  const time = page.locator("#expires-state time");
  await expect(time).toHaveAttribute("datetime", rawUTC);
  await expect(time).toHaveAttribute("title", rawUTC);
  await expect(time).toHaveText(expected);
  if (locale === "fa") {
    if (rawUTC === previewExpirationUTC) await expect(time).toContainText("۱۴۰۵");
    await expect(time).not.toContainText(/\d{4}/);
  } else if (rawUTC === previewExpirationUTC) {
    await expect(time).toContainText("2026");
  }
}

async function assertSemanticAlert(page, selector, kind, iconSelector = ".recipient-alert__icon") {
  const styles = await page.locator(selector).evaluate((element, { semanticKind, nestedIconSelector }) => {
    const tokenPrefix = semanticKind === "status" ? "info" : semanticKind;
    const resolveColor = (token) => {
      const probe = document.createElement("span");
      probe.style.color = `var(${token})`;
      document.body.appendChild(probe);
      const value = getComputedStyle(probe).color;
      probe.remove();
      return value;
    };
    const channels = (value) => (value.match(/[\d.]+/g) || []).slice(0, 3).map(Number);
    const luminance = (value) => {
      const rgb = channels(value).map((channel) => {
        const normalized = channel / 255;
        return normalized <= 0.04045 ? normalized / 12.92 : ((normalized + 0.055) / 1.055) ** 2.4;
      });
      return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2];
    };
    const contrast = (foreground, background) => {
      const values = [luminance(foreground), luminance(background)].sort((a, b) => b - a);
      return (values[0] + 0.05) / (values[1] + 0.05);
    };
    const style = getComputedStyle(element);
    const icon = nestedIconSelector ? element.querySelector(nestedIconSelector) : null;
    const iconStyle = icon ? getComputedStyle(icon) : null;
    return {
      background: style.backgroundColor,
      border: style.borderTopColor,
      text: style.color,
      expectedBackground: resolveColor(`--public-${tokenPrefix}-bg`),
      expectedBorder: resolveColor(`--public-${tokenPrefix}-border`),
      expectedText: resolveColor(`--public-${tokenPrefix}-text`),
      icon: iconStyle?.color || "",
      iconBackground: iconStyle?.backgroundColor || "",
      expectedIcon: icon ? resolveColor(`--public-${tokenPrefix}-icon`) : "",
      expectedIconBackground: icon ? resolveColor(`--public-${tokenPrefix}-icon-bg`) : "",
      contrast: contrast(style.color, style.backgroundColor),
    };
  }, { semanticKind: kind, nestedIconSelector: iconSelector });

  expect(styles.background).toBe(styles.expectedBackground);
  expect(styles.border).toBe(styles.expectedBorder);
  expect(styles.text).toBe(styles.expectedText);
  expect(styles.contrast).toBeGreaterThanOrEqual(4.5);
  expect([styles.background, styles.border, styles.text, styles.icon, styles.iconBackground]).not.toContain("rgb(255, 0, 0)");
  expect([styles.background, styles.border, styles.text, styles.icon, styles.iconBackground]).not.toContain("rgb(0, 255, 0)");
  if (iconSelector) {
    expect(styles.icon).toBe(styles.expectedIcon);
    expect(styles.iconBackground).toBe(styles.expectedIconBackground);
  }
}

async function assertUnavailableIcon(page) {
  const styles = await page.locator(".recipient-status-icon--unavailable").evaluate((element) => {
    const resolveColor = (token) => {
      const probe = document.createElement("span");
      probe.style.color = `var(${token})`;
      document.body.appendChild(probe);
      const value = getComputedStyle(probe).color;
      probe.remove();
      return value;
    };
    const style = getComputedStyle(element);
    return {
      background: style.backgroundColor,
      color: style.color,
      expectedBackground: resolveColor("--public-unavailable-icon-bg"),
      expectedColor: resolveColor("--public-unavailable-icon"),
    };
  });
  expect(styles.background).toBe(styles.expectedBackground);
  expect(styles.color).toBe(styles.expectedColor);
  expect([styles.background, styles.color]).not.toContain("rgb(255, 0, 0)");
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
    const body = await response.json();
    expect(body.expires_at).toMatch(/Z$/);
    return body;
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

    const englishPrepareResponse = page.waitForResponse((response) => response.url().endsWith("/api/v1/secret-links/prepare") && response.request().method() === "POST");
    await page.goto(`/s${englishFragment}`, { waitUntil: "domcontentloaded" });
    const englishPrepared = await englishPrepareResponse;
    const englishPrepareBody = await englishPrepared.json();
    expect(new Date(englishPrepareBody.expires_at).getTime()).toBe(new Date(english.expires_at).getTime());
    await expect(page).toHaveURL(/\/s$/);
    await expect(page.locator("html")).toHaveAttribute("lang", "en");
    await expect(page.locator("html")).toHaveAttribute("dir", "ltr");
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "ready");
    await expect(page.locator("#recipient-title")).toHaveText(recipientCopy.en.readyTitle);
    await expect(page.locator("#recipient-intro")).toHaveText(recipientCopy.en.intro);
    await expect(page.locator(".recipient-alert--status #prepare-state")).toHaveText(recipientCopy.en.readyStatus);
    await expect(page.locator("#ready-state .recipient-alert--warning span:last-child")).toHaveText(recipientCopy.en.readyWarning);
    await assertRecipientDate(page, englishPrepareBody.expires_at, "en");
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
    await expect(page.getByRole("heading", { name: recipientCopy.en.revealedTitle })).toBeVisible();
    await expect(page.locator(".recipient-state-heading p")).toHaveText(recipientCopy.en.revealedDescription);
    await expect(page.locator("#revealed-secret-wrap .recipient-alert--warning span:last-child")).toHaveText(recipientCopy.en.revealedWarning);
    await expect(page.locator("#revealed-secret")).toHaveText(englishValue);
    await expect(page.getByText(englishValue, { exact: true })).toHaveCount(1);
    await expect(page.locator("#password-wrap")).toBeHidden();
    await expect(page.locator("#reveal-button")).toBeHidden();
    await expect(page.getByRole("button", { name: "Revealing information..." })).toHaveCount(0);
    await page.locator("#copy-secret").click();
    await expect(page.locator(".toast").last()).toHaveText("Copied");
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
    await expect(page.locator("#unavailable-message")).toHaveText(recipientCopy.en.unavailableMessage);
    await expect(page.locator("#unavailable-wrap .recipient-alert--unavailable")).toHaveCount(1);
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

    const persianPrepareResponse = page.waitForResponse((response) => response.url().endsWith("/api/v1/secret-links/prepare") && response.request().method() === "POST");
    const persianPageResponse = await page.goto(`/s${persianFragment}`, { waitUntil: "domcontentloaded" });
    const persianPrepared = await persianPrepareResponse;
    const persianPrepareBody = await persianPrepared.json();
    expect(new Date(persianPrepareBody.expires_at).getTime()).toBe(new Date(persian.expires_at).getTime());
    expect(persianPageResponse.status()).toBe(200);
    expect(persianPageResponse.headers()["content-security-policy"]).toContain("font-src 'self'");
    await expect(page.locator("html")).toHaveAttribute("lang", "fa");
    await expect(page.locator("html")).toHaveAttribute("dir", "rtl");
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "ready");
    await expect(page.locator("#recipient-title")).toHaveText(recipientCopy.fa.readyTitle);
    await expect(page.locator("#recipient-intro")).toHaveText(recipientCopy.fa.intro);
    await expect(page.locator(".recipient-alert--status #prepare-state")).toHaveText(recipientCopy.fa.readyStatus);
    await expect(page.locator("#ready-state .recipient-alert--warning span:last-child")).toHaveText(recipientCopy.fa.readyWarning);
    await expect(page.locator("#reveal-button")).toHaveText("نمایش اطلاعات");
    await assertRecipientDate(page, persianPrepareBody.expires_at, "fa");
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
    await expect(page.getByRole("heading", { name: recipientCopy.fa.revealedTitle })).toBeVisible();
    await expect(page.locator(".recipient-state-heading p")).toHaveText(recipientCopy.fa.revealedDescription);
    await expect(page.locator("#revealed-secret-wrap .recipient-alert--warning span:last-child")).toHaveText(recipientCopy.fa.revealedWarning);
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
    await apiKeyRow.getByRole("button", { name: "کپی" }).click();
    await expect(page.locator(".toast").last()).toHaveText("کپی شد");
    await page.locator("#copy-secret").click();
    await expect(page.locator(".toast").last()).toHaveText("کپی شد");
    await assertRecipientLayout(page);
    await assertRecipientTypography(page, "fa", "revealed");

    await page.goto("about:blank");
    await page.goto(`/s${persianFragment}`, { waitUntil: "domcontentloaded" });
    await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "unavailable");
    await expect(page.locator("#unavailable-title")).toHaveText("این لینک دیگر در دسترس نیست");
    await expect(page.locator("#unavailable-message")).toHaveText(recipientCopy.fa.unavailableMessage);
    await expect(page.locator("#unavailable-wrap .recipient-alert--unavailable")).toHaveCount(1);
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

test("recipient previews keep semantic alerts readable in light and dark themes", async ({ page, baseURL }) => {
  const monitor = await monitorPage(page, baseURL);

  for (const theme of ["light", "dark"]) {
    await page.emulateMedia({ colorScheme: theme });
    for (const locale of ["en", "fa"]) {
      const copy = recipientCopy[locale];
      for (const state of ["ready", "revealed", "unavailable"]) {
        const response = await page.goto(`/admin/settings/public-experience/preview?state=${state}&locale=${locale}`, { waitUntil: "domcontentloaded" });
        expect(response.status()).toBe(200);
        await expect(page.locator("html")).toHaveAttribute("lang", locale);
        await expect(page.locator("html")).toHaveAttribute("dir", copy.direction);
        await expect(page.locator("body")).toHaveAttribute("data-recipient-state", state);
        expect(await page.locator("html").evaluate((element) => getComputedStyle(element).colorScheme)).toBe(theme);
        await assertRecipientLayout(page);
        await assertRecipientTypography(page, locale, state);

        if (state === "ready") {
          await expect(page.locator("#recipient-title")).toHaveText(copy.readyTitle);
          await expect(page.locator("#recipient-intro")).toHaveText(copy.intro);
          await expect(page.locator(".recipient-alert--status #prepare-state")).toHaveText(copy.readyStatus);
          await expect(page.locator("#ready-state .recipient-alert--warning span:last-child")).toHaveText(copy.readyWarning);
          await assertSemanticAlert(page, ".recipient-alert--status", "status");
          await assertSemanticAlert(page, "#ready-state .recipient-alert--warning", "warning");
          await assertRecipientDate(page, previewExpirationUTC, locale);
        }

        if (state === "revealed") {
          await expect(page.getByRole("heading", { name: copy.revealedTitle })).toBeVisible();
          await expect(page.locator(".recipient-state-heading p")).toHaveText(copy.revealedDescription);
          await expect(page.locator("#revealed-secret-wrap .recipient-alert--warning span:last-child")).toHaveText(copy.revealedWarning);
          await assertSemanticAlert(page, "#revealed-secret-wrap .recipient-alert--warning", "warning");
          await expect(page.locator("#password-wrap")).toBeHidden();
          await expect(page.locator("#reveal-button")).toBeHidden();
          await expect(page.getByText(/Revealing information|در حال نمایش/)).toHaveCount(0);
          const previewValue = page.locator(".revealed-field .technical-value").first();
          expect(await previewValue.evaluate((element) => ({ direction: getComputedStyle(element).direction, bidi: getComputedStyle(element).unicodeBidi }))).toEqual({ direction: "ltr", bidi: "isolate" });
          await expect(page.locator("#copy-secret")).toBeVisible();
        }

        if (state === "unavailable") {
          await expect(page.locator("#unavailable-title")).toHaveText(copy.unavailableTitle);
          await expect(page.locator("#unavailable-message")).toHaveText(copy.unavailableMessage);
          await expect(page.locator("#unavailable-wrap .recipient-alert--unavailable")).toHaveCount(1);
          await assertSemanticAlert(page, "#unavailable-message", "unavailable", null);
          await assertUnavailableIcon(page);
          const neutralHierarchy = await page.evaluate(() => {
            const card = getComputedStyle(document.querySelector(".recipient-card"));
            const title = getComputedStyle(document.querySelector("#unavailable-title"));
            const message = getComputedStyle(document.querySelector("#unavailable-message"));
            return {
              cardBackground: card.backgroundColor,
              titleColor: title.color,
              messageBackground: message.backgroundColor,
              messageColor: message.color,
            };
          });
          expect(neutralHierarchy.cardBackground).not.toBe(neutralHierarchy.messageBackground);
          expect(neutralHierarchy.titleColor).not.toBe(neutralHierarchy.messageColor);
          await expect(page.locator("#password-wrap")).toBeHidden();
          await expect(page.locator("#reveal-button")).toBeHidden();
        }
      }
    }
  }

  monitor.assertClean();
});
