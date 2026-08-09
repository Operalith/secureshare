const { test, expect } = require("@playwright/test");
const { gotoPage, monitorPage } = require("../helpers");

test.beforeEach(async ({}, testInfo) => {
  test.skip(testInfo.project.name !== "desktop-1280", "Interaction QA runs once; recipient layout owns the six-viewport matrix.");
});

test("credential picker builds mixed independent fields and rejects duplicates", async ({ page, baseURL }) => {
  const monitor = await monitorPage(page, baseURL);
  await gotoPage(page, "/admin/secrets/new");

  const picker = page.locator("#field-preset");
  const rows = page.locator("#kv-rows .secure-field-row");
  await expect(rows).toHaveCount(0);

  await picker.selectOption("username");
  await expect(rows).toHaveCount(1);
  await expect(rows.nth(0).locator('input[name="kv_key"]')).toHaveValue("username");
  await expect(picker).toHaveValue("");

  for (const field of ["password", "api_key", "client_id", "client_secret", "private_key"]) {
    await picker.selectOption(field);
  }
  await expect(rows).toHaveCount(6);
  await expect(rows.nth(1).locator('input[name="kv_sensitive"]')).toBeChecked();
  await expect(rows.nth(3).locator('input[name="kv_sensitive"]')).not.toBeChecked();
  await expect(rows.nth(5).locator('input[name="kv_multiline"]')).toBeChecked();

  await page.locator("#add-kv-row").click();
  await rows.last().locator('input[name="kv_key"]').fill("USERNAME");
  await page.locator('#create-secret-form button[type="submit"]').click();
  await expect(page.locator("#create-status")).toContainText("Duplicate key: USERNAME");

  await rows.last().locator("[data-remove-row]").click();
  await picker.selectOption("__custom__");
  await rows.last().locator('input[name="kv_key"]').fill("tenant_code");
  await rows.last().locator('input[name="kv_value"]').fill("tenant-42");
  await expect(picker).toHaveValue("");
  await expect(rows).toHaveCount(7);
  const overflow = await page.evaluate(() => {
    window.scrollTo({ left: 0, top: window.scrollY, behavior: "instant" });
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
  monitor.assertClean();
});

test("active link password can be replaced and removed without exposing the current value", async ({ page, request, baseURL }, testInfo) => {
  const monitor = await monitorPage(page, baseURL);
  const ipOctet = 20 + ([...testInfo.project.name].reduce((sum, character) => sum + character.charCodeAt(0), 0) % 180);
  const bearer = {
    Authorization: `Bearer ${process.env.TEST_SECURESHARE_ADMIN_API_KEY || "test-admin-api-key-change-me"}`,
    "X-Forwarded-For": `198.51.100.${ipOctet}`,
  };
  await page.context().setExtraHTTPHeaders({ "X-Forwarded-For": bearer["X-Forwarded-For"] });
  const createFixture = async (suffix, password, value) => {
    const response = await request.post("/api/v1/secret-links", {
      headers: bearer,
      data: {
        title: `Protection QA ${suffix} ${testInfo.project.name}`,
        recipient_reference: `protection-${suffix}-${testInfo.project.name}-${Date.now()}`,
        expires_in_seconds: 900,
        password,
        payload: { type: "text", text: value },
      },
    });
    expect(response.status()).toBe(201);
    return response.json();
  };

  const oldPassword = "e2e-first-link-password";
  const replacementPassword = "e2e-replacement-link-password";
  const replacementValue = `replacement-value-${testInfo.project.name}-${Date.now()}`;
  const replaced = await createFixture("replace", oldPassword, replacementValue);
  await gotoPage(page, `/admin/secrets/${replaced.id}`);

  const form = page.locator("[data-password-protection-form]");
  await expect(form).toBeVisible();
  const password = form.locator('input[name="password"]');
  await expect(page.locator("[data-protection-status]")).toHaveText("Yes");
  await expect(password).toHaveValue("");
  await password.fill(replacementPassword);
  await form.locator("[data-protection-save]").click();
  await expect(page.locator(".toast-region")).toContainText("Link password replaced.");
  await expect(password).toHaveValue("");
  await expect(page.locator("main")).not.toContainText(oldPassword);
  await expect(page.locator("main")).not.toContainText(replacementPassword);

  const replacementFragment = new URL(replaced.url).hash;
  await page.goto(`/s${replacementFragment}`, { waitUntil: "domcontentloaded" });
  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "ready");
  await page.locator("#link-password").fill(oldPassword);
  await page.locator("#reveal-button").click();
  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "password_error");
  await page.locator("#link-password").fill(replacementPassword);
  await page.locator("#reveal-button").click();
  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "revealed");
  await expect(page.locator("#revealed-secret")).toHaveText(replacementValue);

  const removedValue = `removed-value-${testInfo.project.name}-${Date.now()}`;
  const removed = await createFixture("remove", "e2e-remove-link-password", removedValue);
  await gotoPage(page, `/admin/secrets/${removed.id}`);
  const removeForm = page.locator("[data-password-protection-form]");
  await expect(removeForm.locator('input[name="password"]')).toHaveValue("");
  await removeForm.locator("[data-protection-remove]").click();
  await page.locator('[data-confirm-dialog] button[value="confirm"]').click();
  await expect(page.locator("[data-protection-status]")).toHaveText("No");
  await expect(removeForm.locator("[data-protection-remove]")).toBeHidden();

  await page.goto(`/s${new URL(removed.url).hash}`, { waitUntil: "domcontentloaded" });
  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "ready");
  await expect(page.locator("#password-wrap")).toBeHidden();
  await page.locator("#reveal-button").click();
  await expect(page.locator("body")).toHaveAttribute("data-recipient-state", "revealed");
  await expect(page.locator("#revealed-secret")).toHaveText(removedValue);
  monitor.assertClean();
});
