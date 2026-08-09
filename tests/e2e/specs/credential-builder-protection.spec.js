const { test, expect } = require("@playwright/test");
const { fixtures, gotoPage, monitorPage } = require("../helpers");

test.beforeEach(async ({}, testInfo) => {
  test.skip(testInfo.project.name === "roles", "covered by the role-specific suite");
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

test("active link password can be set replaced and removed without exposing the old value", async ({ page, baseURL }) => {
  const monitor = await monitorPage(page, baseURL);
  const { secretID } = fixtures();
  await gotoPage(page, `/admin/secrets/${secretID}`);

  const form = page.locator("[data-password-protection-form]");
  await expect(form).toBeVisible();
  const remove = form.locator("[data-protection-remove]");
  if (await remove.isVisible()) {
    await remove.click();
    await page.locator('[data-confirm-dialog] button[value="confirm"]').click();
    await expect(page.locator("[data-protection-status]")).toHaveText("No");
  }

  const password = form.locator('input[name="password"]');
  await password.fill("e2e-first-link-password");
  await form.locator("[data-protection-save]").click();
  await expect(page.locator("[data-protection-status]")).toHaveText("Yes");
  await expect(password).toHaveValue("");
  await expect(form.locator("[data-protection-save]")).toHaveText("Replace password");
  await expect(remove).toBeVisible();

  await password.fill("e2e-replacement-link-password");
  await form.locator("[data-protection-save]").click();
  await expect(page.locator(".toast-region")).toContainText("Link password replaced.");
  await expect(password).toHaveValue("");

  await remove.click();
  await page.locator('[data-confirm-dialog] button[value="confirm"]').click();
  await expect(page.locator("[data-protection-status]")).toHaveText("No");
  await expect(remove).toBeHidden();
  await expect(page.locator("main")).not.toContainText("e2e-first-link-password");
  await expect(page.locator("main")).not.toContainText("e2e-replacement-link-password");
  monitor.assertClean();
});
