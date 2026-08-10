#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const time = require("../web/static/time.js");

const local = time.format("2026-01-01T00:00:00Z", { locale: "en-US", timeZone: "Asia/Tehran" });
assert.match(local, /3:30:00\s*AM/i);
assert.match(local, /(GMT|UTC|\+03:?30)/i);
assert.equal(time.format(null, { emptyLabel: "Never" }), "Never");
assert.equal(time.format("not-a-timestamp"), "Invalid date");

const knownRecipientUTC = "2026-08-10T13:03:00Z";
const persianRecipient = time.format(knownRecipientUTC, {
  locale: "fa-IR-u-ca-persian",
  preset: "recipient",
  timeZone: "Asia/Tehran",
});
assert.match(persianRecipient, /۱۴۰۵/);
assert.match(persianRecipient, /مرداد/);
assert.match(persianRecipient, /۱۶:۳۳/);
assert.doesNotMatch(persianRecipient, /2026/);

const englishRecipient = time.format(knownRecipientUTC, {
  locale: "en-US-u-ca-gregory",
  preset: "recipient",
  timeZone: "Asia/Tehran",
});
assert.match(englishRecipient, /August 10, 2026/i);
assert.match(englishRecipient, /4:33\s*PM/i);
assert.equal(time.format(null, { preset: "recipient", emptyLabel: "Unavailable" }), "Unavailable");
assert.equal(time.format("not-a-timestamp", { preset: "recipient", invalidLabel: "Invalid recipient date" }), "Invalid recipient date");

const attributes = new Map();
const element = {
  tagName: "TIME",
  textContent: "",
  setAttribute(name, value) { attributes.set(name, value); },
};
time.render(element, "2026-01-01T00:00:00Z", { locale: "en-US", timeZone: "Asia/Tehran" });
assert.equal(attributes.get("title"), "2026-01-01T00:00:00Z");
assert.equal(attributes.get("datetime"), "2026-01-01T00:00:00Z");
assert.equal(attributes.get("data-local-time"), "2026-01-01T00:00:00Z");
assert.match(element.textContent, /3:30:00\s*AM/i);

time.render(element, knownRecipientUTC, {
  locale: "fa-IR-u-ca-persian",
  preset: "recipient",
  timeZone: "Asia/Tehran",
});
assert.equal(attributes.get("datetime"), knownRecipientUTC);
assert.equal(attributes.get("title"), knownRecipientUTC);
assert.match(element.textContent, /۱۴۰۵/);

console.log("Browser-local time formatter test passed.");
