#!/usr/bin/env node
"use strict";

const assert = require("node:assert/strict");
const time = require("../web/static/time.js");

const local = time.format("2026-01-01T00:00:00Z", { locale: "en-US", timeZone: "Asia/Tehran" });
assert.match(local, /3:30:00\s*AM/i);
assert.match(local, /(GMT|UTC|\+03:?30)/i);
assert.equal(time.format(null, { emptyLabel: "Never" }), "Never");
assert.equal(time.format("not-a-timestamp"), "Invalid date");

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

console.log("Browser-local time formatter test passed.");
