const fs = require("node:fs");
const vm = require("node:vm");

class FakeClassList {
  constructor() {
    this.values = new Set();
  }

  contains(name) {
    return this.values.has(name);
  }

  toggle(name, force) {
    const enabled = force === undefined ? !this.contains(name) : Boolean(force);
    if (enabled) this.values.add(name);
    else this.values.delete(name);
    return enabled;
  }
}

class FakeElement {
  constructor(document) {
    this.document = document;
    this.classList = new FakeClassList();
    this.listeners = new Map();
    this.attributes = new Map();
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }

  dispatch(type, event = {}) {
    for (const listener of this.listeners.get(type) || []) listener(event);
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) || null;
  }

  hasAttribute(name) {
    return this.attributes.has(name);
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  focus() {
    this.document.activeElement = this;
  }
}

class FakeDocument {
  constructor() {
    this.listeners = new Map();
    this.body = { classList: new FakeClassList() };
    this.documentElement = { dataset: {} };
    this.activeElement = null;
    this.sidebar = new FakeElement(this);
    this.opener = new FakeElement(this);
    this.close = new FakeElement(this);
    this.backdrop = new FakeElement(this);
    this.navLink = new FakeElement(this);
    this.sidebar.querySelector = (selector) => selector === "[data-menu-close]" ? this.close : null;
    this.sidebar.querySelectorAll = (selector) => selector === "a[href]" ? [this.navLink] : [this.close, this.navLink];
  }

  querySelector(selector) {
    if (selector === "[data-sidebar]") return this.sidebar;
    if (selector === "[data-nav-backdrop]") return this.backdrop;
    return null;
  }

  querySelectorAll(selector) {
    if (selector === "[data-menu-toggle]") return [this.opener];
    if (selector === "[data-menu-close]") return [this.close];
    return [];
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }

  dispatch(type, event) {
    for (const listener of this.listeners.get(type) || []) listener(event);
  }
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function keyboardEvent(key, shiftKey = false) {
  return {
    key,
    shiftKey,
    defaultPrevented: false,
    preventDefault() {
      this.defaultPrevented = true;
    },
  };
}

const document = new FakeDocument();
const mediaListeners = [];
const viewport = {
  matches: true,
  addEventListener(type, listener) {
    if (type === "change") mediaListeners.push(listener);
  },
};
const window = {
  matchMedia() {
    return viewport;
  },
  addEventListener() {},
};

const source = fs.readFileSync("web/static/admin.js", "utf8");
vm.runInNewContext(source, { document, window, console, setTimeout, clearTimeout });

document.opener.dispatch("click");
assert(document.sidebar.classList.contains("open"), "menu toggle did not open the mobile drawer");
assert(document.body.classList.contains("navigation-open"), "opening the drawer did not lock body scrolling");
assert(document.opener.getAttribute("aria-expanded") === "true", "opener did not expose expanded state");
assert(document.activeElement === document.close, "opening the drawer did not move focus to its close control");

document.navLink.focus();
const forwardTab = keyboardEvent("Tab");
document.dispatch("keydown", forwardTab);
assert(forwardTab.defaultPrevented && document.activeElement === document.close, "forward Tab did not wrap inside the drawer");

document.close.focus();
const backwardTab = keyboardEvent("Tab", true);
document.dispatch("keydown", backwardTab);
assert(backwardTab.defaultPrevented && document.activeElement === document.navLink, "Shift+Tab did not wrap inside the drawer");

const escape = keyboardEvent("Escape");
document.dispatch("keydown", escape);
assert(escape.defaultPrevented, "Escape was not handled while the drawer was open");
assert(!document.sidebar.classList.contains("open"), "Escape did not close the drawer");
assert(!document.body.classList.contains("navigation-open"), "closing the drawer did not restore body scrolling");
assert(document.opener.getAttribute("aria-expanded") === "false", "opener did not expose collapsed state");
assert(document.activeElement === document.opener, "closing the drawer did not return focus to its opener");

document.opener.dispatch("click");
document.backdrop.dispatch("click");
assert(!document.sidebar.classList.contains("open"), "backdrop did not close the drawer");
assert(document.activeElement === document.opener, "backdrop close did not return focus to the opener");

document.opener.dispatch("click");
document.navLink.dispatch("click");
assert(!document.sidebar.classList.contains("open"), "selecting a navigation link did not close the drawer");
assert(!document.body.classList.contains("navigation-open"), "navigation did not release the body scroll lock");

document.opener.dispatch("click");
viewport.matches = false;
for (const listener of mediaListeners) listener({ matches: false });
assert(!document.sidebar.classList.contains("open"), "desktop resize did not reset the mobile drawer");
assert(!document.body.classList.contains("navigation-open"), "desktop resize left the body scroll lock active");

console.log("Responsive navigation interaction test passed.");
