(function (root, factory) {
  const formatter = factory();
  if (typeof module === "object" && module.exports) module.exports = formatter;
  root.SecureShareTime = formatter;
  if (!root.document) return;
  if (root.document.readyState === "loading") {
    root.document.addEventListener("DOMContentLoaded", () => formatter.apply(root.document), { once: true });
  } else {
    formatter.apply(root.document);
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  const DEFAULT_OPTIONS = {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short",
  };

  function format(value, options = {}) {
    if (value === null || value === undefined || String(value).trim() === "") {
      return options.emptyLabel || "Never";
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return options.invalidLabel || "Invalid date";
    const intlOptions = { ...DEFAULT_OPTIONS };
    if (options.timeZone) intlOptions.timeZone = options.timeZone;
    try {
      return new Intl.DateTimeFormat(options.locale, intlOptions).format(parsed);
    } catch {
      return parsed.toISOString();
    }
  }

  function render(element, value, options = {}) {
    if (!element) return;
    const raw = value === null || value === undefined ? "" : String(value).trim();
    if (raw) {
      element.setAttribute("data-local-time", raw);
      element.setAttribute("title", raw);
      if (element.tagName === "TIME") element.setAttribute("datetime", raw);
    }
    element.textContent = format(raw, options);
  }

  function apply(scope) {
    if (!scope || typeof scope.querySelectorAll !== "function") return;
    Array.from(scope.querySelectorAll("[data-local-time]")).forEach((element) => {
      render(element, element.getAttribute("data-local-time"), {
        emptyLabel: element.getAttribute("data-empty-label") || undefined,
        invalidLabel: element.getAttribute("data-invalid-label") || undefined,
      });
    });
  }

  return { format, render, apply };
});
