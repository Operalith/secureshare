(() => {
  const MAX_FIELDS = 20;
  const MAX_SECRET_BYTES = 32768;

  function qs(selector, root = document) {
    return root.querySelector(selector);
  }

  function qsa(selector, root = document) {
    return Array.from(root.querySelectorAll(selector));
  }

  function toast(message) {
    const region = qs(".toast-region");
    if (!region) return;
    const item = document.createElement("div");
    item.className = "toast";
    item.textContent = message;
    region.appendChild(item);
    setTimeout(() => item.remove(), 3200);
  }

  function setButtonLoading(button, loading) {
    if (!button) return;
    if (loading) {
      button.dataset.originalText = button.textContent;
      button.textContent = button.dataset.loadingText || "Working...";
      button.disabled = true;
      return;
    }
    button.textContent = button.dataset.originalText || button.textContent;
    button.disabled = false;
  }

  function setupTheme() {
    qsa("[data-theme-toggle]").forEach((button) => {
      button.addEventListener("click", () => {
        const current = document.documentElement.dataset.theme;
        const next = current === "dark" ? "light" : "dark";
        document.documentElement.dataset.theme = next;
        toast(`${next === "dark" ? "Dark" : "Light"} mode enabled for this page.`);
      });
    });
  }

  function setupNavigation() {
    const sidebar = qs("[data-sidebar]");
    qsa("[data-menu-toggle]").forEach((button) => {
      button.addEventListener("click", () => sidebar?.classList.toggle("open"));
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") sidebar?.classList.remove("open");
    });
  }

  function setupSecretToggles(root = document) {
    qsa("[data-toggle-secret]", root).forEach((button) => {
      button.addEventListener("click", () => {
        const wrap = button.closest(".input-with-action");
        const input = wrap?.querySelector("[data-secret-input]");
        if (!input) return;
        const reveal = input.type === "password";
        input.type = reveal ? "text" : "password";
        button.textContent = reveal ? "Hide" : "Show";
      });
    });
  }

  function setupLogin() {
    const form = qs("[data-login-form]");
    if (!form) return;
    const error = qs("[data-form-error]", form);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (error) error.textContent = "";
      const submit = form.querySelector('button[type="submit"]');
      setButtonLoading(submit, true);
      const apiKey = String(new FormData(form).get("api_key") || "");
      try {
        const response = await fetch("/api/v1/auth/login", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ api_key: apiKey }),
        });
        if (!response.ok) {
          if (error) error.textContent = "The API key was not accepted.";
          return;
        }
        window.location.assign("/admin");
      } catch {
        if (error) error.textContent = "SecureShare could not be reached.";
      } finally {
        setButtonLoading(submit, false);
      }
    });
  }

  function setupCreateSecret() {
    const form = qs("#create-secret-form");
    if (!form) return;
    const statusLine = qs("#create-status");
    const resultPanel = qs("#created-result");
    const kvRows = qs("#kv-rows");
    let createdID = "";
    let createdPayload = null;

    function setStatus(message) {
      if (statusLine) statusLine.textContent = message || "";
    }

    function mode() {
      return qs("[data-secret-mode].active")?.dataset.secretMode || "structured";
    }

    function setMode(next) {
      qsa("[data-secret-mode]").forEach((button) => button.classList.toggle("active", button.dataset.secretMode === next));
      qsa("[data-mode-panel]").forEach((panel) => panel.classList.toggle("hidden", panel.dataset.modePanel !== next));
    }

    function rowTemplate() {
      const row = document.createElement("div");
      row.className = "secure-field-row";
      row.innerHTML = '<input name="kv_key" placeholder="Field name" autocomplete="off" aria-label="Field key"><span class="input-with-action"><input name="kv_value" type="password" placeholder="Value" autocomplete="off" aria-label="Field value" data-secret-input><button type="button" class="ghost compact" data-toggle-secret aria-label="Show value">Show</button></span><div class="row-actions"><button type="button" class="icon-button" data-move-row="up" aria-label="Move field up">↑</button><button type="button" class="icon-button" data-move-row="down" aria-label="Move field down">↓</button><button type="button" class="icon-button danger-lite" data-remove-row aria-label="Remove field">×</button></div>';
      setupSecretToggles(row);
      return row;
    }

    function structuredSecret() {
      const keys = qsa('input[name="kv_key"]', form);
      const values = qsa('input[name="kv_value"]', form);
      const seen = new Set();
      const secret = {};
      for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index].value.trim();
        if (!key) throw new Error("Every structured field needs a key.");
        const normalized = key.toLowerCase();
        if (seen.has(normalized)) throw new Error(`Duplicate key: ${key}`);
        seen.add(normalized);
        secret[key] = values[index].value;
      }
      return secret;
    }

    function plainSecret(data) {
      const raw = String(data.get("secret_plain") || "");
      if (!raw.trim()) throw new Error("Plain text secret content is required.");
      if (data.get("plain_format") === "json") return JSON.parse(raw);
      return raw;
    }

    function validateSize(secret) {
      const size = new TextEncoder().encode(JSON.stringify(secret)).length;
      if (size > MAX_SECRET_BYTES) throw new Error("Secret payload exceeds the 32 KB limit.");
    }

    function fillResult(response, payload) {
      createdID = response.id;
      createdPayload = payload;
      const expires = new Date(response.expires_at);
      qs("#created-id").textContent = response.id;
      qs("#created-expires").textContent = expires.toISOString();
      qs("#created-lifetime").textContent = selectedLifetimeLabel();
      qs("#created-password").textContent = payload.password ? "Yes" : "No";
      qs("#created-recipient").textContent = payload.recipient_reference || "Not provided";
      qs("#created-url").value = response.url;
      qs("#view-created-meta").href = `/admin/secrets/${response.id}`;
      qs("#revoke-created-url").disabled = false;
      resultPanel.classList.remove("hidden");
      resultPanel.scrollIntoView({ block: "start", behavior: "smooth" });
    }

    function selectedLifetimeLabel() {
      const selected = form.querySelector('input[name="expires_in_seconds"]:checked');
      return selected?.nextElementSibling?.textContent || "Custom";
    }

    qsa("[data-secret-mode]").forEach((button) => {
      button.addEventListener("click", () => setMode(button.dataset.secretMode));
    });

    qs("#add-kv-row")?.addEventListener("click", () => {
      if (qsa(".secure-field-row", kvRows).length >= MAX_FIELDS) {
        toast("Structured secrets are limited to 20 fields.");
        return;
      }
      kvRows.appendChild(rowTemplate());
    });

    kvRows?.addEventListener("click", (event) => {
      const row = event.target.closest(".secure-field-row");
      if (!row) return;
      if (event.target.closest("[data-remove-row]")) {
        if (qsa(".secure-field-row", kvRows).length === 1) {
          toast("At least one field is required.");
          return;
        }
        row.remove();
      }
      if (event.target.closest('[data-move-row="up"]') && row.previousElementSibling) {
        kvRows.insertBefore(row, row.previousElementSibling);
      }
      if (event.target.closest('[data-move-row="down"]') && row.nextElementSibling) {
        kvRows.insertBefore(row.nextElementSibling, row);
      }
    });

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = event.submitter || form.querySelector('button[type="submit"]');
      setStatus("");
      resultPanel?.classList.add("hidden");
      const data = new FormData(form);
      let secret;
      try {
        secret = mode() === "structured" ? structuredSecret() : plainSecret(data);
        validateSize(secret);
      } catch (error) {
        setStatus(error.message);
        return;
      }
      const password = String(data.get("password") || "");
      const payload = {
        title: String(data.get("title") || ""),
        description: String(data.get("description") || ""),
        recipient_reference: String(data.get("recipient_reference") || ""),
        secret,
        expires_in_seconds: Number(data.get("expires_in_seconds") || 86400),
        password: password ? password : null,
        max_failed_attempts: Number(data.get("max_failed_attempts") || 5),
      };
      setButtonLoading(submit, true);
      setStatus("Creating encrypted one-time link...");
      try {
        const response = await fetch("/api/v1/secret-links", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          setStatus(body.message || "The secure link could not be created.");
          return;
        }
        fillResult(body, payload);
        setStatus("Secure link created.");
        toast("One-time link created.");
      } finally {
        setButtonLoading(submit, false);
      }
    });

    qs("#copy-created-url")?.addEventListener("click", async () => {
      const input = qs("#created-url");
      await navigator.clipboard.writeText(input.value);
      toast("One-time URL copied.");
    });

    qs("#revoke-created-url")?.addEventListener("click", async () => {
      if (!createdID) return;
      const ok = await confirmAction("Revoke this link?", "Recipients will no longer be able to reveal this secret.");
      if (!ok) return;
      const response = await fetch(`/api/v1/secret-links/${createdID}/revoke`, { method: "POST", credentials: "same-origin" });
      if (response.ok) {
        qs("#revoke-created-url").disabled = true;
        toast("Link revoked.");
      } else {
        toast("The link was already unavailable.");
      }
    });

    qs("#create-another")?.addEventListener("click", () => {
      form.reset();
      createdID = "";
      createdPayload = null;
      resultPanel?.classList.add("hidden");
      setMode("structured");
      setStatus("");
      window.scrollTo({ top: 0, behavior: "smooth" });
    });

    form.addEventListener("input", () => {
      const password = String(new FormData(form).get("password") || "");
      const summary = qs("#password-summary");
      if (summary) summary.textContent = password ? "Password protection is enabled for this link." : "Password protection is optional.";
      if (createdPayload) createdPayload = null;
    });
  }

  async function confirmAction(title, message) {
    const dialog = qs("[data-confirm-dialog]");
    if (!dialog || typeof dialog.showModal !== "function") return window.confirm(message);
    qs("[data-confirm-title]", dialog).textContent = title;
    qs("[data-confirm-message]", dialog).textContent = message;
    dialog.showModal();
    return new Promise((resolve) => {
      dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true });
    });
  }

  function setupRevokeButtons() {
    document.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-revoke-id]");
      if (!button) return;
      const id = button.getAttribute("data-revoke-id");
      const ok = await confirmAction("Revoke this link?", "Recipients will receive the generic unavailable message.");
      if (!ok) return;
      button.disabled = true;
      const response = await fetch(`/api/v1/secret-links/${id}/revoke`, { method: "POST", credentials: "same-origin" });
      if (response.ok) {
        button.textContent = "Revoked";
        toast("Link revoked.");
      } else {
        button.textContent = "Unavailable";
        toast("The link was already unavailable.");
      }
    });
  }

  setupTheme();
  setupNavigation();
  setupSecretToggles();
  setupLogin();
  setupCreateSecret();
  setupRevokeButtons();
})();
