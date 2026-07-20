(() => {
  const MAX_FIELDS = 50;
  const MAX_SECRET_BYTES = 32768;

  function qs(selector, root = document) {
    return root.querySelector(selector);
  }

  function qsa(selector, root = document) {
    return Array.from(root.querySelectorAll(selector));
  }

  function csrfHeaders(extra = {}) {
    const token = qs('meta[name="csrf-token"]')?.getAttribute("content") || "";
    return token ? { ...extra, "X-CSRF-Token": token } : extra;
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
      const data = new FormData(form);
      const login = String(data.get("login") || "");
      const password = String(data.get("password") || "");
      try {
        const response = await fetch("/api/v1/auth/login", {
          method: "POST",
          credentials: "same-origin",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ login, password }),
        });
        if (!response.ok) {
          if (error) error.textContent = "The username, email, or password was not accepted.";
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
      row.innerHTML = '<input name="kv_key" placeholder="field_name" list="field-presets" autocomplete="off" aria-label="Field key"><span class="input-with-action"><input name="kv_value" type="password" placeholder="Value" autocomplete="off" aria-label="Field value" data-secret-input><button type="button" class="ghost compact" data-toggle-secret aria-label="Show value">Show</button></span><label class="checkbox-line compact-check"><input type="checkbox" name="kv_sensitive" checked> Sensitive</label><label class="checkbox-line compact-check"><input type="checkbox" name="kv_multiline"> Multiline</label><div class="row-actions"><button type="button" class="icon-button" data-move-row="up" aria-label="Move field up">↑</button><button type="button" class="icon-button" data-move-row="down" aria-label="Move field down">↓</button><button type="button" class="icon-button danger-lite" data-remove-row aria-label="Remove field">×</button></div>';
      setupSecretToggles(row);
      return row;
    }

    function structuredPayload() {
      const keys = qsa('input[name="kv_key"]', form);
      const values = qsa('input[name="kv_value"]', form);
      const sensitive = qsa('input[name="kv_sensitive"]', form);
      const multiline = qsa('input[name="kv_multiline"]', form);
      const seen = new Set();
      const fields = [];
      for (let index = 0; index < keys.length; index += 1) {
        const key = keys[index].value.trim();
        if (!key) throw new Error("Every structured field needs a key.");
        if (!/^[A-Za-z0-9_.-]+$/.test(key)) throw new Error(`Invalid field name: ${key}`);
        const normalized = key.toLowerCase();
        if (seen.has(normalized)) throw new Error(`Duplicate key: ${key}`);
        seen.add(normalized);
        fields.push({
          name: key,
          label: labelForField(key),
          value: values[index].value,
          sensitive: Boolean(sensitive[index]?.checked),
          multiline: Boolean(multiline[index]?.checked),
        });
      }
      return { type: "structured", fields };
    }

    function labelForField(name) {
      return name
        .replace(/[_.-]+/g, " ")
        .replace(/\b\w/g, (value) => value.toUpperCase());
    }

    function plainPayload(data) {
      const raw = String(data.get("secret_plain") || "");
      if (!raw.trim()) throw new Error("Plain text secret content is required.");
      if (data.get("plain_format") === "json") return { type: "json", value: JSON.parse(raw) };
      return { type: "text", text: raw };
    }

    function validateSize(payload) {
      const size = new TextEncoder().encode(JSON.stringify(payload)).length;
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
      let payloadModel;
      try {
        payloadModel = mode() === "structured" ? structuredPayload() : plainPayload(data);
        validateSize(payloadModel);
      } catch (error) {
        setStatus(error.message);
        return;
      }
      const password = String(data.get("password") || "");
      const payload = {
        title: String(data.get("title") || ""),
        description: String(data.get("description") || ""),
        recipient_reference: String(data.get("recipient_reference") || ""),
        payload: payloadModel,
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
          headers: csrfHeaders({ "Content-Type": "application/json" }),
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
      const response = await fetch(`/api/v1/secret-links/${createdID}/revoke`, { method: "POST", credentials: "same-origin", headers: csrfHeaders() });
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
      const response = await fetch(`/api/v1/secret-links/${id}/revoke`, { method: "POST", credentials: "same-origin", headers: csrfHeaders() });
      if (response.ok) {
        button.textContent = "Revoked";
        toast("Link revoked.");
      } else {
        button.textContent = "Unavailable";
        toast("The link was already unavailable.");
      }
    });
  }

  function setupUserManagement() {
    const createForm = qs("[data-user-create]");
    createForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = event.submitter || createForm.querySelector('button[type="submit"]');
      const error = qs("[data-form-error]", createForm);
      if (error) error.textContent = "";
      const data = new FormData(createForm);
      const payload = {
        username: String(data.get("username") || ""),
        email: String(data.get("email") || ""),
        password: String(data.get("password") || ""),
        role: String(data.get("role") || "developer"),
        status: String(data.get("status") || "active"),
        force_password_change: data.get("force_password_change") === "on",
      };
      setButtonLoading(submit, true);
      try {
        const response = await fetch("/api/v1/users", {
          method: "POST",
          credentials: "same-origin",
          headers: csrfHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload),
        });
        if (!response.ok) {
          if (error) error.textContent = "User could not be created.";
          return;
        }
        const user = await response.json();
        toast("User created.");
        window.location.assign(`/admin/users/${user.id}`);
      } finally {
        setButtonLoading(submit, false);
      }
    });

    const updateForm = qs("[data-user-update]");
    updateForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const id = updateForm.dataset.userId;
      const data = new FormData(updateForm);
      const response = await fetch(`/api/v1/users/${id}`, {
        method: "PATCH",
        credentials: "same-origin",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          username: String(data.get("username") || ""),
          email: String(data.get("email") || ""),
          role: String(data.get("role") || "developer"),
          status: String(data.get("status") || "active"),
          force_password_change: data.get("force_password_change") === "on",
        }),
      });
      toast(response.ok ? "User updated." : "User could not be updated.");
    });

    const resetForm = qs("[data-user-reset-password]");
    resetForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const id = resetForm.dataset.userId;
      const data = new FormData(resetForm);
      const response = await fetch(`/api/v1/users/${id}/reset-password`, {
        method: "POST",
        credentials: "same-origin",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          password: String(data.get("password") || ""),
          force_password_change: data.get("force_password_change") === "on",
        }),
      });
      if (response.ok) resetForm.reset();
      toast(response.ok ? "Password reset." : "Password could not be reset.");
    });

    document.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-user-action]");
      if (!button) return;
      const id = button.dataset.userId;
      const action = button.dataset.userAction;
      const ok = await confirmAction(`${action === "disable" ? "Disable" : "Enable"} this user?`, "User access changes take effect immediately.");
      if (!ok) return;
      button.disabled = true;
      const response = await fetch(`/api/v1/users/${id}/${action}`, {
        method: "POST",
        credentials: "same-origin",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
        body: "{}",
      });
      toast(response.ok ? "User updated." : "User update failed.");
      if (response.ok) window.location.reload();
    });
  }

  function setupAccount() {
    const form = qs("[data-change-password]");
    form?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const error = qs("[data-form-error]", form);
      if (error) error.textContent = "";
      const submit = event.submitter || form.querySelector('button[type="submit"]');
      const data = new FormData(form);
      setButtonLoading(submit, true);
      try {
        const response = await fetch("/api/v1/me/password", {
          method: "POST",
          credentials: "same-origin",
          headers: csrfHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({
            current_password: String(data.get("current_password") || ""),
            new_password: String(data.get("new_password") || ""),
          }),
        });
        if (!response.ok) {
          if (error) error.textContent = "Password could not be changed.";
          return;
        }
        toast("Password changed. Your session was rotated.");
        form.reset();
      } finally {
        setButtonLoading(submit, false);
      }
    });

    qs("[data-revoke-other-sessions]")?.addEventListener("click", async () => {
      const ok = await confirmAction("Revoke other sessions?", "Other browser sessions for this account will be invalidated.");
      if (!ok) return;
      const response = await fetch("/api/v1/me/sessions/revoke-other", {
        method: "POST",
        credentials: "same-origin",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
        body: "{}",
      });
      toast(response.ok ? "Other sessions revoked." : "Session revocation failed.");
      if (response.ok) window.location.reload();
    });
  }

  setupTheme();
  setupNavigation();
  setupSecretToggles();
  setupLogin();
  setupCreateSecret();
  setupRevokeButtons();
  setupUserManagement();
  setupAccount();
})();
