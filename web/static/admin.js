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

  function renderLocalTime(element, value, emptyLabel = "Never") {
    if (!element) return;
    if (window.SecureShareTime?.render) {
      window.SecureShareTime.render(element, value, { emptyLabel });
      return;
    }
    const raw = value === null || value === undefined ? "" : String(value);
    element.textContent = raw || emptyLabel;
    if (raw) element.setAttribute("title", raw);
  }

  function setupTheme() {
    qsa("[data-theme-toggle]").forEach((button) => {
      const themes = ["system", "light", "dark"];
      const label = (theme) => theme.charAt(0).toUpperCase() + theme.slice(1);
      button.addEventListener("click", async () => {
        const current = themes.includes(document.documentElement.dataset.theme) ? document.documentElement.dataset.theme : "system";
        const next = themes[(themes.indexOf(current) + 1) % themes.length];
        let savedTheme = "";
        setButtonLoading(button, true);
        try {
          const response = await fetch("/api/v1/me/preferences/theme", {
            method: "PUT",
            credentials: "same-origin",
            headers: csrfHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({ theme: next }),
          });
          const body = await response.json().catch(() => ({}));
          if (!response.ok) {
            toast(body.message || "Theme preference could not be saved.");
            return;
          }
          savedTheme = body.theme;
        } catch {
          toast("Theme preference could not be saved. Check your connection and try again.");
        } finally {
          setButtonLoading(button, false);
        }
        if (savedTheme) {
          document.documentElement.dataset.theme = savedTheme;
          button.dataset.themePreference = savedTheme;
          button.textContent = `Theme: ${label(savedTheme)}`;
          button.dataset.originalText = button.textContent;
          button.setAttribute("aria-label", `Color theme: ${label(savedTheme)}`);
          toast(`${label(savedTheme)} theme saved to your account.`);
        }
      });
    });
  }

  function setupNavigation() {
    const sidebar = qs("[data-sidebar]");
    const backdrop = qs("[data-nav-backdrop]");
    const openers = qsa("[data-menu-toggle]");
    const closeButtons = qsa("[data-menu-close]");
    const mobileViewport = window.matchMedia("(max-width: 820px)");
    let lastOpener = null;

    if (!sidebar) return;

    const focusableElements = () => qsa('a[href], button:not([disabled]), summary, input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])', sidebar)
      .filter((element) => !element.hasAttribute("hidden"));

    const setOpen = (open, returnFocus = true) => {
      const shouldOpen = open && mobileViewport.matches;
      sidebar.classList.toggle("open", shouldOpen);
      document.body.classList.toggle("navigation-open", shouldOpen);
      openers.forEach((button) => button.setAttribute("aria-expanded", String(shouldOpen)));
      if (shouldOpen) {
        (qs("[data-menu-close]", sidebar) || focusableElements()[0])?.focus();
      } else if (returnFocus && lastOpener) {
        lastOpener.focus();
      }
    };

    openers.forEach((button) => {
      button.addEventListener("click", () => {
        lastOpener = button;
        setOpen(!sidebar.classList.contains("open"));
      });
    });
    closeButtons.forEach((button) => button.addEventListener("click", () => setOpen(false)));
    backdrop?.addEventListener("click", () => setOpen(false));
    qsa("a[href]", sidebar).forEach((link) => link.addEventListener("click", () => setOpen(false, false)));

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        qsa("[data-user-menu][open]").forEach((menu) => menu.removeAttribute("open"));
        if (sidebar.classList.contains("open")) {
          event.preventDefault();
          setOpen(false);
        }
        return;
      }
      if (event.key !== "Tab" || !mobileViewport.matches || !sidebar.classList.contains("open")) return;
      const focusable = focusableElements();
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });

    const resetForViewport = () => {
      if (!mobileViewport.matches) setOpen(false, false);
    };
    if (typeof mobileViewport.addEventListener === "function") {
      mobileViewport.addEventListener("change", resetForViewport);
    } else {
      mobileViewport.addListener(resetForViewport);
    }
    window.addEventListener("pagehide", () => setOpen(false, false));
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

    function deliveryMode() {
      return qs("[data-delivery-mode].active")?.dataset.deliveryMode || "link";
    }

    function setDeliveryMode(next) {
      qsa("[data-delivery-mode]").forEach((button) => button.classList.toggle("active", button.dataset.deliveryMode === next));
      qsa("[data-delivery-panel]").forEach((panel) => panel.classList.toggle("hidden", panel.dataset.deliveryPanel !== next));
    }

    const fieldPresets = {
      username: { sensitive: false },
      password: { sensitive: true },
      api_key: { sensitive: true },
      client_id: { sensitive: false },
      client_secret: { sensitive: true },
      access_token: { sensitive: true },
      refresh_token: { sensitive: true },
      host: { sensitive: false },
      port: { sensitive: false },
      database: { sensitive: false },
      connection_string: { sensitive: true, multiline: true },
      private_key: { sensitive: true, multiline: true },
      certificate: { sensitive: false, multiline: true },
    };

    const structuredError = qs("[data-structured-error]", form);
    const fieldPicker = qs("#field-preset", form);

    function rowTemplate(preset = {}) {
      const row = document.createElement("div");
      row.className = "secure-field-row";
      row.innerHTML = '<input name="kv_key" placeholder="field_name" autocomplete="off" aria-label="Field key"><span class="input-with-action"><input name="kv_value" type="password" placeholder="Value" autocomplete="off" aria-label="Field value" data-secret-input><button type="button" class="ghost compact" data-toggle-secret aria-label="Show value">Show</button></span><label class="checkbox-line compact-check"><input type="checkbox" name="kv_sensitive"> Sensitive</label><label class="checkbox-line compact-check"><input type="checkbox" name="kv_multiline"> Multiline</label><div class="row-actions"><button type="button" class="icon-button" data-move-row="up" aria-label="Move field up">↑</button><button type="button" class="icon-button" data-move-row="down" aria-label="Move field down">↓</button><button type="button" class="icon-button danger-lite" data-remove-row aria-label="Remove field">×</button></div>';
      qs('input[name="kv_key"]', row).value = preset.name || "";
      qs('input[name="kv_sensitive"]', row).checked = preset.sensitive !== false;
      qs('input[name="kv_multiline"]', row).checked = Boolean(preset.multiline);
      setupSecretToggles(row);
      return row;
    }

    function currentFieldNames() {
      return new Set(qsa('input[name="kv_key"]', form).map((input) => input.value.trim().toLowerCase()).filter(Boolean));
    }

    function addStructuredField(name = "") {
      if (qsa(".secure-field-row", kvRows).length >= MAX_FIELDS) {
        if (structuredError) structuredError.textContent = `Structured secrets are limited to ${MAX_FIELDS} fields.`;
        return false;
      }
      const normalized = name.trim().toLowerCase();
      if (normalized && currentFieldNames().has(normalized)) {
        if (structuredError) structuredError.textContent = `${labelForField(name)} has already been added.`;
        return false;
      }
      const preset = normalized ? { name: normalized, ...(fieldPresets[normalized] || {}) } : {};
      const row = rowTemplate(preset);
      kvRows.appendChild(row);
      if (structuredError) structuredError.textContent = "";
      qs(normalized ? 'input[name="kv_value"]' : 'input[name="kv_key"]', row)?.focus();
      return true;
    }

    function structuredPayload() {
      const keys = qsa('input[name="kv_key"]', form);
      const values = qsa('input[name="kv_value"]', form);
      const sensitive = qsa('input[name="kv_sensitive"]', form);
      const multiline = qsa('input[name="kv_multiline"]', form);
      const seen = new Set();
      const fields = [];
      if (keys.length === 0) throw new Error("Add at least one structured field.");
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
      const credentialLabels = {
        client_id: "OAuth Client ID",
        client_secret: "OAuth Client Secret",
      };
      const normalized = name.toLowerCase();
      if (credentialLabels[normalized]) return credentialLabels[normalized];
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
      qs("#created-id").textContent = response.id;
      renderLocalTime(qs("#created-expires"), response.expires_at, "Invalid date");
      qs("#created-lifetime").textContent = selectedLifetimeLabel();
      qs("#created-password").textContent = payload.password ? "Yes" : "No";
      qs("#created-recipient").textContent = payload.recipient_reference || "Not provided";
      qs("#created-url").value = response.url;
      const email = response.delivery?.email || { requested: false, status: "not_requested" };
      qs("#created-email-status").textContent = email.requested ? `${email.status}${email.to ? ` to ${email.to}` : ""}` : "Not requested";
      renderLocalTime(qs("#created-email-sent"), email.sent_at, "Not sent");
      qs("#email-retry-panel")?.classList.toggle("hidden", !email.requested);
      qs("#retry-email-to").value = payload.delivery?.email?.to || "";
      qs("#retry-email-name").value = payload.delivery?.email?.recipient_name || "";
      qs("#retry-email-subject").value = payload.delivery?.email?.subject || "";
      qs("#retry-email-message").value = payload.delivery?.email?.message || "";
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

    qsa("[data-delivery-mode]").forEach((button) => {
      button.addEventListener("click", () => setDeliveryMode(button.dataset.deliveryMode));
    });

    qs("#add-kv-row")?.addEventListener("click", () => {
      addStructuredField();
    });

    fieldPicker?.addEventListener("change", () => {
      const selected = fieldPicker.value;
      fieldPicker.value = "";
      if (!selected) return;
      addStructuredField(selected === "__custom__" ? "" : selected);
    });

    kvRows?.addEventListener("click", (event) => {
      const row = event.target.closest(".secure-field-row");
      if (!row) return;
      if (event.target.closest("[data-remove-row]")) {
        row.remove();
        if (structuredError) structuredError.textContent = "";
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
      const sendEmail = deliveryMode() === "email";
      if (sendEmail) {
        payload.delivery = {
          email: {
            send: true,
            to: String(data.get("delivery_to") || ""),
            recipient_name: String(data.get("delivery_recipient_name") || ""),
            use_default_template: data.get("delivery_use_default_template") === "on",
            subject: String(data.get("delivery_subject") || ""),
            message: String(data.get("delivery_message") || ""),
          },
        };
      }
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
      setDeliveryMode("link");
      setStatus("");
      kvRows.replaceChildren();
      if (fieldPicker) fieldPicker.value = "";
      if (structuredError) structuredError.textContent = "";
      window.scrollTo({ top: 0, behavior: "smooth" });
    });

    qs("[data-delivery-preview]")?.addEventListener("click", async () => {
      const data = new FormData(form);
      const status = qs("[data-delivery-status]");
      const response = await fetch("/api/v1/settings/email/template-preview", {
        method: "POST",
        credentials: "same-origin",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          subject: String(data.get("delivery_subject") || ""),
          message: String(data.get("delivery_message") || ""),
        }),
      });
      const body = await response.json().catch(() => ({}));
      if (status) status.textContent = response.ok ? `Preview ready: ${body.subject || "default subject"}.` : body.message || "Preview failed.";
    });

    qs("#retry-email")?.addEventListener("click", async () => {
      const url = qs("#created-url")?.value || "";
      const token = url.includes("#") ? url.split("#").pop() : "";
      if (!token) {
        toast("Retry is unavailable after the raw token is gone.");
        return;
      }
      const response = await fetch("/api/v1/secret-links/send-email", {
        method: "POST",
        credentials: "same-origin",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify({
          token,
          to: qs("#retry-email-to")?.value || "",
          recipient_name: qs("#retry-email-name")?.value || "",
          subject: qs("#retry-email-subject")?.value || "",
          message: qs("#retry-email-message")?.value || "",
        }),
      });
      const body = await response.json().catch(() => ({}));
      toast(response.ok && body.email?.status === "sent" ? "Email retry sent." : "Email retry failed.");
    });

    form.addEventListener("input", () => {
      const password = String(new FormData(form).get("password") || "");
      const summary = qs("#password-summary");
      if (summary) summary.textContent = password ? "Password protection is enabled for this link." : "Password protection is optional.";
      if (createdPayload) createdPayload = null;
    });
  }

  function setupPasswordProtection() {
    const form = qs("[data-password-protection-form]");
    if (!form) return;
    const secretID = form.dataset.secretId;
    const error = qs("[data-protection-error]", form);
    const save = qs("[data-protection-save]", form);
    const remove = qs("[data-protection-remove]", form);

    function updateProtectionUI(protectedNow) {
      form.dataset.passwordProtected = String(protectedNow);
      const status = qs("[data-protection-status]");
      const badge = qs("[data-protection-badge]");
      const guidance = qs("[data-protection-guidance]");
      if (status) status.textContent = protectedNow ? "Yes" : "No";
      if (badge) badge.textContent = protectedNow ? "Protected" : "Not protected";
      if (guidance) guidance.textContent = protectedNow
        ? "The current link password cannot be recovered. If it was lost, you can replace it with a new password."
        : "This active link does not currently require a separate password.";
      if (save) save.textContent = protectedNow ? "Replace password" : "Set password";
      if (remove) remove.classList.toggle("hidden", !protectedNow);
    }

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      if (error) error.textContent = "";
      const password = String(new FormData(form).get("password") || "");
      const wasProtected = form.dataset.passwordProtected === "true";
      let updated = false;
      setButtonLoading(save, true);
      try {
        const response = await fetch(`/api/v1/secret-links/${secretID}/password`, {
          method: "PUT",
          credentials: "same-origin",
          headers: csrfHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ password }),
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          if (error) error.textContent = body.message || "Link password could not be updated.";
          return;
        }
        form.reset();
        updated = true;
      } catch {
        if (error) error.textContent = "Link password could not be updated. Check your connection and try again.";
      } finally {
        setButtonLoading(save, false);
      }
      if (updated) {
        updateProtectionUI(true);
        toast(wasProtected ? "Link password replaced." : "Link password set.");
      }
    });

    remove?.addEventListener("click", async () => {
      const ok = await confirmAction("Remove link password?", "The same one-time URL will remain active without password protection.");
      if (!ok) return;
      if (error) error.textContent = "";
      setButtonLoading(remove, true);
      let updated = false;
      try {
        const response = await fetch(`/api/v1/secret-links/${secretID}/password`, {
          method: "DELETE",
          credentials: "same-origin",
          headers: csrfHeaders(),
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          if (error) error.textContent = body.message || "Link password could not be removed.";
          return;
        }
        form.reset();
        updated = true;
      } catch {
        if (error) error.textContent = "Link password could not be removed. Check your connection and try again.";
      } finally {
        setButtonLoading(remove, false);
      }
      if (updated) {
        updateProtectionUI(false);
        toast("Link password removed.");
      }
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

  function setupAPIClients() {
    const resultPanel = qs("[data-api-client-result]");

    function selectedScopes(form) {
      return qsa('input[name="scopes"]:checked', form).map((input) => input.value);
    }

    function expirationValue(raw) {
      const value = String(raw || "").trim();
      if (!value) return "";
      const parsed = new Date(value);
      if (Number.isNaN(parsed.getTime())) throw new Error("Expiration must be a valid date and time.");
      return parsed.toISOString();
    }

    function showCredentials(client) {
      const idInput = qs("#api-client-id");
      const secretInput = qs("#api-client-secret");
      if (idInput) idInput.value = client.client_id || "";
      if (secretInput) secretInput.value = client.client_secret || "";
      const viewLink = qs("#view-api-client");
      if (viewLink && client.id) viewLink.href = `/admin/api-clients/${client.id}`;
      resultPanel?.classList.remove("hidden");
      resultPanel?.scrollIntoView({ block: "start", behavior: "smooth" });
    }

    const createForm = qs("[data-api-client-create]");
    createForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = event.submitter || createForm.querySelector('button[type="submit"]');
      const error = qs("[data-form-error]", createForm);
      if (error) error.textContent = "";
      resultPanel?.classList.add("hidden");
      const data = new FormData(createForm);
      let expiresAt = "";
      try {
        expiresAt = expirationValue(data.get("expires_at"));
      } catch (err) {
        if (error) error.textContent = err.message;
        return;
      }
      const payload = {
        name: String(data.get("name") || ""),
        scopes: selectedScopes(createForm),
        expires_at: expiresAt,
      };
      setButtonLoading(submit, true);
      try {
        const response = await fetch("/api/v1/api-clients", {
          method: "POST",
          credentials: "same-origin",
          headers: csrfHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify(payload),
        });
        const body = await response.json().catch(() => ({}));
        if (!response.ok) {
          if (error) error.textContent = body.message || "API client could not be created.";
          return;
        }
        showCredentials(body);
        toast("API client created.");
        createForm.reset();
      } finally {
        setButtonLoading(submit, false);
      }
    });

    document.addEventListener("click", async (event) => {
      const copyButton = event.target.closest("[data-copy-target]");
      if (!copyButton) return;
      const input = qs(copyButton.dataset.copyTarget);
      if (!input) return;
      await navigator.clipboard.writeText(input.value);
      toast("Copied.");
    });

    document.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-api-client-action]");
      if (!button) return;
      const id = button.dataset.apiClientId;
      const action = button.dataset.apiClientAction;
      const labels = {
        disable: ["Disable this API client?", "Existing integrations using this client will stop authenticating."],
        enable: ["Enable this API client?", "Integrations can authenticate again if the client has not expired."],
        revoke: ["Revoke this API client?", "Revoked clients cannot authenticate and the secret cannot be recovered."],
        "rotate-secret": ["Rotate this client secret?", "The previous client secret will stop authenticating immediately."],
      };
      const [title, message] = labels[action] || ["Confirm action?", "This change takes effect immediately."];
      const ok = await confirmAction(title, message);
      if (!ok) return;
      button.disabled = true;
      resultPanel?.classList.add("hidden");
      const response = await fetch(`/api/v1/api-clients/${id}/${action}`, {
        method: "POST",
        credentials: "same-origin",
        headers: csrfHeaders(),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        toast("API client update failed.");
        button.disabled = false;
        return;
      }
      if (action === "rotate-secret") {
        showCredentials(body);
        toast("Client secret rotated.");
        button.disabled = false;
        return;
      }
      toast("API client updated.");
      window.location.reload();
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

  function setupEmailSettings() {
    const settingsForm = qs("[data-email-settings]");
    const testForm = qs("[data-email-test]");
    if (!settingsForm && !testForm) return;

    function settingsPayload(form) {
      const data = new FormData(form);
      return {
        enabled: data.get("enabled") === "on",
        smtp_host: String(data.get("smtp_host") || ""),
        smtp_port: Number(data.get("smtp_port") || 0),
        encryption_mode: String(data.get("encryption_mode") || "starttls"),
        smtp_username: String(data.get("smtp_username") || ""),
        smtp_password: String(data.get("smtp_password") || ""),
        clear_smtp_password: data.get("clear_smtp_password") === "on",
        from_name: String(data.get("from_name") || ""),
        from_email: String(data.get("from_email") || ""),
        reply_to_email: String(data.get("reply_to_email") || ""),
        connection_timeout_seconds: Number(data.get("connection_timeout_seconds") || 5),
        send_timeout_seconds: Number(data.get("send_timeout_seconds") || 10),
        default_subject: String(data.get("default_subject") || ""),
        default_message: String(data.get("default_message") || ""),
        footer_text: String(data.get("footer_text") || ""),
      };
    }

    function clearSMTPFieldErrors() {
      if (!settingsForm) return;
      qsa("[aria-invalid]", settingsForm).forEach((field) => field.removeAttribute("aria-invalid"));
    }

    function smtpErrorMessage(body, fallback) {
      const fields = body?.fields && typeof body.fields === "object" ? body.fields : {};
      const messages = Object.entries(fields).map(([name, message]) => {
        settingsForm?.querySelector(`[name="${name}"]`)?.setAttribute("aria-invalid", "true");
        return String(message);
      });
      return [body?.message || fallback, ...messages].filter(Boolean).join(" ");
    }

    async function saveCurrentSettings(announce) {
      if (!settingsForm) return { ok: true, body: {} };
      const error = qs("[data-form-error]", settingsForm);
      const status = qs("[data-email-status]", settingsForm);
      if (error) error.textContent = "";
      clearSMTPFieldErrors();
      const response = await fetch("/api/v1/settings/email", {
        method: "PUT",
        credentials: "same-origin",
        headers: csrfHeaders({ "Content-Type": "application/json" }),
        body: JSON.stringify(settingsPayload(settingsForm)),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (error) error.textContent = smtpErrorMessage(body, "Email settings could not be saved.");
        return { ok: false, body };
      }
      settingsForm.querySelector('input[name="smtp_password"]').value = "";
      settingsForm.querySelector('input[name="clear_smtp_password"]').checked = false;
      if (announce) {
        if (status) status.textContent = body.password_configured ? "Settings saved. Password configured." : "Settings saved. No password is stored.";
        toast("Email settings saved.");
      }
      return { ok: true, body };
    }

    settingsForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = event.submitter || settingsForm.querySelector('button[type="submit"]');
      const error = qs("[data-form-error]", settingsForm);
      const status = qs("[data-email-status]", settingsForm);
      if (error) error.textContent = "";
      if (status) status.textContent = "";
      setButtonLoading(submit, true);
      try {
        await saveCurrentSettings(true);
      } finally {
        setButtonLoading(submit, false);
      }
    });

    document.addEventListener("click", async (event) => {
      const previewButton = event.target.closest("[data-email-preview]");
      if (previewButton && settingsForm) {
        const status = qs("[data-email-status]", settingsForm);
        const panel = qs("[data-email-preview-panel]");
        const text = qs("[data-email-preview-text]");
        const htmlFrame = qs("[data-email-preview-html]");
        setButtonLoading(previewButton, true);
        try {
          const payload = settingsPayload(settingsForm);
          const response = await fetch("/api/v1/settings/email/template-preview", {
            method: "POST",
            credentials: "same-origin",
            headers: csrfHeaders({ "Content-Type": "application/json" }),
            body: JSON.stringify({
              subject: payload.default_subject,
              message: payload.default_message,
              footer_text: payload.footer_text,
            }),
          });
          const body = await response.json().catch(() => ({}));
          if (!response.ok) {
            if (status) status.textContent = body.message || "Template preview could not be generated.";
            return;
          }
          if (text) text.textContent = `Subject: ${body.subject}\n\n${body.text}`;
          if (htmlFrame) htmlFrame.setAttribute("srcdoc", body.html || "");
          panel?.classList.remove("hidden");
          panel?.scrollIntoView({ block: "nearest", behavior: "smooth" });
        } finally {
          setButtonLoading(previewButton, false);
        }
        return;
      }

      const button = event.target.closest("[data-email-action]");
      if (!button) return;
      const action = button.dataset.emailAction;
      const status = qs("[data-email-status]", settingsForm);
      setButtonLoading(button, true);
      try {
        if (action !== "disable") {
          const saved = await saveCurrentSettings(false);
          if (!saved.ok) {
            if (status) status.textContent = "Fix the highlighted SMTP settings before testing.";
            return;
          }
        }
        const response = await fetch(`/api/v1/settings/email/${action}`, {
          method: "POST",
          credentials: "same-origin",
          headers: csrfHeaders({ "Content-Type": "application/json" }),
          body: "{}",
        });
        const body = await response.json().catch(() => ({}));
        if (status) {
          if (action === "test-connection") status.textContent = body.ok ? `Connection test succeeded in ${body.duration_ms} ms.` : smtpErrorMessage(body, "Connection test failed.");
          if (action === "enable") status.textContent = response.ok ? "SMTP delivery enabled." : smtpErrorMessage(body, "SMTP delivery could not be enabled.");
          if (action === "disable") status.textContent = response.ok ? "SMTP delivery disabled." : smtpErrorMessage(body, "SMTP delivery could not be disabled.");
        }
        toast(response.ok && body.ok !== false ? "Email settings action completed." : "Email settings action finished with warnings.");
      } finally {
        setButtonLoading(button, false);
      }
    });

    testForm?.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submit = event.submitter || testForm.querySelector('button[type="submit"]');
      const status = qs("[data-email-test-status]", testForm);
      const data = new FormData(testForm);
      setButtonLoading(submit, true);
      try {
        const saved = await saveCurrentSettings(false);
        if (!saved.ok) {
          if (status) status.textContent = "Fix the highlighted SMTP settings before sending a test email.";
          return;
        }
        const response = await fetch("/api/v1/settings/email/send-test", {
          method: "POST",
          credentials: "same-origin",
          headers: csrfHeaders({ "Content-Type": "application/json" }),
          body: JSON.stringify({ to: String(data.get("to") || "") }),
        });
        const body = await response.json().catch(() => ({}));
        if (status) status.textContent = body.ok ? `Test email sent in ${body.duration_ms} ms.` : smtpErrorMessage(body, "Test email failed.");
      } finally {
        setButtonLoading(submit, false);
      }
    });
  }

  setupTheme();
  setupNavigation();
  setupSecretToggles();
  setupLogin();
  setupCreateSecret();
  setupPasswordProtection();
  setupRevokeButtons();
  setupUserManagement();
  setupAPIClients();
  setupAccount();
  setupEmailSettings();
})();
