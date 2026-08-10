(() => {
  const states = new Set(["loading", "ready", "submitting", "password_error", "revealed", "unavailable", "network_error"]);
  let token = "";
  let revealedText = "";
  let currentState = "loading";
  let retryAction = "prepare";

  const copySource = document.querySelector("#recipient-copy");
  const copy = {
    locale: copySource?.dataset.locale || "en",
    ready: copySource?.dataset.ready || "The information remains available until you choose “Reveal information”.",
    availableUntil: copySource?.dataset.availableUntil || "Available until",
    availableUntilSuffix: copySource?.dataset.availableUntilSuffix ?? ".",
    reveal: copySource?.dataset.reveal || "Reveal information",
    revealing: copySource?.dataset.revealing || "Revealing information...",
    wrongPassword: copySource?.dataset.wrongPassword || "The link password is incorrect. Try again.",
    unavailableTitle: copySource?.dataset.unavailableTitle || "This link is no longer available",
    unavailableMessage: copySource?.dataset.unavailableMessage || "This link has expired, was revoked, or has already been viewed.",
    sessionLostTitle: copySource?.dataset.sessionLostTitle || "Reopen the original secure link",
    sessionLostMessage: copySource?.dataset.sessionLostMessage || "For your security, this link is not stored in the browser. Reopen the original link you received.",
    show: copySource?.dataset.show || "Show",
    hide: copySource?.dataset.hide || "Hide",
    copy: copySource?.dataset.copy || "Copy",
    copySuccess: copySource?.dataset.copySuccess || "Copied",
    invalidDate: copySource?.dataset.invalidDate || "Invalid date",
  };

  const readyState = document.querySelector("#ready-state");
  const prepareState = document.querySelector("#prepare-state");
  const expiresState = document.querySelector("#expires-state");
  const revealButton = document.querySelector("#reveal-button");
  const passwordWrap = document.querySelector("#password-wrap");
  const passwordInput = document.querySelector("#link-password");
  const passwordError = document.querySelector("#password-error");
  const secretWrap = document.querySelector("#revealed-secret-wrap");
  const structuredWrap = document.querySelector("#structured-secret");
  const plainWrap = document.querySelector("#plain-secret-wrap");
  const secretCode = document.querySelector("#revealed-secret");
  const copyButton = document.querySelector("#copy-secret");
  const unavailableWrap = document.querySelector("#unavailable-wrap");
  const unavailableTitle = document.querySelector("#unavailable-title");
  const unavailableMessage = document.querySelector("#unavailable-message");
  const networkRetry = document.querySelector("#network-retry");

  function toast(message) {
    const region = document.querySelector(".toast-region");
    if (!region) return;
    const item = document.createElement("div");
    item.className = "toast";
    item.textContent = message;
    region.appendChild(item);
    setTimeout(() => item.remove(), 3200);
  }

  function setState(next) {
    if (!states.has(next)) throw new Error(`Unknown recipient state: ${next}`);
    currentState = next;
    document.body.dataset.recipientState = next;
    document.querySelectorAll("[data-recipient-state-panel]").forEach((panel) => {
      let visible = panel.dataset.recipientStatePanel === next;
      if (panel === readyState && ["ready", "submitting", "password_error"].includes(next)) visible = true;
      panel.classList.toggle("hidden", !visible);
    });
    passwordError?.classList.toggle("hidden", next !== "password_error");
    passwordInput?.toggleAttribute("aria-invalid", next === "password_error");
  }

  function setSubmitting(submitting) {
    if (!revealButton) return;
    revealButton.textContent = submitting ? (revealButton.dataset.loadingText || copy.revealing) : copy.reveal;
    revealButton.disabled = submitting;
  }

  function unavailable() {
    token = "";
    setSubmitting(false);
    unavailableTitle.textContent = copy.unavailableTitle;
    unavailableMessage.textContent = copy.unavailableMessage;
    setState("unavailable");
  }

  function sessionLost() {
    token = "";
    setSubmitting(false);
    unavailableTitle.textContent = copy.sessionLostTitle;
    unavailableMessage.textContent = copy.sessionLostMessage;
    setState("unavailable");
  }

  function networkError(action) {
    retryAction = action;
    setSubmitting(false);
    setState("network_error");
  }

  function setupSecretToggles(root = document) {
    root.querySelectorAll("[data-toggle-secret]").forEach((button) => {
      button.addEventListener("click", () => {
        const wrap = button.closest(".input-with-action");
        const input = wrap?.querySelector("[data-secret-input]");
        if (!input) return;
        const reveal = input.type === "password";
        input.type = reveal ? "text" : "password";
        button.textContent = reveal ? copy.hide : copy.show;
        button.setAttribute("aria-label", button.textContent);
      });
    });
  }

  async function prepare() {
    const fragment = window.location.hash.slice(1);
    if (fragment) {
      token = fragment;
      history.replaceState(null, "", `${window.location.pathname}${window.location.search}`);
    }
    if (!token) {
      sessionLost();
      return;
    }
    setState("loading");
    try {
      const response = await fetch("/api/v1/secret-links/prepare", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        networkError("prepare");
        return;
      }
      if (!body.may_attempt) {
        unavailable();
        return;
      }
      passwordWrap.classList.toggle("hidden", !body.password_required);
      if (body.expires_at) {
        const timeElement = document.createElement("time");
        if (window.SecureShareTime?.render) {
          window.SecureShareTime.render(timeElement, body.expires_at, {
            locale: copy.locale,
            preset: "recipient",
            emptyLabel: copy.invalidDate,
            invalidLabel: copy.invalidDate,
          });
        } else {
          timeElement.textContent = body.expires_at;
          timeElement.setAttribute("datetime", body.expires_at);
          timeElement.setAttribute("title", body.expires_at);
        }
        expiresState.replaceChildren(`${copy.availableUntil} `, timeElement, copy.availableUntilSuffix);
      }
      prepareState.textContent = copy.ready;
      setSubmitting(false);
      setState("ready");
    } catch {
      networkError("prepare");
    }
  }

  function renderField(field) {
    const row = document.createElement("div");
    row.className = "revealed-field";

    const name = document.createElement("strong");
    name.textContent = field.label || field.name;

    const secret = document.createElement("span");
    secret.className = "secret-value technical-value";
    secret.dataset.value = String(field.value);
    secret.textContent = field.sensitive ? "••••••••••••" : secret.dataset.value;

    const actions = document.createElement("div");
    actions.className = "row-actions";
    const reveal = document.createElement("button");
    reveal.type = "button";
    reveal.className = "ghost compact";
    reveal.textContent = copy.show;
    reveal.hidden = !field.sensitive;
    reveal.addEventListener("click", () => {
      const showing = secret.textContent === secret.dataset.value;
      secret.textContent = showing ? "••••••••••••" : secret.dataset.value;
      reveal.textContent = showing ? copy.show : copy.hide;
    });
    const copyAction = document.createElement("button");
    copyAction.type = "button";
    copyAction.className = "secondary compact";
    copyAction.textContent = copy.copy;
    copyAction.addEventListener("click", async () => {
      await navigator.clipboard.writeText(secret.dataset.value);
      toast(copy.copySuccess);
    });
    actions.append(reveal, copyAction);
    row.append(name, secret, actions);
    return row;
  }

  function renderSecret(payload, legacySecret) {
    structuredWrap.textContent = "";
    structuredWrap.classList.add("hidden");
    plainWrap.classList.add("hidden");

    if (payload?.type === "structured" && Array.isArray(payload.fields)) {
      revealedText = payload.fields.map((field) => `${field.label || field.name}: ${field.value}`).join("\n");
      payload.fields.forEach((field) => structuredWrap.appendChild(renderField(field)));
      structuredWrap.classList.remove("hidden");
      return;
    }
    if (payload?.type === "json") {
      revealedText = JSON.stringify(payload.value, null, 2);
      secretCode.textContent = revealedText;
      plainWrap.classList.remove("hidden");
      return;
    }
    if (payload?.type === "text") {
      revealedText = payload.text || "";
      secretCode.textContent = revealedText;
      plainWrap.classList.remove("hidden");
      return;
    }
    revealedText = typeof legacySecret === "string" ? legacySecret : JSON.stringify(legacySecret, null, 2);
    secretCode.textContent = revealedText;
    plainWrap.classList.remove("hidden");
  }

  async function reveal() {
    if (!token) {
      sessionLost();
      return;
    }
    passwordError.textContent = "";
    setSubmitting(true);
    setState("submitting");
    let shouldFocusPassword = false;
    try {
      const response = await fetch("/api/v1/secret-links/consume", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token, password: passwordInput.value || "" }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) {
        if (response.status === 401 && body.code === "LINK_PASSWORD_INVALID") {
          passwordError.textContent = copy.wrongPassword;
          setState("password_error");
          shouldFocusPassword = true;
          return;
        }
        if (body.code === "SECRET_UNAVAILABLE") {
          unavailable();
          return;
        }
        networkError("reveal");
        return;
      }
      token = "";
      renderSecret(body.payload, body.secret);
      setState("revealed");
    } catch {
      networkError("reveal");
    } finally {
      setSubmitting(false);
      if (currentState === "submitting") setState("ready");
      if (shouldFocusPassword) passwordInput.focus();
    }
  }

  revealButton?.addEventListener("click", reveal);
  passwordInput?.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !revealButton.disabled) reveal();
  });
  networkRetry?.addEventListener("click", () => {
    if (retryAction === "reveal") reveal();
    else prepare();
  });
  copyButton?.addEventListener("click", async () => {
    if (!revealedText) return;
    await navigator.clipboard.writeText(revealedText);
    toast(copy.copySuccess);
  });
  setupSecretToggles();
  prepare();
})();
