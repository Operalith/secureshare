(() => {
  let token = "";
  let revealedText = "";

  const state = document.querySelector("#prepare-state");
  const expiresState = document.querySelector("#expires-state");
  const revealButton = document.querySelector("#reveal-button");
  const passwordWrap = document.querySelector("#password-wrap");
  const passwordInput = document.querySelector("#link-password");
  const secretWrap = document.querySelector("#revealed-secret-wrap");
  const structuredWrap = document.querySelector("#structured-secret");
  const plainWrap = document.querySelector("#plain-secret-wrap");
  const secretCode = document.querySelector("#revealed-secret");
  const copyButton = document.querySelector("#copy-secret");
  const unavailableWrap = document.querySelector("#unavailable-wrap");

  function toast(message) {
    const region = document.querySelector(".toast-region");
    if (!region) return;
    const item = document.createElement("div");
    item.className = "toast";
    item.textContent = message;
    region.appendChild(item);
    setTimeout(() => item.remove(), 3200);
  }

  function setState(message) {
    state.textContent = message;
    state.classList.remove("skeleton-line");
  }

  function unavailable() {
    token = "";
    revealButton.disabled = true;
    setState("This secret has expired, was revoked, or has already been viewed.");
    unavailableWrap.classList.remove("hidden");
  }

  function setupSecretToggles(root = document) {
    root.querySelectorAll("[data-toggle-secret]").forEach((button) => {
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

  async function prepare() {
    const fragment = window.location.hash.slice(1);
    if (fragment) {
      token = fragment;
      history.replaceState(null, "", window.location.pathname);
    }
    if (!token) {
      unavailable();
      return;
    }
    const response = await fetch("/api/v1/secret-links/prepare", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token }),
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok || !body.may_attempt) {
      unavailable();
      return;
    }
    if (body.password_required) passwordWrap.classList.remove("hidden");
    if (body.expires_at) expiresState.textContent = `Available until ${new Date(body.expires_at).toISOString()}.`;
    revealButton.disabled = false;
    setState("Ready to reveal. Opening this page has not consumed the secret.");
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

  function renderField(key, value) {
    const row = document.createElement("div");
    row.className = "revealed-field";

    const name = document.createElement("strong");
    name.textContent = key;

    const secret = document.createElement("span");
    secret.className = "secret-value";
    secret.dataset.value = String(value);
    secret.textContent = "••••••••••••";

    const actions = document.createElement("div");
    actions.className = "row-actions";
    const reveal = document.createElement("button");
    reveal.type = "button";
    reveal.className = "ghost compact";
    reveal.textContent = "Show";
    reveal.addEventListener("click", () => {
      const showing = secret.textContent === secret.dataset.value;
      secret.textContent = showing ? "••••••••••••" : secret.dataset.value;
      reveal.textContent = showing ? "Show" : "Hide";
    });
    const copy = document.createElement("button");
    copy.type = "button";
    copy.className = "secondary compact";
    copy.textContent = "Copy";
    copy.addEventListener("click", async () => {
      await navigator.clipboard.writeText(secret.dataset.value);
      toast(`${key} copied.`);
    });
    actions.append(reveal, copy);
    row.append(name, secret, actions);
    return row;
  }

  function renderSecret(secret) {
    structuredWrap.textContent = "";
    structuredWrap.classList.add("hidden");
    plainWrap.classList.add("hidden");
    revealedText = typeof secret === "string" ? secret : JSON.stringify(secret, null, 2);

    if (secret && typeof secret === "object" && !Array.isArray(secret)) {
      Object.entries(secret).forEach(([key, value]) => structuredWrap.appendChild(renderField(key, typeof value === "string" ? value : JSON.stringify(value))));
      structuredWrap.classList.remove("hidden");
      return;
    }
    secretCode.textContent = revealedText;
    plainWrap.classList.remove("hidden");
  }

  async function reveal() {
    if (!token) {
      unavailable();
      return;
    }
    setButtonLoading(revealButton, true);
    setState("Revealing secret...");
    const response = await fetch("/api/v1/secret-links/consume", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ token, password: passwordInput.value || "" }),
    });
    const body = await response.json().catch(() => ({}));
    token = "";
    if (!response.ok) {
      unavailable();
      return;
    }
    renderSecret(body.secret);
    secretWrap.classList.remove("hidden");
    setState("Secret revealed once.");
  }

  revealButton?.addEventListener("click", reveal);
  copyButton?.addEventListener("click", async () => {
    if (!revealedText) return;
    await navigator.clipboard.writeText(revealedText);
    toast("Secret copied.");
  });
  setupSecretToggles();
  prepare();
})();
