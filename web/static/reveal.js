(() => {
  let token = "";
  let revealedText = "";
  const state = document.querySelector("#prepare-state");
  const revealButton = document.querySelector("#reveal-button");
  const passwordWrap = document.querySelector("#password-wrap");
  const passwordInput = document.querySelector("#link-password");
  const secretWrap = document.querySelector("#revealed-secret-wrap");
  const secretCode = document.querySelector("#revealed-secret");
  const copyButton = document.querySelector("#copy-secret");

  function setState(message) {
    state.textContent = message;
  }

  function unavailable() {
    token = "";
    revealButton.disabled = true;
    setState("This secret has expired, was revoked, or has already been viewed.");
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
    if (body.password_required) {
      passwordWrap.classList.remove("hidden");
    }
    revealButton.disabled = false;
    setState("Ready to reveal. Opening this page has not consumed the secret.");
  }

  async function reveal() {
    if (!token) {
      unavailable();
      return;
    }
    revealButton.disabled = true;
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
    revealedText = typeof body.secret === "string" ? body.secret : JSON.stringify(body.secret, null, 2);
    secretCode.textContent = revealedText;
    secretWrap.classList.remove("hidden");
    setState("Secret revealed once.");
  }

  revealButton?.addEventListener("click", reveal);
  copyButton?.addEventListener("click", async () => {
    if (!revealedText) return;
    await navigator.clipboard.writeText(revealedText);
    setState("Secret copied.");
  });
  prepare();
})();
