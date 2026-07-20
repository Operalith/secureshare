(() => {
  const form = document.querySelector("#create-secret-form");
  const typeSelect = document.querySelector("#secret-type");
  const statusLine = document.querySelector("#create-status");
  const resultPanel = document.querySelector("#created-result");
  const addRowButton = document.querySelector("#add-kv-row");
  const kvRows = document.querySelector("#kv-rows");
  let createdID = "";

  function setStatus(message) {
    if (statusLine) statusLine.textContent = message || "";
  }

  function updateSecretInput() {
    if (!typeSelect) return;
    document.querySelectorAll(".secret-input").forEach((el) => el.classList.add("hidden"));
    const target = document.querySelector(`.secret-input-${typeSelect.value}`);
    if (target) target.classList.remove("hidden");
  }

  function addKVRow() {
    if (!kvRows) return;
    const row = document.createElement("div");
    row.className = "kv-row";
    row.innerHTML = '<input name="kv_key" placeholder="Key" autocomplete="off"><input name="kv_value" placeholder="Value" autocomplete="off"><button type="button" class="icon-button remove-kv-row" aria-label="Remove field">x</button>';
    kvRows.appendChild(row);
  }

  function buildSecret(data) {
    const kind = data.get("secret_type");
    if (kind === "json") {
      const raw = String(data.get("secret_json") || "");
      return JSON.parse(raw);
    }
    if (kind === "kv") {
      const secret = {};
      const keys = form.querySelectorAll('input[name="kv_key"]');
      const values = form.querySelectorAll('input[name="kv_value"]');
      keys.forEach((key, index) => {
        const name = key.value.trim();
        if (name) secret[name] = values[index].value;
      });
      if (Object.keys(secret).length === 0) throw new Error("Add at least one key-value field.");
      return secret;
    }
    const text = String(data.get("secret_text") || "");
    if (!text) throw new Error("Secret content is required.");
    return text;
  }

  async function createSecret(event) {
    event.preventDefault();
    setStatus("Creating secure link...");
    resultPanel?.classList.add("hidden");
    const data = new FormData(form);
    let secret;
    try {
      secret = buildSecret(data);
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
    createdID = body.id;
    document.querySelector("#created-id").textContent = body.id;
    document.querySelector("#created-expires").textContent = new Date(body.expires_at).toISOString();
    document.querySelector("#created-url").value = body.url;
    document.querySelector("#view-created-meta").href = `/admin/secrets/${body.id}`;
    resultPanel.classList.remove("hidden");
    setStatus("Secure link created.");
    form.reset();
    updateSecretInput();
  }

  async function revokeCreated() {
    if (!createdID) return;
    const response = await fetch(`/api/v1/secret-links/${createdID}/revoke`, {
      method: "POST",
      credentials: "same-origin",
    });
    if (response.ok) {
      setStatus("Link revoked.");
      document.querySelector("#revoke-created-url").disabled = true;
    } else {
      setStatus("The link could not be revoked.");
    }
  }

  async function revokeFromMetadata(event) {
    const button = event.target.closest("[data-revoke-id]");
    if (!button) return;
    const id = button.getAttribute("data-revoke-id");
    button.disabled = true;
    const response = await fetch(`/api/v1/secret-links/${id}/revoke`, {
      method: "POST",
      credentials: "same-origin",
    });
    button.textContent = response.ok ? "Revoked" : "Unavailable";
  }

  typeSelect?.addEventListener("change", updateSecretInput);
  addRowButton?.addEventListener("click", addKVRow);
  kvRows?.addEventListener("click", (event) => {
    const button = event.target.closest(".remove-kv-row");
    if (!button) return;
    const rows = kvRows.querySelectorAll(".kv-row");
    if (rows.length > 1) button.closest(".kv-row").remove();
  });
  form?.addEventListener("submit", createSecret);
  document.querySelector("#copy-created-url")?.addEventListener("click", async () => {
    const input = document.querySelector("#created-url");
    await navigator.clipboard.writeText(input.value);
    setStatus("Link copied.");
  });
  document.querySelector("#revoke-created-url")?.addEventListener("click", revokeCreated);
  document.addEventListener("click", revokeFromMetadata);
  updateSecretInput();
})();
