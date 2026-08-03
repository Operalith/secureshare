const fs = require("node:fs/promises");
const path = require("node:path");
const { request } = require("@playwright/test");

const authDir = process.env.PLAYWRIGHT_AUTH_DIR || path.join(__dirname, ".auth");

async function requireOK(response, operation) {
  if (!response.ok()) {
    throw new Error(`${operation} failed with HTTP ${response.status()}`);
  }
  return response;
}

async function login(baseURL, loginName, password) {
  const context = await request.newContext({ baseURL });
  const response = await requireOK(await context.post("/api/v1/auth/login", {
    data: { login: loginName, password },
  }), `login for ${loginName}`);
  const body = await response.json();
  return { context, csrfToken: body.csrf_token };
}

module.exports = async (config) => {
  const baseURL = config.projects[0].use.baseURL || process.env.BASE_URL || "http://app-test:8080";
  await fs.mkdir(authDir, { recursive: true });

  const admin = await login(baseURL, process.env.E2E_ADMIN_USERNAME || "test-admin", process.env.E2E_ADMIN_PASSWORD || "test-admin-password-change-me");
  const createUser = async (username, role) => {
    const response = await requireOK(await admin.context.post("/api/v1/users", {
      headers: { "X-CSRF-Token": admin.csrfToken },
      data: {
        username,
        email: `${username}@example.local`,
        password: `${username}-password`,
        role,
        status: "active",
      },
    }), `create ${role} fixture`);
    return response.json();
  };

  const developer = await createUser("qa-developer", "developer");
  const viewer = await createUser("qa-viewer", "viewer");
  const clientResponse = await requireOK(await admin.context.post("/api/v1/api-clients", {
    headers: { "X-CSRF-Token": admin.csrfToken },
    data: { name: "QA navigation client", scopes: ["secret:create", "secret:list"] },
  }), "create API client fixture");
  const client = await clientResponse.json();
  const secretResponse = await requireOK(await admin.context.post("/api/v1/secret-links", {
    headers: { "X-CSRF-Token": admin.csrfToken },
    data: {
      title: "Isolated QA navigation fixture",
      recipient_reference: "ui-e2e-fixture",
      expires_in_seconds: 3600,
      payload: { type: "text", text: "isolated-browser-test-value" },
    },
  }), "create secret metadata fixture");
  const secret = await secretResponse.json();

  await admin.context.storageState({ path: path.join(authDir, "admin.json") });
  const developerLogin = await login(baseURL, "qa-developer", "qa-developer-password");
  await developerLogin.context.storageState({ path: path.join(authDir, "developer.json") });
  const viewerLogin = await login(baseURL, "qa-viewer", "qa-viewer-password");
  await viewerLogin.context.storageState({ path: path.join(authDir, "viewer.json") });

  await fs.writeFile(path.join(authDir, "fixtures.json"), JSON.stringify({
    secretID: secret.id,
    clientID: client.id,
    developerID: developer.id,
    viewerID: viewer.id,
  }));

  await Promise.all([admin.context.dispose(), developerLogin.context.dispose(), viewerLogin.context.dispose()]);
};
