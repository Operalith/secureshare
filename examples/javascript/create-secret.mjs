const baseURL = (process.env.SECURESHARE_BASE_URL || "http://localhost:8080").replace(/\/$/, "");
const clientID = process.env.SECURESHARE_CLIENT_ID;
const clientSecret = process.env.SECURESHARE_CLIENT_SECRET;

if (!clientID || !clientSecret) {
  console.error("SECURESHARE_CLIENT_ID and SECURESHARE_CLIENT_SECRET are required");
  process.exit(2);
}

const payload = {
  title: "Example login",
  expires_in_seconds: 3600,
  payload: {
    type: "structured",
    fields: [
      { name: "username", label: "Username", value: "example-user", sensitive: false, multiline: false },
      { name: "password", label: "Password", value: "example-password", sensitive: true, multiline: false },
    ],
  },
};

const controller = new AbortController();
const timeout = setTimeout(() => controller.abort(), 15000);

try {
  const response = await fetch(`${baseURL}/api/v1/secret-links`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${Buffer.from(`${clientID}:${clientSecret}`).toString("base64")}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(payload),
    signal: controller.signal,
  });

  if (!response.ok) {
    console.error(`SecureShare returned HTTP ${response.status}`);
    process.exit(1);
  }

  const body = await response.json();
  console.log(body.url);
} finally {
  clearTimeout(timeout);
}
