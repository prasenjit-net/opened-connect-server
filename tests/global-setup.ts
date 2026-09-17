import { request } from "@playwright/test";
import fs from "node:fs";
import { ADMIN_CSRF_PATH, ADMIN_EMAIL, ADMIN_PASSWORD, ADMIN_STORAGE_STATE_PATH, AUTH_DIR, BASE_URL } from "./fixtures/constants";

// Runs once, before any spec file, against whatever server is already
// running at BASE_URL — this suite never starts one itself. Verifies the
// target is reachable and OIDC-enabled, logs in as the configured admin,
// and persists the session cookie + CSRF token so every spec can build an
// authenticated admin client without repeating a login.
export default async function globalSetup() {
  fs.mkdirSync(AUTH_DIR, { recursive: true });

  const ctx = await request.newContext({ baseURL: BASE_URL });
  try {
    const discovery = await ctx.get("/.well-known/openid-configuration").catch(() => null);
    if (!discovery || !discovery.ok()) {
      throw new Error(
        `No OIDC-enabled server responding at ${BASE_URL}.\n` +
          `Start one first — either your own instance (with oidc.enabled: true in its config) or a disposable one via:\n` +
          `  bash scripts/run-server.sh\n` +
          `then point this suite at it with E2E_BASE_URL (see tests/README.md).`,
      );
    }

    const loginRes = await ctx.post("/api/auth/login", {
      data: { email: ADMIN_EMAIL, password: ADMIN_PASSWORD },
    });
    if (!loginRes.ok()) {
      throw new Error(
        `Admin login failed against ${BASE_URL} (${loginRes.status()}): ${await loginRes.text()}\n` +
          `Check E2E_ADMIN_EMAIL/E2E_ADMIN_PASSWORD match a real active administrator on that server.`,
      );
    }
    const session = (await loginRes.json()) as { csrfToken: string; user: { role: string } };
    if (session.user.role !== "admin") {
      throw new Error(`${ADMIN_EMAIL} signed in but is not an administrator on ${BASE_URL}.`);
    }
    fs.writeFileSync(ADMIN_CSRF_PATH, JSON.stringify({ csrfToken: session.csrfToken }, null, 2));
    await ctx.storageState({ path: ADMIN_STORAGE_STATE_PATH });
  } finally {
    await ctx.dispose();
  }
}
