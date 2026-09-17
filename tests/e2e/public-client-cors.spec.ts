import { expect, test } from "@playwright/test";
import { AdminClient, type ClientView } from "../fixtures/admin-client";
import { BASE_URL, PUBLIC_CLIENT_ORIGIN, PUBLIC_CLIENT_PORT, PUBLIC_CLIENT_REDIRECT_URI, RUN_ID } from "../fixtures/constants";
import { buildAuthorizeUrl, fillLoginForm } from "../fixtures/oidc-flow";
import { generatePKCE, randomState } from "../fixtures/pkce";
import { clientSideExchangeHtml, StubCallbackServer } from "../fixtures/stub-callback-server";

// /token and /userinfo only allow cross-origin browser JS calls from
// origins listed in oidc.allowedOrigins. This suite cannot assume the
// target server lists PUBLIC_CLIENT_ORIGIN, so it checks first and skips
// (rather than failing) if it doesn't — see tests/README.md.
test.describe("public client browser-side token exchange (CORS)", () => {
  let admin: AdminClient;
  let client: ClientView;
  let originAllowed = false;
  const userEmail = `cors-user-${RUN_ID}@example.test`;
  const userPassword = "a very real end user password";

  test.beforeAll(async ({ request }) => {
    admin = await AdminClient.create();
    await admin.createUser({ name: "CORS Test User", email: userEmail, password: userPassword });
    client = await admin.createClient({
      client_name: `CORS Public Client RP ${RUN_ID}`,
      redirect_uris: [PUBLIC_CLIENT_REDIRECT_URI],
      token_endpoint_auth_method: "none",
    });

    const preflight = await request.fetch(`${BASE_URL}/token`, {
      method: "OPTIONS",
      headers: { Origin: PUBLIC_CLIENT_ORIGIN, "Access-Control-Request-Method": "POST" },
    });
    originAllowed = preflight.headers()["access-control-allow-origin"] === PUBLIC_CLIENT_ORIGIN;
  });

  test.afterAll(async () => {
    await admin.dispose();
  });

  test("a browser-side fetch from an allowed origin can exchange the code and call UserInfo", async ({ page }) => {
    test.skip(!originAllowed, `${PUBLIC_CLIENT_ORIGIN} is not in oidc.allowedOrigins on the target server; see tests/README.md.`);

    const { verifier, challenge } = generatePKCE();
    const stubServer = await StubCallbackServer.start(
      clientSideExchangeHtml({ baseUrl: BASE_URL, clientId: client.client_id, codeVerifier: verifier }),
      PUBLIC_CLIENT_PORT,
    );
    try {
      await page.goto(
        buildAuthorizeUrl({ clientId: client.client_id, redirectUri: PUBLIC_CLIENT_REDIRECT_URI, state: randomState(), nonce: randomState(), codeChallenge: challenge }),
      );
      await page.waitForURL(/\/login\?/);
      await fillLoginForm(page, userEmail, userPassword);
      await page.waitForURL(/\/oidc\/continue\?tx=/);
      await page.getByRole("button", { name: "Approve" }).click();

      await page.waitForURL(new RegExp(PUBLIC_CLIENT_ORIGIN.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
      await expect(page.locator("#result")).not.toHaveText("pending");
      const result = JSON.parse((await page.locator("#result").textContent())!);
      expect(result.tokenStatus, JSON.stringify(result)).toBe(200);
      expect(result.userInfoStatus).toBe(200);
      expect(result.userInfo.email).toBe(userEmail);
    } finally {
      await stubServer.stop();
    }
  });

  test("an origin not on the allowlist gets no CORS header on /token (browser JS would be blocked from reading the response)", async ({ request }) => {
    const res = await request.fetch(`${BASE_URL}/token`, {
      method: "OPTIONS",
      headers: { Origin: "https://not-an-allowed-origin.test", "Access-Control-Request-Method": "POST" },
    });
    expect(res.headers()["access-control-allow-origin"]).toBeUndefined();
  });
});
