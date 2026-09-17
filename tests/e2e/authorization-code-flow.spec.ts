import { expect, test } from "@playwright/test";
import { AdminClient, type ClientView } from "../fixtures/admin-client";
import { BASE_URL, RELYING_PARTY_REDIRECT_URI, RUN_ID } from "../fixtures/constants";
import { buildAuthorizeUrl, currentQueryParam, fillLoginForm } from "../fixtures/oidc-flow";
import { generatePKCE, randomState } from "../fixtures/pkce";
import { mockRelyingParty } from "../fixtures/relying-party";
import { verifyIdToken } from "../fixtures/verify-id-token";

test.describe("authorization code flow (golden path)", () => {
  let admin: AdminClient;
  let client: ClientView;
  const userEmail = `golden-path-user-${RUN_ID}@example.test`;
  const userPassword = "a very real end user password";

  test.beforeAll(async () => {
    admin = await AdminClient.create();
    await admin.createUser({ name: "Golden Path User", email: userEmail, password: userPassword });
    client = await admin.createClient({
      client_name: `Golden Path RP ${RUN_ID}`,
      redirect_uris: [RELYING_PARTY_REDIRECT_URI],
      token_endpoint_auth_method: "client_secret_basic",
      response_types: ["code"],
      grant_types: ["authorization_code"],
    });
    expect(client.protocol_compatible).toBe(true);
    expect(client.client_secret).toBeTruthy();
  });

  test.afterAll(async () => {
    await admin.dispose();
  });

  test("a regular user can complete discovery -> login -> consent -> code exchange -> signature-verified UserInfo", async ({ page, request }) => {
    await mockRelyingParty(page);
    const { verifier, challenge } = generatePKCE();
    const state = randomState();
    const nonce = randomState();

    await page.goto(
      buildAuthorizeUrl({
        clientId: client.client_id,
        redirectUri: RELYING_PARTY_REDIRECT_URI,
        state,
        nonce,
        codeChallenge: challenge,
        scope: "openid profile email",
      }),
    );

    // No session yet: /authorize must bounce through the real login form.
    await page.waitForURL(/\/login\?/);
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await fillLoginForm(page, userEmail, userPassword);

    // Back at the continuation page, a fresh grant always needs consent.
    await page.waitForURL(/\/oidc\/continue\?tx=/);
    await expect(page.getByText("This application would like to:")).toBeVisible();
    await expect(page.getByText("Confirm your identity")).toBeVisible();
    await expect(page.getByText("Your email address")).toBeVisible();
    await page.getByRole("button", { name: "Approve" }).click();

    // Approval redirects the real browser to the relying party (mocked).
    await page.waitForURL(new RegExp(RELYING_PARTY_REDIRECT_URI.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    const code = currentQueryParam(page, "code");
    const returnedState = currentQueryParam(page, "state");
    expect(code).toBeTruthy();
    expect(returnedState).toBe(state);

    // The relying party's backend (not browser JS) exchanges the code —
    // modeled here with Playwright's Node-side request context, using
    // client_secret_basic exactly as registered.
    const tokenRes = await request.post(`${BASE_URL}/token`, {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${Buffer.from(`${client.client_id}:${client.client_secret}`).toString("base64")}`,
      },
      form: {
        grant_type: "authorization_code",
        code: code!,
        redirect_uri: RELYING_PARTY_REDIRECT_URI,
        code_verifier: verifier,
      },
    });
    expect(tokenRes.status(), await tokenRes.text()).toBe(200);
    expect(tokenRes.headers()["cache-control"]).toBe("no-store");
    const tokens = await tokenRes.json();
    expect(tokens.token_type).toBe("Bearer");
    expect(tokens.access_token).toBeTruthy();
    expect(tokens.id_token).toBeTruthy();

    // Independently verify the ID token's signature against the published
    // JWKS (the "jose" library, not this project's own Go code) and check
    // its claims.
    const { payload } = await verifyIdToken(tokens.id_token, client.client_id);
    expect(payload.nonce).toBe(nonce);
    expect(typeof payload.auth_time).toBe("number");
    expect(payload.iss).toBe(BASE_URL);

    const userInfoRes = await request.get(`${BASE_URL}/userinfo`, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userInfoRes.status()).toBe(200);
    const userInfo = await userInfoRes.json();
    expect(userInfo.sub).toBe(payload.sub);
    expect(userInfo.email).toBe(userEmail);
    const raw = JSON.stringify(userInfo);
    for (const forbidden of ["passwordHash", "argon2", "custom_attributes"]) {
      expect(raw).not.toContain(forbidden);
    }

    // The browser's own authenticated session cookie (still held by `page`
    // from the login above) must never substitute for the bearer token.
    const cookieOnly = await page.request.get(`${BASE_URL}/userinfo`);
    expect(cookieOnly.status()).toBe(401);
  });
});
