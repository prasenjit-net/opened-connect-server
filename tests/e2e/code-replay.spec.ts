import { expect, test } from "@playwright/test";
import { AdminClient, type ClientView } from "../fixtures/admin-client";
import { BASE_URL, RELYING_PARTY_REDIRECT_URI, RUN_ID } from "../fixtures/constants";
import { approveConsentIfShown, buildAuthorizeUrl, currentQueryParam, fillLoginForm } from "../fixtures/oidc-flow";
import { generatePKCE, randomState } from "../fixtures/pkce";
import { mockRelyingParty } from "../fixtures/relying-party";

test.describe("authorization code single-use enforcement", () => {
  let admin: AdminClient;
  let client: ClientView;
  const userEmail = `code-replay-user-${RUN_ID}@example.test`;
  const userPassword = "a very real end user password";

  test.beforeAll(async () => {
    admin = await AdminClient.create();
    await admin.createUser({ name: "Code Replay User", email: userEmail, password: userPassword });
    client = await admin.createClient({
      client_name: `Code Replay RP ${RUN_ID}`,
      redirect_uris: [RELYING_PARTY_REDIRECT_URI],
      token_endpoint_auth_method: "none",
    });
  });

  test.afterAll(async () => {
    await admin.dispose();
  });

  test("a second exchange of an already-used code fails, and revokes the access token the first exchange minted", async ({ page, request }) => {
    await mockRelyingParty(page);
    const { verifier, challenge } = generatePKCE();

    await page.goto(
      buildAuthorizeUrl({
        clientId: client.client_id,
        redirectUri: RELYING_PARTY_REDIRECT_URI,
        state: randomState(),
        nonce: randomState(),
        codeChallenge: challenge,
      }),
    );
    await page.waitForURL(/\/login\?/);
    await fillLoginForm(page, userEmail, userPassword);
    await page.waitForURL(/\/oidc\/continue\?tx=/);
    await approveConsentIfShown(page, RELYING_PARTY_REDIRECT_URI);
    const code = currentQueryParam(page, "code")!;

    const exchange = () =>
      request.post(`${BASE_URL}/token`, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        form: { grant_type: "authorization_code", client_id: client.client_id, code, redirect_uri: RELYING_PARTY_REDIRECT_URI, code_verifier: verifier },
      });

    const first = await exchange();
    expect(first.status(), await first.text()).toBe(200);
    const firstTokens = await first.json();

    const second = await exchange();
    expect(second.status()).toBe(400);
    const secondBody = await second.json();
    expect(secondBody.error).toBe("invalid_grant");

    // The replay must not just fail — it revokes the token minted by the
    // original, legitimate exchange too.
    const userInfoAfterReplay = await request.get(`${BASE_URL}/userinfo`, {
      headers: { Authorization: `Bearer ${firstTokens.access_token}` },
    });
    expect(userInfoAfterReplay.status()).toBe(401);
  });

  test("two concurrent exchanges of the same code yield exactly one success", async ({ page, request }) => {
    await mockRelyingParty(page);
    const { verifier, challenge } = generatePKCE();

    await page.goto(
      buildAuthorizeUrl({
        clientId: client.client_id,
        redirectUri: RELYING_PARTY_REDIRECT_URI,
        state: randomState(),
        nonce: randomState(),
        codeChallenge: challenge,
      }),
    );
    await page.waitForURL(/\/login\?/);
    await fillLoginForm(page, userEmail, userPassword);
    await page.waitForURL(/\/oidc\/continue\?tx=/);
    await approveConsentIfShown(page, RELYING_PARTY_REDIRECT_URI);
    const code = currentQueryParam(page, "code")!;

    const form = { grant_type: "authorization_code", client_id: client.client_id, code, redirect_uri: RELYING_PARTY_REDIRECT_URI, code_verifier: verifier };
    const [a, b] = await Promise.all([
      request.post(`${BASE_URL}/token`, { headers: { "Content-Type": "application/x-www-form-urlencoded" }, form }),
      request.post(`${BASE_URL}/token`, { headers: { "Content-Type": "application/x-www-form-urlencoded" }, form }),
    ]);
    const statuses = [a.status(), b.status()].sort();
    expect(statuses).toEqual([200, 400]);
  });
});
