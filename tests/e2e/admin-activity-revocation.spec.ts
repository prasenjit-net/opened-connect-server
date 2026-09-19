import { expect, test } from "@playwright/test";
import { AdminClient, type ClientView } from "../fixtures/admin-client";
import { BASE_URL, RELYING_PARTY_REDIRECT_URI, RUN_ID } from "../fixtures/constants";
import { approveConsentIfShown, buildAuthorizeUrl, currentQueryParam, fillLoginForm } from "../fixtures/oidc-flow";
import { generatePKCE, randomState } from "../fixtures/pkce";
import { mockRelyingParty } from "../fixtures/relying-party";

test.describe("admin activity monitoring and revocation", () => {
  let admin: AdminClient;
  let client: ClientView;
  const clientName = `Activity Revocation RP ${RUN_ID}`;
  const userEmail = `activity-revocation-user-${RUN_ID}@example.test`;
  const userPassword = "a very real end user password";

  test.beforeAll(async () => {
    admin = await AdminClient.create();
    await admin.createUser({ name: "Activity Revocation User", email: userEmail, password: userPassword });
    client = await admin.createClient({
      client_name: clientName,
      redirect_uris: [RELYING_PARTY_REDIRECT_URI],
      token_endpoint_auth_method: "none",
    });
  });

  test.afterAll(async () => {
    await admin.dispose();
  });

  async function obtainLiveAccessToken(page: import("@playwright/test").Page, request: import("@playwright/test").APIRequestContext) {
    await mockRelyingParty(page);
    const { verifier, challenge } = generatePKCE();
    await page.goto(
      buildAuthorizeUrl({ clientId: client.client_id, redirectUri: RELYING_PARTY_REDIRECT_URI, state: randomState(), nonce: randomState(), codeChallenge: challenge }),
    );
    await page.waitForURL(/\/login\?/);
    await fillLoginForm(page, userEmail, userPassword);
    await page.waitForURL(/\/oidc\/continue\?tx=/);
    await approveConsentIfShown(page, RELYING_PARTY_REDIRECT_URI);
    const code = currentQueryParam(page, "code")!;
    const tokenRes = await request.post(`${BASE_URL}/token`, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      form: { grant_type: "authorization_code", client_id: client.client_id, code, redirect_uri: RELYING_PARTY_REDIRECT_URI, code_verifier: verifier },
    });
    expect(tokenRes.status(), await tokenRes.text()).toBe(200);
    return tokenRes.json();
  }

  test("the admin can see a completed grant in the activity overview and revoke its access token", async ({ page, request }) => {
    const tokens = await obtainLiveAccessToken(page, request);

    // Confirm it works before revocation.
    const before = await request.get(`${BASE_URL}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    expect(before.status()).toBe(200);

    const activity = await admin.listActivity("tokens", { q: clientName });
    const record = activity.records.find((r) => r.clientId === client.client_id && r.status === "active");
    expect(record, `expected an active token activity record for ${clientName}`).toBeTruthy();

    await admin.revokeActivity("tokens", record!.id);

    const after = await request.get(`${BASE_URL}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    expect(after.status()).toBe(401);

    // Revoking an already-revoked record is idempotent — it must not error.
    await expect(admin.revokeActivity("tokens", record!.id)).resolves.toBeUndefined();
  });

  test("revoking a user's consent cascades: pending grants and future silent sign-in for that client both stop", async ({ page, request }) => {
    const tokens = await obtainLiveAccessToken(page, request);
    const before = await request.get(`${BASE_URL}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    expect(before.status()).toBe(200);

    const consents = await admin.listActivity("consents", { q: clientName });
    const consentRecord = consents.records.find((r) => r.clientId === client.client_id && r.status === "active");
    expect(consentRecord, `expected an active consent record for ${clientName}`).toBeTruthy();

    await admin.revokeActivity("consents", consentRecord!.id);

    // Consent revocation cascades to the access token too.
    const after = await request.get(`${BASE_URL}/userinfo`, { headers: { Authorization: `Bearer ${tokens.access_token}` } });
    expect(after.status()).toBe(401);

    // A fresh prompt=none attempt for this user/client must now require
    // consent again rather than silently reusing the revoked grant.
    const { challenge } = generatePKCE();
    const silentRes = await page.request.get(
      buildAuthorizeUrl({
        clientId: client.client_id,
        redirectUri: RELYING_PARTY_REDIRECT_URI,
        state: randomState(),
        nonce: randomState(),
        codeChallenge: challenge,
        prompt: "none",
      }),
      { maxRedirects: 0 },
    );
    expect(silentRes.status()).toBe(302);
    const location = new URL(silentRes.headers()["location"]!);
    expect(location.searchParams.get("error")).toBe("consent_required");
  });
});
