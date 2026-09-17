import { expect, test } from "@playwright/test";
import { AdminClient, type ClientView } from "../fixtures/admin-client";
import { BASE_URL, RELYING_PARTY_REDIRECT_URI, RUN_ID } from "../fixtures/constants";
import { buildAuthorizeUrl } from "../fixtures/oidc-flow";
import { generatePKCE, randomState } from "../fixtures/pkce";

test.describe("invalid requests never reach the relying party", () => {
  let admin: AdminClient;
  let client: ClientView;

  test.beforeAll(async () => {
    admin = await AdminClient.create();
    client = await admin.createClient({
      client_name: `Invalid Request RP ${RUN_ID}`,
      redirect_uris: [RELYING_PARTY_REDIRECT_URI],
      token_endpoint_auth_method: "none",
    });
  });

  test.afterAll(async () => {
    await admin.dispose();
  });

  test("an unknown client_id renders an error page directly, never a redirect", async ({ page }) => {
    const { challenge } = generatePKCE();
    const res = await page.goto(
      buildAuthorizeUrl({
        clientId: "this-client-id-does-not-exist",
        redirectUri: RELYING_PARTY_REDIRECT_URI,
        state: randomState(),
        nonce: randomState(),
        codeChallenge: challenge,
      }),
    );
    expect(res?.status()).toBe(400);
    expect(page.url()).toContain(`${BASE_URL}/authorize`); // never navigated away
    await expect(page.getByRole("heading", { name: "This sign-in request cannot be completed" })).toBeVisible();
    await expect(page.getByText("This client is not registered.")).toBeVisible();
  });

  test("a redirect_uri not on the client's registered list renders an error page directly, never a redirect", async ({ page }) => {
    const { challenge } = generatePKCE();
    const res = await page.goto(
      buildAuthorizeUrl({
        clientId: client.client_id,
        redirectUri: "https://an-attacker-controlled-site.test/cb",
        state: randomState(),
        nonce: randomState(),
        codeChallenge: challenge,
      }),
    );
    expect(res?.status()).toBe(400);
    expect(page.url()).toContain(`${BASE_URL}/authorize`);
    await expect(page.getByText("The redirect_uri does not exactly match a URI registered for this client.")).toBeVisible();
  });

  test("a duplicated security-critical parameter is rejected before any client/redirect trust decision", async ({ page }) => {
    const { challenge } = generatePKCE();
    const url = buildAuthorizeUrl({
      clientId: client.client_id,
      redirectUri: RELYING_PARTY_REDIRECT_URI,
      state: randomState(),
      nonce: randomState(),
      codeChallenge: challenge,
    });
    const res = await page.goto(`${url}&client_id=another-client-id`);
    expect(res?.status()).toBe(400);
    await expect(page.getByText(/duplicate, malformed, or oversized parameters/)).toBeVisible();
  });
});
