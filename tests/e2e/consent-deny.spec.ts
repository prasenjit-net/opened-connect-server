import { expect, test } from "@playwright/test";
import { AdminClient, type ClientView } from "../fixtures/admin-client";
import { ADMIN_EMAIL, ADMIN_PASSWORD, RELYING_PARTY_REDIRECT_URI, RUN_ID } from "../fixtures/constants";
import { buildAuthorizeUrl, currentQueryParam, fillLoginForm } from "../fixtures/oidc-flow";
import { generatePKCE, randomState } from "../fixtures/pkce";
import { mockRelyingParty } from "../fixtures/relying-party";

test.describe("consent denial", () => {
  let admin: AdminClient;
  let client: ClientView;

  test.beforeAll(async () => {
    admin = await AdminClient.create();
    client = await admin.createClient({
      client_name: `Deny Flow RP ${RUN_ID}`,
      redirect_uris: [RELYING_PARTY_REDIRECT_URI],
      token_endpoint_auth_method: "none",
    });
  });

  test.afterAll(async () => {
    await admin.dispose();
  });

  test("denying consent still redirects the relying party back with access_denied, never a dead end", async ({ page }) => {
    await mockRelyingParty(page);
    const { challenge } = generatePKCE();
    const state = randomState();

    await page.goto(
      buildAuthorizeUrl({
        clientId: client.client_id,
        redirectUri: RELYING_PARTY_REDIRECT_URI,
        state,
        nonce: randomState(),
        codeChallenge: challenge,
      }),
    );
    await page.waitForURL(/\/login\?/);
    await fillLoginForm(page, ADMIN_EMAIL, ADMIN_PASSWORD);

    await page.waitForURL(/\/oidc\/continue\?tx=/);
    await page.getByRole("button", { name: "Deny" }).click();

    await page.waitForURL(new RegExp(RELYING_PARTY_REDIRECT_URI.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
    expect(currentQueryParam(page, "error")).toBe("access_denied");
    expect(currentQueryParam(page, "state")).toBe(state);
    expect(currentQueryParam(page, "code")).toBeNull();
  });
});
