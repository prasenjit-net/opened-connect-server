import { expect, test } from "@playwright/test";
import type { APIRequestContext } from "@playwright/test";
import { AdminClient, type ClientView } from "../fixtures/admin-client";
import { RELYING_PARTY_REDIRECT_URI, RUN_ID } from "../fixtures/constants";
import { buildAuthorizeUrl } from "../fixtures/oidc-flow";
import { generatePKCE, randomState } from "../fixtures/pkce";

// Once client_id/redirect_uri are validated, PKCE failures redirect back to
// the relying party with an OAuth error (the redirect is now trusted) —
// unlike the invalid-requests.spec.ts cases, which fail before that point.
//
// These checks use Playwright's Node-side `request` fixture with
// maxRedirects: 0 rather than a real browser navigation: no UI is ever
// rendered on this failure path, and (separately) Chromium doesn't
// reliably let page.route() intercept a redirect Location that occurs
// mid-navigation to an unresolvable host — a direct HTTP check is both
// more accurate to what's being tested and immune to that quirk.
test.describe("PKCE is mandatory (S256 only, no downgrade)", () => {
  let admin: AdminClient;
  let client: ClientView;

  test.beforeAll(async () => {
    admin = await AdminClient.create();
    client = await admin.createClient({
      client_name: `PKCE Enforcement RP ${RUN_ID}`,
      redirect_uris: [RELYING_PARTY_REDIRECT_URI],
      token_endpoint_auth_method: "none",
    });
  });

  test.afterAll(async () => {
    await admin.dispose();
  });

  async function expectRedirectError(request: APIRequestContext, url: string) {
    const res = await request.get(url, { maxRedirects: 0 });
    expect(res.status()).toBe(302);
    const location = new URL(res.headers()["location"]!);
    expect(location.origin + location.pathname).toBe(RELYING_PARTY_REDIRECT_URI);
    expect(location.searchParams.get("error")).toBe("invalid_request");
  }

  test("a missing code_challenge is rejected", async ({ request }) => {
    await expectRedirectError(
      request,
      buildAuthorizeUrl({
        clientId: client.client_id,
        redirectUri: RELYING_PARTY_REDIRECT_URI,
        state: randomState(),
        nonce: randomState(),
        omitCodeChallenge: true,
      }),
    );
  });

  test('a "plain" code_challenge_method is rejected — only S256 is accepted', async ({ request }) => {
    const { challenge } = generatePKCE();
    await expectRedirectError(
      request,
      buildAuthorizeUrl({
        clientId: client.client_id,
        redirectUri: RELYING_PARTY_REDIRECT_URI,
        state: randomState(),
        nonce: randomState(),
        codeChallenge: challenge,
        codeChallengeMethod: "plain",
      }),
    );
  });

  test("an empty code_challenge_method is rejected (no implicit fallback to plain)", async ({ request }) => {
    const { challenge } = generatePKCE();
    await expectRedirectError(
      request,
      buildAuthorizeUrl({
        clientId: client.client_id,
        redirectUri: RELYING_PARTY_REDIRECT_URI,
        state: randomState(),
        nonce: randomState(),
        codeChallenge: challenge,
        codeChallengeMethod: "",
      }),
    );
  });
});
