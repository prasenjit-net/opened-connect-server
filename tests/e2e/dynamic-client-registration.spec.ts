import { expect, test } from "@playwright/test";
import { AdminClient } from "../fixtures/admin-client";
import { BASE_URL, RELYING_PARTY_REDIRECT_URI, RUN_ID } from "../fixtures/constants";

// Dynamic registration is an opt-in server feature (oidc.registrationEnabled)
// that this suite cannot assume is on for whatever target server it's
// pointed at. Skip cleanly (with an explanatory message) rather than
// failing when it's off.
test.describe("dynamic client registration", () => {
  let admin: AdminClient;
  let registrationEnabled = false;

  test.beforeAll(async () => {
    admin = await AdminClient.create();
    registrationEnabled = (await admin.registrationSettings()).enabled;
  });

  test.afterAll(async () => {
    await admin.dispose();
  });

  test("an initial access token registers a client, which can then read back its own registration", async ({ request }) => {
    test.skip(!registrationEnabled, "oidc.registrationEnabled is off on the target server; see tests/README.md to enable it.");

    const { token: initialAccessToken } = await admin.issueInitialAccessToken({ label: `e2e-${RUN_ID}`, maxUses: 1, lifetimeHours: 1 });

    const registerRes = await request.post(`${BASE_URL}/register`, {
      headers: { Authorization: `Bearer ${initialAccessToken}`, "Content-Type": "application/json" },
      data: {
        client_name: `Dynamically Registered RP ${RUN_ID}`,
        redirect_uris: [RELYING_PARTY_REDIRECT_URI],
        token_endpoint_auth_method: "none",
      },
    });
    expect(registerRes.status(), await registerRes.text()).toBe(201);
    const registered = await registerRes.json();
    expect(registered.client_id).toBeTruthy();
    admin.trackRegisteredClient(registered.client_id);
    expect(registered.registration_access_token).toBeTruthy();
    expect(registered.registration_client_uri).toBe(`${BASE_URL}/register/${registered.client_id}`);
    // Public client: no secret should ever be issued.
    expect(registered.client_secret).toBeUndefined();

    // A second use of the same (maxUses: 1) initial access token must fail.
    const secondRegisterRes = await request.post(`${BASE_URL}/register`, {
      headers: { Authorization: `Bearer ${initialAccessToken}`, "Content-Type": "application/json" },
      data: { redirect_uris: [RELYING_PARTY_REDIRECT_URI] },
    });
    expect(secondRegisterRes.status()).toBe(401);

    // The registration access token can read the client back...
    const readRes = await request.get(`${BASE_URL}/register/${registered.client_id}`, {
      headers: { Authorization: `Bearer ${registered.registration_access_token}` },
    });
    expect(readRes.status()).toBe(200);
    const read = await readRes.json();
    expect(read.client_id).toBe(registered.client_id);

    // ...but a wrong/absent token cannot.
    const wrongTokenRes = await request.get(`${BASE_URL}/register/${registered.client_id}`, {
      headers: { Authorization: "Bearer not-the-real-registration-token" },
    });
    expect(wrongTokenRes.status()).toBe(401);
  });

  test("an initial access token cannot be used to supply server-owned fields", async ({ request }) => {
    test.skip(!registrationEnabled, "oidc.registrationEnabled is off on the target server; see tests/README.md to enable it.");

    const { token: initialAccessToken } = await admin.issueInitialAccessToken({ label: `e2e-owned-${RUN_ID}`, maxUses: 1 });
    const res = await request.post(`${BASE_URL}/register`, {
      headers: { Authorization: `Bearer ${initialAccessToken}`, "Content-Type": "application/json" },
      data: { redirect_uris: [RELYING_PARTY_REDIRECT_URI], client_id: "attacker-chosen-id" },
    });
    expect(res.status()).toBe(400);
    const body = await res.json();
    expect(body.error).toBe("invalid_client_metadata");
  });
});
