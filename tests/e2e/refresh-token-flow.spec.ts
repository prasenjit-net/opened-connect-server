import { randomUUID } from "node:crypto";
import { test, expect } from "../fixtures/oauth-test";
import { ADMIN_STORAGE_STATE_PATH, BASE_URL, RELYING_PARTY_REDIRECT_URI, RUN_ID } from "../fixtures/constants";
import { browserGrant, clientAuth, expectError, readTokens, userInfo, type Tokens } from "../fixtures/oauth";
import { buildAuthorizeUrl } from "../fixtures/oidc-flow";
import { generatePKCE, randomState } from "../fixtures/pkce";

test.beforeEach(async ({ settings }) => {
  test.skip(!settings.refreshTokensEnabled, "Requires oauth.refreshTokensEnabled: true.");
});

for (const method of ["none", "client_secret_post"] as const) {
  test(`rotates ${method} refresh tokens, narrows scope, rejects expansion and revokes a replayed family`, async ({ admin, page, request }) => {
    const user = { name: "Refresh User", email: `refresh-${randomUUID()}@example.test`, password: "refresh flow test password" };
    await admin.createUser(user);
    const client = await admin.createClient({ redirect_uris: [RELYING_PARTY_REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: method });
    await admin.setOAuthPolicy(client.client_id, { grants: ["refresh_token"], refreshEnabled: true });
    const { tokens: initial } = await browserGrant(page, request, client, user, true);
    expect(initial.refresh_token).toBeTruthy(); expect(initial.id_token).toBeTruthy();
    const form = { ...clientAuth(client), grant_type: "refresh_token", refresh_token: initial.refresh_token! };
    await expectError(await request.post("/token", { form: { ...form, scope: "openid email" } }), 400, "invalid_scope");
    await expectError(await request.post("/token", { form: { ...form, resource: "https://other.example.test" } }), 400, "invalid_target");
    const other = await admin.createClient({ redirect_uris: [RELYING_PARTY_REDIRECT_URI], token_endpoint_auth_method: "none" });
    await expectError(await request.post("/token", { form: { ...clientAuth(other), grant_type: "refresh_token", refresh_token: initial.refresh_token! } }), 400, "invalid_grant");
    const next = await readTokens(await request.post("/token", { form: { ...form, scope: "openid" } }));
    expect(next.refresh_token).toBeTruthy(); expect(next.refresh_token).not.toBe(initial.refresh_token);
    expect(next.id_token).toBeUndefined(); expect(next.scope).toBe("openid");
    expect((await userInfo(request, next.access_token)).status()).toBe(200);
    await expectError(await request.post("/token", { form: { ...form, refresh_token: next.refresh_token!, scope: "openid profile" } }), 400, "invalid_scope");
    await expectError(await request.post("/token", { form }), 400, "invalid_grant");
    for (const tokens of [initial, next]) expect((await userInfo(request, tokens.access_token)).status()).toBe(401);
    await expectError(await request.post("/token", { form: { ...form, refresh_token: next.refresh_token! } }), 400, "invalid_grant");
  });
}

test("offline issuance requires explicit consent and the authorization code still revokes refresh descendants on replay", async ({ admin, page, request }) => {
  const user = { name: "Offline Consent", email: `offline-${randomUUID()}@example.test`, password: "offline consent test password" };
  await admin.createUser(user);
  const client = await admin.createClient({ redirect_uris: [RELYING_PARTY_REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "none" });
  await admin.setOAuthPolicy(client.client_id, { grants: ["refresh_token"], refreshEnabled: true });
  const url = buildAuthorizeUrl({ clientId: client.client_id, redirectUri: RELYING_PARTY_REDIRECT_URI, state: randomState(), nonce: randomState(), codeChallenge: generatePKCE().challenge, scope: "openid offline_access" });
  const refused = await request.get(url, { maxRedirects: 0 });
  expect(refused.status()).toBe(302);
  expect(new URL(refused.headers().location).searchParams.get("error")).toBe("invalid_scope");
  const { tokens, codeForm } = await browserGrant(page, request, client, user, true);
  const refreshed = await readTokens(await request.post("/token", { form: { ...clientAuth(client), grant_type: "refresh_token", refresh_token: tokens.refresh_token! } }));
  await expectError(await request.post("/token", { form: codeForm }), 400, "invalid_grant");
  expect((await userInfo(request, refreshed.access_token)).status()).toBe(401);
  await expectError(await request.post("/token", { form: { ...clientAuth(client), grant_type: "refresh_token", refresh_token: refreshed.refresh_token! } }), 400, "invalid_grant");
});

test("concurrent refresh yields one response, then replay invalidates the winning token", async ({ admin, page, request }) => {
  const user = { name: "Concurrent Refresh", email: `parallel-${randomUUID()}@example.test`, password: "parallel refresh test password" };
  await admin.createUser(user);
  const client = await admin.createClient({ redirect_uris: [RELYING_PARTY_REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "none" });
  await admin.setOAuthPolicy(client.client_id, { grants: ["refresh_token"], refreshEnabled: true });
  const { tokens } = await browserGrant(page, request, client, user, true);
  const form = { ...clientAuth(client), grant_type: "refresh_token", refresh_token: tokens.refresh_token! };
  const responses = await Promise.all([request.post("/token", { form }), request.post("/token", { form })]);
  expect(responses.map(r => r.status()).sort()).toEqual([200, 400]);
  const winner = await readTokens(responses.find(r => r.status() === 200)!);
  await expectError(responses.find(r => r.status() === 400)!, 400, "invalid_grant");
  expect((await userInfo(request, winner.access_token)).status()).toBe(401);
});

test("logout and access-token revocation preserve offline access; consumed refresh revocation cancels the family", async ({ admin, page, request }) => {
  const user = { name: "Offline Lifecycle", email: `logout-${randomUUID()}@example.test`, password: "logout refresh test password" };
  await admin.createUser(user);
  const client = await admin.createClient({ redirect_uris: [RELYING_PARTY_REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "none" });
  await admin.setOAuthPolicy(client.client_id, { grants: ["refresh_token"], refreshEnabled: true });
  const { tokens } = await browserGrant(page, request, client, user, true);
  const session = await (await page.request.get(`${BASE_URL}/api/auth/session`)).json();
  const logout = await page.request.post(`${BASE_URL}/api/auth/logout`, { headers: { "X-CSRF-Token": session.csrfToken }, data: {} });
  expect(logout.status()).toBe(204);
  expect((await page.request.get(`${BASE_URL}/api/auth/session`)).status()).toBe(401);
  expect((await request.post("/revoke", { form: { ...clientAuth(client), token: tokens.access_token } })).status()).toBe(200);
  const form = { ...clientAuth(client), grant_type: "refresh_token", refresh_token: tokens.refresh_token! };
  const next = await readTokens(await request.post("/token", { form }));
  expect((await userInfo(request, next.access_token)).status()).toBe(200);
  expect((await request.post("/revoke", { form: { ...clientAuth(client), token: tokens.refresh_token! } })).status()).toBe(200);
  expect((await userInfo(request, next.access_token)).status()).toBe(401);
  await expectError(await request.post("/token", { form: { ...form, refresh_token: next.refresh_token! } }), 400, "invalid_grant");
});

test("refresh monitoring loads automatically, paginates, hides consumed revoke actions and revokes the active family", async ({ admin, page, browser, request }) => {
  const user = { name: "Refresh Monitoring", email: `monitor-${randomUUID()}@example.test`, password: "monitor refresh test password" };
  await admin.createUser(user);
  const client = await admin.createClient({ client_name: `Refresh Monitor ${RUN_ID}`, redirect_uris: [RELYING_PARTY_REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "none" });
  await admin.setOAuthPolicy(client.client_id, { grants: ["refresh_token"], refreshEnabled: true });
  const { tokens: first } = await browserGrant(page, request, client, user, true);
  let latest: Tokens = first;
  for (let i = 0; i < 11; i++) latest = await readTokens(await request.post("/token", { form: { ...clientAuth(client), grant_type: "refresh_token", refresh_token: latest.refresh_token! } }));
  const context = await browser.newContext({ storageState: ADMIN_STORAGE_STATE_PATH });
  try {
    const monitor = await context.newPage();
    const initial = monitor.waitForResponse(r => new URL(r.url()).pathname === "/api/admin/activity/refresh");
    await monitor.goto(`${BASE_URL}/activity/refresh`);
    expect((await initial).status()).toBe(200);
    await monitor.getByLabel("Search activity").fill(client.client_id);
    await monitor.getByRole("button", { name: "Search", exact: true }).click();
    await expect(monitor.getByText("12 records · Page 1 of 2 · 10 per page")).toBeVisible();
    await expect(monitor.locator("tbody tr")).toHaveCount(10);
    await monitor.getByRole("button", { name: "Next", exact: true }).click();
    await expect(monitor.getByText("12 records · Page 2 of 2 · 10 per page")).toBeVisible();
    await expect(monitor.locator("tbody tr")).toHaveCount(2);
    await monitor.getByRole("combobox", { name: /^Status/ }).selectOption("consumed");
    await monitor.getByRole("button", { name: "Search", exact: true }).click();
    await expect(monitor.getByText("11 records · Page 1 of 2 · 10 per page")).toBeVisible();
    await expect(monitor.getByRole("button", { name: "Revoke", exact: true })).toHaveCount(0);
    await monitor.getByRole("combobox", { name: /^Status/ }).selectOption("active");
    await monitor.getByRole("button", { name: "Search", exact: true }).click();
    await expect(monitor.getByText("1 records · Page 1 of 1 · 10 per page")).toBeVisible();
    await monitor.getByText("Record details", { exact: true }).click();
    await expect(monitor.getByText(/Absolute expiry:/)).toBeVisible();
    await expect(monitor.getByText(/Idle expiry:/)).toBeVisible();
    await monitor.getByRole("button", { name: "Revoke", exact: true }).click();
    await monitor.getByRole("button", { name: "Confirm revoke", exact: true }).click();
    await expect(monitor.getByText("No activity records match.")).toBeVisible();
    expect((await userInfo(request, latest.access_token)).status()).toBe(401);
    await expectError(await request.post("/token", { form: { ...clientAuth(client), grant_type: "refresh_token", refresh_token: latest.refresh_token! } }), 400, "invalid_grant");
  } finally { await context.close(); }
});

for (const action of ["consent revocation", "password change"] as const) {
  test(`${action} invalidates an existing refresh family and its access token`, async ({ admin, page, request }) => {
    const user = { name: "Refresh Invalidation", email: `security-${randomUUID()}@example.test`, password: "refresh security test password" };
    await admin.createUser(user);
    const client = await admin.createClient({ redirect_uris: [RELYING_PARTY_REDIRECT_URI], grant_types: ["authorization_code", "refresh_token"], token_endpoint_auth_method: "none" });
    await admin.setOAuthPolicy(client.client_id, { grants: ["refresh_token"], refreshEnabled: true });
    const { tokens } = await browserGrant(page, request, client, user, true);
    if (action === "consent revocation") {
      const consents = await admin.listActivity("consents", { q: client.client_id, status: "active" });
      expect(consents.records).toHaveLength(1);
      await admin.revokeActivity("consents", consents.records[0].id);
    } else {
      const session = await (await page.request.get(`${BASE_URL}/api/auth/session`)).json();
      const changed = await page.request.post(`${BASE_URL}/api/user/profile/password`, { headers: { "X-CSRF-Token": session.csrfToken }, data: { currentPassword: user.password, newPassword: "changed refresh security password" } });
      expect(changed.status(), await changed.text()).toBe(204);
      expect((await page.request.get(`${BASE_URL}/api/auth/session`)).status()).toBe(401);
    }
    expect((await userInfo(request, tokens.access_token)).status()).toBe(401);
    await expectError(await request.post("/token", { form: { ...clientAuth(client), grant_type: "refresh_token", refresh_token: tokens.refresh_token! } }), 400, "invalid_grant");
  });
}
