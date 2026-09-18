import { test, expect } from "../fixtures/oauth-test";
import { ADMIN_STORAGE_STATE_PATH, BASE_URL, RELYING_PARTY_REDIRECT_URI, RUN_ID } from "../fixtures/constants";
import { browserGrant, clientAuth, expectError, readTokens, userInfo } from "../fixtures/oauth";

test("code-token introspection requires permission; public revocation enforces ownership and is idempotent", async ({ admin, page, request }) => {
  const user = { email: `lifecycle-${RUN_ID}@example.test`, password: "lifecycle test user password" };
  await admin.createUser({ ...user, name: "OAuth Lifecycle" });
  const client = await admin.createClient({ client_name: `Lifecycle ${RUN_ID}`, redirect_uris: [RELYING_PARTY_REDIRECT_URI], token_endpoint_auth_method: "none" });
  const other = await admin.createClient({ grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_post" });
  const { tokens } = await browserGrant(page, request, client, user);
  const inspection = { ...clientAuth(other), token: tokens.access_token, token_type_hint: "refresh_token" };
  await expectError(await request.post("/introspect", { form: inspection }), 403, "access_denied");
  await admin.setOAuthPolicy(other.client_id, { introspectionEnabled: true, introspectionAudiences: ["userinfo"] });
  const before = await request.post("/introspect", { form: inspection });
  expect(before.status()).toBe(200);
  expect(before.headers()["cache-control"]).toBe("no-store");
  expect(await before.json()).toMatchObject({ active: true, client_id: client.client_id, aud: "userinfo", scope: "openid profile" });
  await expectError(await request.post("/introspect", { form: { client_id: client.client_id, token: tokens.access_token } }), 403, "access_denied");
  // Browser cookies are not client credentials at the lifecycle endpoints.
  await expectError(await page.request.post(`${BASE_URL}/introspect`, { form: { token: tokens.access_token } }), 401, "invalid_client");
  const foreign = await request.post("/revoke", { form: inspection });
  expect(foreign.status()).toBe(200); expect(await foreign.text()).toBe("");
  expect((await userInfo(request, tokens.access_token)).status()).toBe(200);
  for (const token of [tokens.access_token, tokens.access_token, "unknown-token"]) {
    const res = await request.post("/revoke", { form: { client_id: client.client_id, token, token_type_hint: "unknown-hint" } });
    expect(res.status()).toBe(200); expect(await res.text()).toBe("");
  }
  expect((await userInfo(request, tokens.access_token)).status()).toBe(401);
  expect(await (await request.post("/introspect", { form: inspection })).json()).toEqual({ active: false });
  expect(await (await request.post("/introspect", { form: { ...inspection, token: tokens.id_token! } })).json()).toEqual({ active: false });
});

test("token endpoint rejects malformed forms, public machine grants, and unapproved confidential clients", async ({ admin, request }) => {
  const confidential = await admin.createClient({ grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_post" });
  const publicClient = await admin.createClient({ redirect_uris: [RELYING_PARTY_REDIRECT_URI], token_endpoint_auth_method: "none" });
  await expectError(await request.post("/token", { form: { ...clientAuth(confidential), grant_type: "client_credentials" } }), 400, "unauthorized_client");
  await expectError(await request.post("/token", { form: { ...clientAuth(publicClient), grant_type: "client_credentials" } }), 400, "unauthorized_client");
  await expectError(await request.post("/token", { data: { ...clientAuth(confidential), grant_type: "client_credentials" } }), 400, "invalid_request");
  const raw = new URLSearchParams({ ...clientAuth(confidential), grant_type: "client_credentials" });
  raw.append("grant_type", "authorization_code");
  await expectError(await request.post("/token", { headers: { "Content-Type": "application/x-www-form-urlencoded" }, data: raw.toString() }), 400, "invalid_request");
  for (const path of ["/revoke", "/introspect"]) await expectError(await request.post(path, { form: clientAuth(confidential) }), 400, "invalid_request");
});

test("disabled refresh/password grants are omitted from discovery and rejected even for registered clients", async ({ admin, settings, request }) => {
  test.skip(settings.refreshTokensEnabled && settings.passwordGrantEnabled, "Both optional grants enabled; positive-flow tests cover this configuration.");
  const client = await admin.createClient({ redirect_uris: [RELYING_PARTY_REDIRECT_URI], grant_types: ["authorization_code", "refresh_token", "password"], token_endpoint_auth_method: "client_secret_post" });
  const doc = await (await request.get("/.well-known/openid-configuration")).json();
  for (const [grant, enabled] of [["refresh_token", settings.refreshTokensEnabled], ["password", settings.passwordGrantEnabled]] as const) {
    if (enabled) continue;
    expect(doc.grant_types_supported).not.toContain(grant);
    await expectError(await request.post("/token", { form: { ...clientAuth(client), grant_type: grant, refresh_token: "untrusted", username: "unknown@example.test", password: "not-a-password" } }), 400, "unsupported_grant_type");
  }
});

test("machine tokens enforce resource/scope policy, inspection audiences, monitoring and revocation", async ({ admin, settings, request, browser }) => {
  const resources = settings.resources.filter(r => r.enabled && r.scopes.length);
  test.skip(!resources.length, "Requires an enabled oauth.resources entry with scopes.");
  const resource = resources[0]; const scope = resource.scopes[0];
  const client = await admin.createClient({ client_name: `Machine ${RUN_ID}`, grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_post" });
  const inspector = await admin.createClient({ grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_post" });
  await admin.setOAuthPolicy(client.client_id, { grants: ["client_credentials"], defaultResource: resource.audience, resources: { [resource.audience]: { allowed: [scope], default: [scope] } } });
  const form = { ...clientAuth(client), grant_type: "client_credentials" };
  const tokens = await readTokens(await request.post("/token", { form }));
  expect(tokens.scope).toBe(scope); expect(tokens.id_token).toBeUndefined(); expect(tokens.refresh_token).toBeUndefined();
  await admin.setOAuthPolicy(inspector.client_id, { introspectionEnabled: true, introspectionAudiences: ["userinfo"] });
  const inspect = { ...clientAuth(inspector), token: tokens.access_token };
  expect(await (await request.post("/introspect", { form: inspect })).json()).toEqual({ active: false });
  await admin.setOAuthPolicy(inspector.client_id, { introspectionEnabled: true, introspectionAudiences: [resource.audience] });
  expect(await (await request.post("/introspect", { form: inspect })).json()).toMatchObject({ active: true, sub: `client:${client.client_id}`, aud: resource.audience, client_id: client.client_id, scope });
  await expectError(await request.post("/token", { form: { ...form, scope: "openid" } }), 400, "invalid_scope");
  await expectError(await request.post("/token", { form: { ...form, resource: "https://unapproved.example.test" } }), 400, "invalid_target");
  const duplicate = new URLSearchParams(form); duplicate.append("resource", resource.audience); duplicate.append("resource", resource.audience);
  await expectError(await request.post("/token", { headers: { "Content-Type": "application/x-www-form-urlencoded" }, data: duplicate.toString() }), 400, "invalid_target");
  expect((await userInfo(request, tokens.access_token)).status()).toBe(401);
  for (const path of ["/api/user/profile", "/api/admin/users", "/api/admin/oauth"]) expect((await request.get(path, { headers: { Authorization: `Bearer ${tokens.access_token}` } })).status()).toBe(401);
  const records = await admin.listActivity("tokens", { q: client.client_id, grantType: "client_credentials", audience: resource.audience });
  expect(records.records).toHaveLength(1);
  expect(records.records[0]).toMatchObject({ subjectKind: "client", audience: resource.audience, grantType: "client_credentials", canRevoke: true });
  expect(JSON.stringify(records)).not.toContain(tokens.access_token);
  const context = await browser.newContext({ storageState: ADMIN_STORAGE_STATE_PATH });
  try {
    const page = await context.newPage();
    await page.goto(`${BASE_URL}/activity/tokens`);
    await page.getByLabel("Search activity").fill(client.client_id);
    await page.getByRole("combobox", { name: /^Grant type/ }).selectOption("client_credentials");
    await page.getByRole("textbox", { name: "Audience", exact: true }).fill(resource.audience);
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page.getByText("1 records · Page 1 of 1 · 10 per page")).toBeVisible();
    await expect(page.getByText("Machine client", { exact: true })).toBeVisible();
    await expect(page.getByText("Awaiting sign-in", { exact: true })).toHaveCount(0);
    await page.getByText("Record details", { exact: true }).click();
    await expect(page.getByText(`Audience: ${resource.audience}`, { exact: true })).toBeVisible();
    await expect(page.getByText("Grant: client_credentials", { exact: true })).toBeVisible();
    expect(await page.locator("body").innerText()).not.toContain(tokens.access_token);
  } finally { await context.close(); }

  const revoke = await request.post("/revoke", { form: { ...clientAuth(client), token: tokens.access_token } });
  expect(revoke.status()).toBe(200); expect(await revoke.text()).toBe("");
  expect(await (await request.post("/introspect", { form: inspect })).json()).toEqual({ active: false });
});

test("password grant requires explicit user entitlements and never creates browser or OpenID authority", async ({ admin, settings, request }) => {
  const resource = settings.resources.find(r => r.enabled && r.scopes.length);
  test.skip(!settings.passwordGrantEnabled || !resource, "Requires oauth.passwordGrantEnabled and an enabled API resource.");
  const user = await admin.createUser({ name: "Legacy OAuth", email: `password-${RUN_ID}@example.test`, password: "legacy test password", role: "admin" });
  const client = await admin.createClient({ grant_types: ["password"], token_endpoint_auth_method: "client_secret_post" });
  const scope = resource!.scopes[0];
  await admin.setOAuthPolicy(client.client_id, { grants: ["password"], passwordEnabled: true, defaultResource: resource!.audience, resources: { [resource!.audience]: { allowed: [scope], default: [scope] } } });
  const form = { ...clientAuth(client), grant_type: "password", username: user.email, password: "legacy test password" };
  // Even an app administrator has no implicit API scopes.
  await expectError(await request.post("/token", { form }), 400, "invalid_grant");
  await admin.setOAuthAccess(user.id, { [resource!.audience]: [scope] });
  const tokens = await readTokens(await request.post("/token", { form }));
  expect(tokens.id_token).toBeUndefined(); expect(tokens.refresh_token).toBeUndefined();
  expect((await request.get("/api/auth/session")).status()).toBe(401);
  expect((await userInfo(request, tokens.access_token)).status()).toBe(401);
  for (const username of [user.email, "unknown@example.test"]) await expectError(await request.post("/token", { form: { ...form, username, password: "wrong" } }), 400, "invalid_grant");
  await admin.setOAuthAccess(user.id, {});
  await expectError(await request.post("/token", { form }), 400, "invalid_grant");
});
