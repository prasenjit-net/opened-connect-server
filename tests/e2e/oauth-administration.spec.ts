import { randomUUID } from "node:crypto";
import { test, expect } from "../fixtures/oauth-test";
import { ADMIN_STORAGE_STATE_PATH, BASE_URL, RELYING_PARTY_REDIRECT_URI } from "../fixtures/constants";
import { fillLoginForm } from "../fixtures/oidc-flow";

test("regular users cannot see administrative OAuth controls or edit their own resource entitlements", async ({ admin, page, request }) => {
  const password = "regular authorization test password";
  const user = await admin.createUser({ name: "Regular OAuth User", email: `guard-${randomUUID()}@example.test`, password });
  const client = await admin.createClient({ redirect_uris: [RELYING_PARTY_REDIRECT_URI], token_endpoint_auth_method: "none" });
  await page.goto("/login"); await fillLoginForm(page, user.email, password); await page.waitForURL(url => url.pathname === "/");
  await expect(page.getByRole("link", { name: "Users", exact: true })).toHaveCount(0);
  const session = await (await page.request.get("/api/auth/session")).json();
  for (const path of ["/api/admin/oauth", `/api/admin/clients/${client.client_id}/oauth-policy`, `/api/admin/users/${user.id}/oauth-access`, "/api/admin/activity/refresh"]) {
    expect((await request.get(path)).status()).toBe(401);
    expect((await page.request.get(path)).status()).toBe(403);
  }
  expect((await page.request.put(`/api/admin/users/${user.id}/oauth-access`, { headers: { "X-CSRF-Token": session.csrfToken }, data: {} })).status()).toBe(403);
  for (const path of [`/clients/${client.client_id}`, `/users/${user.id}`, "/activity/refresh"]) {
    await page.goto(path); await expect(page.getByRole("heading", { name: "Access denied" })).toBeVisible();
  }
  await page.goto("/profile"); await expect(page.getByRole("button", { name: "Configure resource access" })).toHaveCount(0);
});

test("admin OAuth editors persist policies, respect server flags and require CSRF", async ({ admin, browser, settings }) => {
  const client = await admin.createClient({ client_name: "OAuth editor fixture", grant_types: ["client_credentials"], token_endpoint_auth_method: "client_secret_post" });
  const user = await admin.createUser({ name: "OAuth editor user", email: `editor-${randomUUID()}@example.test`, password: "OAuth editor test password" });
  const context = await browser.newContext({ storageState: ADMIN_STORAGE_STATE_PATH });
  try {
    const page = await context.newPage();
    expect((await context.request.put(`${BASE_URL}/api/admin/clients/${client.client_id}/oauth-policy`, { data: {} })).status()).toBe(403);
    expect((await context.request.put(`${BASE_URL}/api/admin/users/${user.id}/oauth-access`, { data: {} })).status()).toBe(403);
    await page.goto(`${BASE_URL}/clients/${client.client_id}`);
    await expect(page.getByRole("combobox", { name: /Client purpose/ })).toHaveValue("oauth");
    await expect(page.getByRole("textbox", { name: "Redirect URIs", exact: true })).toHaveCount(0);
    await page.getByRole("button", { name: "Configure OAuth permissions" }).click();
    await page.getByRole("checkbox", { name: /Client credentials — machine access/ }).check();
    await expect(page.getByRole("checkbox", { name: "Legacy password grant", exact: true })).toBeDisabled();
    await page.getByRole("checkbox", { name: "Allow token introspection", exact: true }).check();
    await page.getByRole("checkbox", { name: "userinfo", exact: true }).check();
    const saved = page.waitForResponse(r => r.url().endsWith("/oauth-policy") && r.request().method() === "PUT");
    await page.getByRole("button", { name: "Save OAuth permissions", exact: true }).click();
    expect((await saved).status()).toBe(200);
    await page.reload(); await page.getByRole("button", { name: "Configure OAuth permissions" }).click();
    await expect(page.getByRole("checkbox", { name: /Client credentials — machine access/ })).toBeChecked();
    await expect(page.getByRole("checkbox", { name: "userinfo", exact: true })).toBeChecked();
    await page.goto(`${BASE_URL}/users/${user.id}`);
    await page.getByRole("button", { name: "Configure resource access" }).click();
    const resource = settings.resources.find(r => r.enabled && r.scopes.length);
    if (resource) {
      const group = page.getByRole("group", { name: resource.audience, exact: true });
      await group.getByRole("checkbox", { name: resource.scopes[0], exact: true }).check();
      const savedAccess = page.waitForResponse(r => r.url().endsWith("/oauth-access") && r.request().method() === "PUT");
      await page.getByRole("button", { name: "Save resource access" }).click(); expect((await savedAccess).status()).toBe(200);
      await page.reload(); await page.getByRole("button", { name: "Configure resource access" }).click();
      await expect(page.getByRole("group", { name: resource.audience, exact: true }).getByRole("checkbox", { name: resource.scopes[0], exact: true })).toBeChecked();
    } else { await expect(page.getByText("No API resources configured.", { exact: true })).toBeVisible(); }
  } finally { await context.close(); }
});
