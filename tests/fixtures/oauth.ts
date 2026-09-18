import { expect, type APIRequestContext, type Page } from "@playwright/test";
import type { ClientView } from "./admin-client";
import { BASE_URL, RELYING_PARTY_REDIRECT_URI } from "./constants";
import { buildAuthorizeUrl, currentQueryParam, fillLoginForm } from "./oidc-flow";
import { generatePKCE, randomState } from "./pkce";
import { mockRelyingParty } from "./relying-party";

export interface OAuthSettings {
  protocolEnabled: boolean;
  refreshTokensEnabled: boolean;
  passwordGrantEnabled: boolean;
  resources: { audience: string; scopes: string[]; enabled: boolean }[];
}
export interface OAuthPolicy {
  grants?: string[];
  resources?: Record<string, { allowed: string[]; default: string[] }>;
  defaultResource?: string;
  introspectionEnabled?: boolean;
  introspectionAudiences?: string[];
  refreshInspection?: boolean;
  refreshEnabled?: boolean;
  passwordEnabled?: boolean;
}
export interface Tokens { access_token: string; refresh_token?: string; id_token?: string; token_type: string; scope: string; }

export function clientAuth(client: ClientView): Record<string, string> {
  return { client_id: client.client_id, ...(client.client_secret ? { client_secret: client.client_secret } : {}) };
}
export async function expectError(res: import("@playwright/test").APIResponse, status: number, error: string) {
  expect(res.status(), await res.text()).toBe(status);
  expect(await res.json()).toMatchObject({ error });
  expect(res.headers()["cache-control"]).toBe("no-store");
}
export async function readTokens(res: import("@playwright/test").APIResponse): Promise<Tokens> {
  expect(res.status(), await res.text()).toBe(200);
  expect(res.headers()["cache-control"]).toBe("no-store");
  const tokens = await res.json() as Tokens;
  expect(tokens.access_token).toBeTruthy();
  expect(tokens.token_type).toBe("Bearer");
  expect(res.headers()["set-cookie"]).toBeUndefined();
  return tokens;
}
export async function userInfo(request: APIRequestContext, token: string) {
  return request.get(`${BASE_URL}/userinfo`, { headers: { Authorization: `Bearer ${token}` } });
}
/** Fresh browser context and a fresh client per test keep consent deterministic. */
export async function browserGrant(page: Page, request: APIRequestContext, client: ClientView, user: { email: string; password: string }, offline = false) {
  await mockRelyingParty(page);
  const { verifier, challenge } = generatePKCE();
  const state = randomState();
  await page.goto(buildAuthorizeUrl({ clientId: client.client_id, redirectUri: RELYING_PARTY_REDIRECT_URI, state, nonce: randomState(), codeChallenge: challenge, scope: offline ? "openid profile offline_access" : "openid profile", prompt: "consent" }));
  await page.waitForURL(/\/login\?/);
  await fillLoginForm(page, user.email, user.password);
  await page.waitForURL(/\/oidc\/continue\?tx=/);
  if (offline) await expect(page.getByText("Maintain access when you are not signed in")).toBeVisible();
  await page.getByRole("button", { name: "Approve", exact: true }).click();
  await page.waitForURL(url => url.origin + url.pathname === RELYING_PARTY_REDIRECT_URI);
  expect(currentQueryParam(page, "state")).toBe(state);
  const code = currentQueryParam(page, "code");
  expect(code).toBeTruthy();
  const form = { ...clientAuth(client), grant_type: "authorization_code", code: code!, redirect_uri: RELYING_PARTY_REDIRECT_URI, code_verifier: verifier };
  const tokens = await readTokens(await request.post(`${BASE_URL}/token`, { form }));
  return { tokens, codeForm: form };
}
