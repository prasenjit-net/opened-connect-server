import type { Page } from "@playwright/test";
import { BASE_URL } from "./constants";

export interface AuthorizeParams {
  clientId: string;
  redirectUri: string;
  state: string;
  nonce: string;
  scope?: string;
  prompt?: string;
  maxAge?: number;
  responseType?: string;
  /** Omit to default to "S256"; pass "plain" or "" to exercise rejection. */
  codeChallengeMethod?: string;
  /** Omit to include a valid challenge; pass a string (incl. "") to override. */
  codeChallenge?: string;
  omitCodeChallenge?: boolean;
}

/** Builds a full /authorize URL against the disposable e2e server. */
export function buildAuthorizeUrl(params: AuthorizeParams): string {
  const q = new URLSearchParams({
    response_type: params.responseType ?? "code",
    client_id: params.clientId,
    redirect_uri: params.redirectUri,
    scope: params.scope ?? "openid profile email",
    state: params.state,
    nonce: params.nonce,
  });
  if (!params.omitCodeChallenge) {
    q.set("code_challenge", params.codeChallenge ?? "placeholder-challenge-set-by-caller");
    q.set("code_challenge_method", params.codeChallengeMethod ?? "S256");
  }
  if (params.prompt) q.set("prompt", params.prompt);
  if (params.maxAge !== undefined) q.set("max_age", String(params.maxAge));
  return `${BASE_URL}/authorize?${q.toString()}`;
}

/** Fills and submits the admin console's real login form. Assumes the page
 * has already been redirected to /login. */
export async function fillLoginForm(page: Page, email: string, password: string): Promise<void> {
  await page.getByLabel("Email").fill(email);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in" }).click();
}

/** Reads a query parameter off the page's current URL — used to inspect the
 * final redirect a mocked relying party received. */
export function currentQueryParam(page: Page, key: string): string | null {
  return new URL(page.url()).searchParams.get(key);
}

/**
 * Approves consent if the consent screen is shown, then waits for the
 * final redirect to redirectUri. Assumes the page has already reached
 * /oidc/continue. A covering consent from an earlier grant for the same
 * user+client+scopes (this server's documented reuse behavior — see
 * ConsentScreen/interaction.go) completes the request immediately with no
 * button to click at all, so this only clicks Approve when it actually
 * appears rather than assuming it always will.
 */
export async function approveConsentIfShown(page: Page, redirectUri: string): Promise<void> {
  const approve = page.getByRole("button", { name: "Approve" });
  try {
    await approve.waitFor({ state: "visible", timeout: 3_000 });
    await approve.click();
  } catch {
    // No consent screen — an existing covering consent let it complete already.
  }
  await page.waitForURL(new RegExp(redirectUri.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
}
