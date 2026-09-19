import type { Page } from "@playwright/test";
import { RELYING_PARTY_ORIGIN } from "./constants";

/**
 * Intercepts every request to the fake relying-party origin and fulfills a
 * minimal static callback page locally — Playwright mocks it at the
 * network layer, so no real DNS/TLS/server for relying-party.test is ever
 * needed. This is enough to observe the final redirect (via page.url())
 * exactly as a real confidential-client RP's browser-facing callback page
 * would receive it; the RP's own backend would then exchange the code
 * server-side (which specs do directly via an APIRequestContext).
 *
 * This mocking approach only works for observing the redirect itself —
 * a page whose document was served this way cannot successfully fetch() a
 * real endpoint afterwards (Chromium treats the synthetic response as
 * having a restricted security context). public-client-cors.spec.ts needs
 * exactly that, so it uses a real local server instead — see
 * fixtures/stub-callback-server.ts.
 */
export async function mockRelyingParty(page: Page): Promise<void> {
  await page.route(`${RELYING_PARTY_ORIGIN}/**`, async (route) => {
    const url = new URL(route.request().url());
    await route.fulfill({
      status: 200,
      contentType: "text/html; charset=utf-8",
      body: `<!doctype html><html><body><h1>Relying party callback</h1><pre id="query">${url.search}</pre></body></html>`,
    });
  });
}
