import http from "node:http";

/**
 * A real, listening local HTTP server that serves one static callback page.
 * Needed specifically for public-client-cors.spec.ts: a page whose document
 * was served via Playwright's page.route()/route.fulfill() mocking cannot
 * successfully fetch() a genuinely separate real endpoint (Chromium treats
 * a fully synthetic response as having a restricted security context) —
 * confirmed empirically. A real server sidesteps that entirely, which is
 * exactly what's needed to exercise real browser CORS enforcement.
 *
 * Listens on a fixed port (matching PUBLIC_CLIENT_ORIGIN in
 * fixtures/constants.ts) rather than an OS-assigned one, because the
 * target server's oidc.allowedOrigins allowlist is static configuration
 * that can't know a randomly-chosen port in advance.
 */
export class StubCallbackServer {
  private constructor(private readonly server: http.Server) {}

  static async start(html: string, port: number): Promise<StubCallbackServer> {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
    });
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(port, "127.0.0.1", resolve);
    });
    return new StubCallbackServer(server);
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) => this.server.close((err) => (err ? reject(err) : resolve())));
  }
}

export function clientSideExchangeHtml(opts: { baseUrl: string; clientId: string; codeVerifier: string }): string {
  return `<!doctype html>
<html><body>
<pre id="result">pending</pre>
<script>
(async () => {
  const params = new URLSearchParams(location.search);
  const code = params.get("code");
  const error = params.get("error");
  const out = document.getElementById("result");
  if (error) { out.textContent = JSON.stringify({ error }); return; }
  try {
    const tokenRes = await fetch(${JSON.stringify(opts.baseUrl)} + "/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: ${JSON.stringify(opts.clientId)},
        code: code,
        redirect_uri: location.origin + location.pathname,
        code_verifier: ${JSON.stringify(opts.codeVerifier)},
      }),
    });
    const tokens = await tokenRes.json();
    if (!tokenRes.ok) { out.textContent = JSON.stringify({ tokenStatus: tokenRes.status, tokenError: tokens }); return; }
    const userInfoRes = await fetch(${JSON.stringify(opts.baseUrl)} + "/userinfo", {
      headers: { Authorization: "Bearer " + tokens.access_token },
    });
    const userInfo = await userInfoRes.json();
    out.textContent = JSON.stringify({ tokenStatus: tokenRes.status, userInfoStatus: userInfoRes.status, userInfo: userInfo });
  } catch (e) {
    out.textContent = JSON.stringify({ fetchError: String(e) });
  }
})();
</script>
</body></html>`;
}
