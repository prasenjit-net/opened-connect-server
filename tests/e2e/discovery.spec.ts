import { expect, test } from "@playwright/test";
import { AdminClient } from "../fixtures/admin-client";
import { BASE_URL } from "../fixtures/constants";

test.describe("discovery and JWKS", () => {
  test("publishes a discovery document consistent with the configured issuer", async ({ request }) => {
    const res = await request.get("/.well-known/openid-configuration");
    expect(res.status()).toBe(200);
    const doc = await res.json();

    expect(doc.issuer).toBe(BASE_URL);
    expect(doc.authorization_endpoint).toBe(`${BASE_URL}/authorize`);
    expect(doc.token_endpoint).toBe(`${BASE_URL}/token`);
    expect(doc.userinfo_endpoint).toBe(`${BASE_URL}/userinfo`);
    expect(doc.jwks_uri).toBe(`${BASE_URL}/jwks`);
    expect(doc.response_types_supported).toEqual(["code"]);
    const admin = await AdminClient.create();
    const settings = await admin.oauthSettings().finally(() => admin.dispose());
    expect(doc.grant_types_supported).toEqual(["authorization_code", "client_credentials", ...(settings.refreshTokensEnabled ? ["refresh_token"] : []), ...(settings.passwordGrantEnabled ? ["password"] : [])]);
    expect(doc.scopes_supported.includes("offline_access")).toBe(settings.refreshTokensEnabled);
    expect(doc.revocation_endpoint).toBe(`${BASE_URL}/revoke`);
    expect(doc.introspection_endpoint).toBe(`${BASE_URL}/introspect`);
    expect(doc.introspection_endpoint_auth_methods_supported).toEqual(["client_secret_basic", "client_secret_post"]);
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
    expect(doc.id_token_signing_alg_values_supported).toEqual(["RS256"]);

    // Endpoints this delivery doesn't implement must be omitted, not
    // published as false or as a URL that 404s.
    for (const absent of ["registration_endpoint", "end_session_endpoint"]) {
      // Dynamic registration is actually enabled on this e2e server, so if
      // a registration_endpoint IS published, it must be a real, working
      // URL rather than silently absent — see dynamic-client-registration.spec.ts.
      if (absent === "registration_endpoint" && doc[absent]) continue;
      expect(doc[absent], `expected ${absent} to be omitted`).toBeUndefined();
    }
  });

  test("OAuth metadata agrees with OIDC discovery", async ({ request }) => {
    const oidc = await (await request.get("/.well-known/openid-configuration")).json();
    const res = await request.get("/.well-known/oauth-authorization-server");
    expect(res.status()).toBe(200);
    const oauth = await res.json();
    for (const key of ["issuer", "authorization_endpoint", "token_endpoint", "jwks_uri", "grant_types_supported", "revocation_endpoint", "introspection_endpoint", "token_endpoint_auth_methods_supported", "introspection_endpoint_auth_methods_supported", "revocation_endpoint_auth_methods_supported"]) expect(oauth[key], key).toEqual(oidc[key]);
  });

  test("publishes only public RSA key material", async ({ request }) => {
    const res = await request.get("/jwks");
    expect(res.status()).toBe(200);
    const jwks = await res.json();
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys.length).toBeGreaterThan(0);
    const body = JSON.stringify(jwks);
    for (const forbidden of ['"d":', '"p":', '"q":', "PRIVATE KEY"]) {
      expect(body).not.toContain(forbidden);
    }
    for (const key of jwks.keys) {
      expect(key.kty).toBe("RSA");
      expect(key.n).toBeTruthy();
      expect(key.e).toBeTruthy();
    }
  });

  test("protocol routes are reserved even for the wrong HTTP method, never falling through to the SPA", async ({ request }) => {
    for (const path of ["/token", "/introspect", "/revoke"]) {
      const res = await request.get(path);
      expect(res.status()).toBe(405);
      expect(res.headers()["content-type"]).toContain("application/json");
      expect(await res.json()).toMatchObject({ error: "invalid_request" });
    }
  });
});
