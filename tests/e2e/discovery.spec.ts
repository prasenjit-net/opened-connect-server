import { expect, test } from "@playwright/test";
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
    expect(doc.grant_types_supported).toEqual(["authorization_code"]);
    expect(doc.code_challenge_methods_supported).toEqual(["S256"]);
    expect(doc.id_token_signing_alg_values_supported).toEqual(["RS256"]);

    // Endpoints this delivery doesn't implement must be omitted, not
    // published as false or as a URL that 404s.
    for (const absent of ["registration_endpoint", "revocation_endpoint", "introspection_endpoint", "end_session_endpoint"]) {
      // Dynamic registration is actually enabled on this e2e server, so if
      // a registration_endpoint IS published, it must be a real, working
      // URL rather than silently absent — see dynamic-client-registration.spec.ts.
      if (absent === "registration_endpoint" && doc[absent]) continue;
      expect(doc[absent], `expected ${absent} to be omitted`).toBeUndefined();
    }
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
    const res = await request.get("/token"); // POST-only
    expect(res.status()).not.toBe(200);
    const body = await res.text();
    expect(body).not.toContain("<!doctype html");
  });
});
