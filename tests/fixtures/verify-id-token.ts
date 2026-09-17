import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import { BASE_URL } from "./constants";

// A fresh remote JWKS set per call keeps each spec file's verification
// independent (no shared cache surviving key rotation within a single
// suite run) while still exercising the exact "fetch JWKS, verify RS256"
// path a real relying-party library performs.
export async function verifyIdToken(idToken: string, audience: string): Promise<{ payload: JWTPayload }> {
  const jwks = createRemoteJWKSet(new URL(`${BASE_URL}/jwks`));
  const { payload } = await jwtVerify(idToken, jwks, {
    issuer: BASE_URL,
    audience,
    algorithms: ["RS256"],
  });
  return { payload };
}
