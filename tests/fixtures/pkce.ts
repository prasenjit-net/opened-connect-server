import { createHash, randomBytes } from "node:crypto";

function base64url(input: Buffer): string {
  return input.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface PKCEPair {
  verifier: string;
  challenge: string;
}

/** Generates an RFC 7636 verifier/S256-challenge pair. This server accepts
 * only S256 (never `plain`), matching internal/oidc/pkce.go. */
export function generatePKCE(): PKCEPair {
  const verifier = base64url(randomBytes(32)); // 43 chars, well within the 43-128 range
  const challenge = base64url(createHash("sha256").update(verifier).digest());
  return { verifier, challenge };
}

export function randomState(): string {
  return base64url(randomBytes(16));
}
