import path from "node:path";
import { fileURLToPath } from "node:url";

const TESTS_DIR = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

// This suite never starts a server itself — it targets whatever instance is
// already running at BASE_URL (your own `make dev`/`serve`, or a disposable
// one you started yourself with `bash scripts/run-server.sh` in another
// terminal). Point it elsewhere with E2E_BASE_URL.
export const BASE_URL = process.env.E2E_BASE_URL ?? "http://localhost:8080";

// Must belong to a real active administrator on the target instance. There
// is no safe default for a password, so this throws immediately (with a
// clear message) rather than limping along and failing confusingly later.
export const ADMIN_EMAIL = process.env.E2E_ADMIN_EMAIL ?? "admin@example.com";
export const ADMIN_PASSWORD = requireEnv("E2E_ADMIN_PASSWORD");

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(
      `${name} is required. Point this suite at a real admin account on the target server: ` +
        `E2E_BASE_URL=... E2E_ADMIN_EMAIL=... E2E_ADMIN_PASSWORD=... npm test\n` +
        `See tests/README.md.`,
    );
  }
  return value;
}

// A unique-per-run suffix so specs that create users/clients never collide
// with leftovers from a previous run against the same (possibly
// persistent, not disposable) target server.
export const RUN_ID = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;

// A relying-party origin that never resolves on the real network. Every
// request to it is intercepted and fulfilled locally by Playwright's route
// mocking (see fixtures/relying-party.ts) — no real server needed, and it
// exercises the exact browser-redirect behavior a real RP would see.
export const RELYING_PARTY_ORIGIN = "https://relying-party.test";
export const RELYING_PARTY_REDIRECT_URI = `${RELYING_PARTY_ORIGIN}/callback`;

// Used only by public-client-cors.spec.ts's browser-side fetch test. That
// test's callback page must genuinely fetch() the target server from a
// real browser security context — a page.route()-mocked response doesn't
// support that (confirmed empirically: Chromium blocks outbound fetch()
// from a fully synthetic response as "Failed to fetch"). fixtures/
// stub-callback-server.ts runs a real, minimal HTTP server on this fixed
// port instead. Fixed (not OS-assigned) because the target server's
// oidc.allowedOrigins allowlist is static configuration that can't know a
// randomly-chosen port in advance.
export const PUBLIC_CLIENT_PORT = 9999;
export const PUBLIC_CLIENT_ORIGIN = `http://127.0.0.1:${PUBLIC_CLIENT_PORT}`;
export const PUBLIC_CLIENT_REDIRECT_URI = `${PUBLIC_CLIENT_ORIGIN}/callback`;

export const AUTH_DIR = path.join(TESTS_DIR, ".auth");
export const ADMIN_STORAGE_STATE_PATH = path.join(AUTH_DIR, "admin-storage-state.json");
export const ADMIN_CSRF_PATH = path.join(AUTH_DIR, "admin-csrf.json");
