import fs from "node:fs";
import { AUTH_DIR } from "./fixtures/constants";

// The disposable server process itself is stopped by Playwright's
// webServer lifecycle; this just clears the saved admin session so a
// stale cookie/CSRF pair is never accidentally reused against a future,
// differently-provisioned server instance.
export default async function globalTeardown() {
  fs.rmSync(AUTH_DIR, { recursive: true, force: true });
}
