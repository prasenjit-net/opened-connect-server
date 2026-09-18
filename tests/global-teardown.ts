import fs from "node:fs";
import { AUTH_DIR } from "./fixtures/constants";

// The target server is managed externally and is left running.
// This clears the saved admin session so a
// stale cookie/CSRF pair is never accidentally reused against a future,
// differently-provisioned server instance.
export default async function globalTeardown() {
  fs.rmSync(AUTH_DIR, { recursive: true, force: true });
}
