import { defineConfig, devices } from "@playwright/test";
import { BASE_URL } from "./fixtures/constants";

// Manual-only e2e suite: never run by CI, and never starts a server
// itself — it targets whatever instance is already running at BASE_URL.
// Start one yourself first (your own `make dev`/`serve`, or a disposable
// instance via `bash scripts/run-server.sh` in another terminal). See
// tests/README.md.
//
// Tests share whatever server/identity store is already running, so they
// run serially and each spec provisions its own OIDC client(s) (and, where
// needed, its own uniquely-named user) to stay isolated from other spec
// files and from previous runs.
export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [["html", { open: "never" }], ["list"]],
  globalSetup: "./global-setup.ts",
  globalTeardown: "./global-teardown.ts",
  use: {
    baseURL: BASE_URL,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
  ],
});
