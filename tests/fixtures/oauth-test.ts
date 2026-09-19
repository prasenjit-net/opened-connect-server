import { test as base } from "@playwright/test";
import { AdminClient } from "./admin-client";
import type { OAuthSettings } from "./oauth";
export { expect } from "@playwright/test";
export const test = base.extend<{ admin: AdminClient; settings: OAuthSettings }>({
  admin: async ({}, use) => {
    const admin = await AdminClient.create();
    try { await use(admin); } finally { await admin.dispose(); }
  },
  settings: async ({ admin }, use) => { await use(await admin.oauthSettings()); },
});
