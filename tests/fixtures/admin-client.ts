import type { OAuthPolicy, OAuthSettings } from "./oauth";
import { request, type APIRequestContext } from "@playwright/test";
import fs from "node:fs";
import { ADMIN_CSRF_PATH, ADMIN_STORAGE_STATE_PATH, BASE_URL } from "./constants";

export interface ClientView {
  client_id: string;
  client_secret?: string;
  has_client_secret: boolean;
  protocol_compatible: boolean;
  [key: string]: unknown;
}

export interface InitialAccessTokenResult {
  credential: { id: string; label: string; status: string; [key: string]: unknown };
  token: string; // "iat_..."
}

export interface ActivityRecord {
  id: string;
  kind: string;
  status: string;
  clientId: string;
  clientName: string;
  userId?: string;
  scopes: string[];
  [key: string]: unknown;
}

/**
 * A thin wrapper around the admin management API, authenticated with the
 * session global-setup.ts already established. Each spec file should build
 * its own AdminClient and register whatever OIDC clients/tokens it needs —
 * specs must not assume another spec file's fixtures still exist.
 */
export class AdminClient {
  private readonly ownedClients = new Set<string>();
  private readonly ownedUsers = new Set<string>();
  private readonly ownedInitialTokens = new Set<string>();

  private constructor(
    private readonly ctx: APIRequestContext,
    private readonly csrfToken: string,
  ) {}

  static async create(): Promise<AdminClient> {
    const { csrfToken } = JSON.parse(fs.readFileSync(ADMIN_CSRF_PATH, "utf-8")) as { csrfToken: string };
    const ctx = await request.newContext({ baseURL: BASE_URL, storageState: ADMIN_STORAGE_STATE_PATH });
    return new AdminClient(ctx, csrfToken);
  }

  async dispose() {
    const failures: string[] = [];
    try {
      for (const id of this.ownedInitialTokens) {
        const res = await this.ctx.post(`/api/admin/registration-tokens/${encodeURIComponent(id)}/revoke`, { headers: this.headers(), data: {} });
        // Consumed/expired invitations have no remaining registration authority.
        if (![204, 404, 409].includes(res.status())) failures.push(`registration token ${id}: ${res.status()}`);
      }
      for (const [kind, ids] of [["clients", this.ownedClients], ["users", this.ownedUsers]] as const) {
        for (const id of ids) {
          const res = await this.ctx.delete(`/api/admin/${kind}/${encodeURIComponent(id)}`, { headers: this.headers() });
          if (![204, 404].includes(res.status())) failures.push(`${kind}/${id}: ${res.status()}`);
        }
      }
    } finally { await this.ctx.dispose(); }
    if (failures.length) throw new Error(`Test fixture cleanup failed: ${failures.join(", ")}`);
  }

  private headers() {
    return { "Content-Type": "application/json", "X-CSRF-Token": this.csrfToken };
  }

  /** Registers a client through the admin API — the deterministic setup
   * path that works regardless of oidc.registrationEnabled. */
  async createUser(input: { name: string; email: string; password: string; role?: "user" | "admin" }): Promise<{ id: string; email: string }> {
    const res = await this.ctx.post("/api/admin/users", {
      headers: this.headers(),
      data: { name: input.name, email: input.email, password: input.password, role: input.role ?? "user", active: true },
    });
    if (res.status() !== 201) throw new Error(`createUser failed: ${res.status()} ${await res.text()}`);
    const user = await res.json() as { id: string; email: string };
    this.ownedUsers.add(user.id);
    return user;
  }

  /** Only adopt a client returned by this test's successful /register call. */
  trackRegisteredClient(id: string) { this.ownedClients.add(id); }

  async createClient(metadata: Record<string, unknown>): Promise<ClientView> {
    const res = await this.ctx.post("/api/admin/clients", { headers: this.headers(), data: metadata });
    if (res.status() !== 201) throw new Error(`createClient failed: ${res.status()} ${await res.text()}`);
    const client = await res.json() as ClientView;
    this.ownedClients.add(client.client_id);
    return client;
  }

  async updateClient(clientId: string, metadata: Record<string, unknown>): Promise<ClientView> {
    const res = await this.ctx.put(`/api/admin/clients/${encodeURIComponent(clientId)}`, { headers: this.headers(), data: metadata });
    if (res.status() !== 200) throw new Error(`updateClient failed: ${res.status()} ${await res.text()}`);
    return (await res.json()) as ClientView;
  }

  async deleteClient(clientId: string): Promise<void> {
    const res = await this.ctx.delete(`/api/admin/clients/${encodeURIComponent(clientId)}`, { headers: this.headers() });
    if (res.status() !== 204) throw new Error(`deleteClient failed: ${res.status()} ${await res.text()}`);
  }

  async oauthSettings(): Promise<OAuthSettings> {
    const res = await this.ctx.get("/api/admin/oauth");
    if (res.status() !== 200) throw new Error(`OAuth settings failed: ${res.status()} ${await res.text()}`);
    return res.json();
  }

  async setOAuthPolicy(id: string, policy: OAuthPolicy): Promise<void> {
    const res = await this.ctx.put(`/api/admin/clients/${encodeURIComponent(id)}/oauth-policy`, { headers: this.headers(), data: policy });
    if (res.status() !== 200) throw new Error(`OAuth policy failed: ${res.status()} ${await res.text()}`);
  }

  async setOAuthAccess(id: string, access: Record<string, string[]>): Promise<void> {
    const res = await this.ctx.put(`/api/admin/users/${encodeURIComponent(id)}/oauth-access`, { headers: this.headers(), data: access });
    if (res.status() !== 200) throw new Error(`OAuth access failed: ${res.status()} ${await res.text()}`);
  }

  async registrationSettings(): Promise<{ enabled: boolean; endpoint?: string }> {
    const res = await this.ctx.get("/api/admin/registration");
    if (res.status() !== 200) throw new Error(`registrationSettings failed: ${res.status()} ${await res.text()}`);
    return (await res.json()) as { enabled: boolean; endpoint?: string };
  }

  async issueInitialAccessToken(input: { label: string; maxUses?: number; lifetimeHours?: number }): Promise<InitialAccessTokenResult> {
    const res = await this.ctx.post("/api/admin/registration-tokens", { headers: this.headers(), data: input });
    if (res.status() !== 201) throw new Error(`issueInitialAccessToken failed: ${res.status()} ${await res.text()}`);
    const result = await res.json() as InitialAccessTokenResult;
    this.ownedInitialTokens.add(result.credential.id);
    return result;
  }

  async issueClientRegistrationToken(clientId: string): Promise<string> {
    const res = await this.ctx.post(`/api/admin/clients/${encodeURIComponent(clientId)}/registration-token`, { headers: this.headers(), data: {} });
    if (res.status() !== 201) throw new Error(`issueClientRegistrationToken failed: ${res.status()} ${await res.text()}`);
    const body = (await res.json()) as { token: string };
    return body.token;
  }

  async activityOverview(): Promise<Record<string, unknown>> {
    const res = await this.ctx.get("/api/admin/activity/overview");
    if (res.status() !== 200) throw new Error(`activityOverview failed: ${res.status()} ${await res.text()}`);
    return res.json();
  }

  async listActivity(kind: "transactions" | "codes" | "tokens" | "consents" | "refresh", query: Record<string, string> = {}): Promise<{ records: ActivityRecord[]; [key: string]: unknown }> {
    const qs = new URLSearchParams(query).toString();
    const res = await this.ctx.get(`/api/admin/activity/${kind}${qs ? `?${qs}` : ""}`);
    if (res.status() !== 200) throw new Error(`listActivity(${kind}) failed: ${res.status()} ${await res.text()}`);
    return res.json();
  }

  async revokeActivity(kind: "transactions" | "codes" | "tokens" | "consents" | "refresh", id: string): Promise<void> {
    const res = await this.ctx.post(`/api/admin/activity/${kind}/${encodeURIComponent(id)}/revoke`, { headers: this.headers(), data: {} });
    if (res.status() !== 204) throw new Error(`revokeActivity(${kind}, ${id}) failed: ${res.status()} ${await res.text()}`);
  }
}
