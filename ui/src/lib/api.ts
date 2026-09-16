import type { ActivityKind, ActivityList, ActivityOverview } from "./activity";
import type { ClientMetadata, ClientList, ClientResult, OIDCClient } from "./clients";
import type { TransactionView } from "./oidc";
export interface UiConfig {
  appName: string;
  tagline: string;
  defaultTheme: "light" | "dark" | "auto";
  repoUrl?: string | null;
}

export interface ServerConfig {
  ui: UiConfig;
  version: string;
  startedAtMs: number;
}

export type Role = "user" | "admin";
export interface ProfileClaims {
 given_name?: string; family_name?: string; middle_name?: string; nickname?: string;
 preferred_username?: string; profile?: string; picture?: string; website?: string;
 gender?: string; birthdate?: string; zoneinfo?: string; locale?: string; phone_number?: string;
 address?: { formatted?: string; street_address?: string; locality?: string; region?: string; postal_code?: string; country?: string };
 custom_attributes?: Record<string, unknown>;
}
export interface ProfileInput extends ProfileClaims { name: string; email: string; }
export interface User extends ProfileClaims {
 sub?: string; updated_at?: number; email_verified?: boolean; phone_number_verified?: boolean;
  id: string; name: string; email: string; role: Role; active: boolean;
  createdAt: string; updatedAt: string;
}
export interface Session { user: User; csrfToken: string; expiresAt: string; }
export interface UserInput extends ProfileClaims { email_verified?: boolean; phone_number_verified?: boolean; name: string; email: string; role: Role; active: boolean; }
export interface UserList { users: User[]; total: number; page: number; pageSize: number; }
let csrfToken: string | null = null;
export function setCSRFToken(token: string | null) { csrfToken = token; }

export class ApiError extends Error {
  readonly code: string;
  readonly status: number;

  constructor(code: string, status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      ...init,
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
        ...(csrfToken && init?.method && init.method !== "GET" ? { "X-CSRF-Token": csrfToken } : {}),
        ...(init?.headers as Record<string, string> | undefined),
      },
    });
  } catch {
    throw new ApiError("NETWORK", 0, "Cannot reach the server");
  }

  if (!res.ok) {
    // Prefer the backend's { error: { code, message } } envelope.
    let code = `HTTP_${res.status}`;
    let message = res.statusText || "Request failed";
    try {
      const body = (await res.json()) as {
        error?: { code?: string; message?: string };
      };
      if (body.error) {
        code = body.error.code ?? code;
        message = body.error.message ?? message;
      }
    } catch {
      /* body was not JSON — keep the status text */
    }
    if (res.status === 401 && path !== "/api/auth/login" && path !== "/api/auth/session") {
      window.dispatchEvent(new Event("session-expired"));
    }
    throw new ApiError(code, res.status, message);
  }

  if (res.status === 204) {
    return undefined as T;
  }
  return (await res.json()) as T;
}

export const api = {
  activity: (kind: ActivityKind, params: { q: string; status: string; page: number }, signal?: AbortSignal) => request<ActivityList>(`/api/admin/activity/${kind}?${new URLSearchParams({ ...params, page: String(params.page) })}`, { signal }),
  activityOverview: (signal?: AbortSignal) => request<ActivityOverview>("/api/admin/activity/overview", { signal }),
  revokeActivity: (kind: ActivityKind, id: string) => request<void>(`/api/admin/activity/${kind}/${encodeURIComponent(id)}/revoke`, { method: "POST", body: "{}" }),
  clients: (params: { q: string; page: number }, signal?: AbortSignal) => request<ClientList>(`/api/admin/clients?${new URLSearchParams({ q: params.q, page: String(params.page) })}`, { signal }),
  client: (id: string) => request<OIDCClient>(`/api/admin/clients/${encodeURIComponent(id)}`),
  createClient: (input: ClientMetadata) => request<ClientResult>("/api/admin/clients", { method: "POST", body: JSON.stringify(input) }),
  updateClient: (id: string, input: ClientMetadata) => request<ClientResult>(`/api/admin/clients/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(input) }),
  deleteClient: (id: string) => request<void>(`/api/admin/clients/${encodeURIComponent(id)}`, { method: "DELETE", body: "{}" }),
  rotateClientSecret: (id: string) => request<ClientResult>(`/api/admin/clients/${encodeURIComponent(id)}/secret`, { method: "POST", body: "{}" }),
  session: () => request<Session>("/api/auth/session"),
  login: (email: string, password: string) => request<Session>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => request<void>("/api/auth/logout", { method: "POST", body: "{}" }),
  updateProfile: (input: ProfileInput) => request<User>("/api/user/profile", { method: "PUT", body: JSON.stringify(input) }),
  changePassword: (currentPassword: string, newPassword: string) => request<void>("/api/user/profile/password", { method: "POST", body: JSON.stringify({ currentPassword, newPassword }) }),
  users: (params: { q: string; role: string; status: string; page: number }, signal?: AbortSignal) => request<UserList>(`/api/admin/users?${new URLSearchParams({ ...params, page: String(params.page), pageSize: "10" })}`, { signal }),
  user: (id: string) => request<User>(`/api/admin/users/${encodeURIComponent(id)}`),
  createUser: (input: UserInput & { password: string }) => request<User>("/api/admin/users", { method: "POST", body: JSON.stringify(input) }),
  updateUser: (id: string, input: UserInput) => request<User>(`/api/admin/users/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(input) }),
  deleteUser: (id: string) => request<void>(`/api/admin/users/${encodeURIComponent(id)}`, { method: "DELETE", body: "{}" }),
  config: () => request<ServerConfig>("/api/public/config"),
  health: () => request<{ status: string; version: string }>("/api/public/health"),
  authorization: (id: string) => request<TransactionView>(`/api/user/authorization/${encodeURIComponent(id)}`),
  decideAuthorization: (id: string, input: { approve: boolean; scopes: string[] }) => request<TransactionView>(`/api/user/authorization/${encodeURIComponent(id)}/decision`, { method: "POST", body: JSON.stringify(input) }),
};
