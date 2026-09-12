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
export interface User {
  id: string; name: string; email: string; role: Role; active: boolean;
  createdAt: string; updatedAt: string;
}
export interface Session { user: User; csrfToken: string; expiresAt: string; }
export interface UserInput { name: string; email: string; role: Role; active: boolean; }
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
  session: () => request<Session>("/api/auth/session"),
  login: (email: string, password: string) => request<Session>("/api/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  logout: () => request<void>("/api/auth/logout", { method: "POST", body: "{}" }),
  updateProfile: (name: string) => request<User>("/api/profile", { method: "PUT", body: JSON.stringify({ name }) }),
  changePassword: (currentPassword: string, newPassword: string) => request<void>("/api/profile/password", { method: "POST", body: JSON.stringify({ currentPassword, newPassword }) }),
  users: (params: { q: string; role: string; status: string; page: number }) => request<UserList>(`/api/users?${new URLSearchParams({ ...params, page: String(params.page), pageSize: "20" })}`),
  createUser: (input: UserInput & { password: string }) => request<User>("/api/users", { method: "POST", body: JSON.stringify(input) }),
  updateUser: (id: string, input: UserInput) => request<User>(`/api/users/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(input) }),
  deleteUser: (id: string) => request<void>(`/api/users/${encodeURIComponent(id)}`, { method: "DELETE", body: "{}" }),
  config: () => request<ServerConfig>("/api/config"),
  health: () => request<{ status: string; version: string }>("/api/health"),
};
