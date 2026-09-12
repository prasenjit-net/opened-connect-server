import { afterEach, describe, expect, it, vi } from "vitest";
import { api, ApiError } from "./api";

function mockFetchOnce(response: Partial<Response> & { json?: () => Promise<unknown> }) {
  const fetchMock = vi.fn().mockResolvedValue(response as Response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api client", () => {
  it("returns parsed JSON on a successful response", async () => {
    mockFetchOnce({
      ok: true,
      status: 200,
      json: () => Promise.resolve({ status: "ok", version: "0.1.0" }),
    });
    const result = await api.health();
    expect(result).toEqual({ status: "ok", version: "0.1.0" });
  });

  it("throws ApiError built from the backend's error envelope", async () => {
    mockFetchOnce({
      ok: false,
      status: 400,
      statusText: "Bad Request",
      json: () =>
        Promise.resolve({
          error: { code: "BAD_REQUEST", message: "health check failed" },
        }),
    });

    await expect(api.health()).rejects.toMatchObject({
      name: "ApiError",
      code: "BAD_REQUEST",
      status: 400,
      message: "health check failed",
    });
  });

  it("falls back to the HTTP status when the error body isn't JSON", async () => {
    mockFetchOnce({
      ok: false,
      status: 500,
      statusText: "Internal Server Error",
      json: () => Promise.reject(new Error("not json")),
    });

    await expect(api.health()).rejects.toMatchObject({
      code: "HTTP_500",
      status: 500,
      message: "Internal Server Error",
    });
  });

  it("wraps a network failure as a NETWORK ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new TypeError("Failed to fetch")),
    );

    await expect(api.health()).rejects.toBeInstanceOf(ApiError);
    await expect(api.health()).rejects.toMatchObject({ code: "NETWORK", status: 0 });
  });
});

it("uses the public, auth, user, and admin API groups", async () => {
 const fetch = mockFetchOnce({ ok: true, status: 204 });
 await api.config();
 await api.health();
 await api.session();
 await api.login("user@example.com","password");
 await api.logout();
 await api.updateProfile({ name:"User",email:"user@example.com" });
 await api.changePassword("old","new");
 await api.users({ q:"",role:"",status:"",page:1 });
 await api.user("user-id");
 await api.createUser({ name:"User",email:"user@example.com",role:"user",active:true,password:"password" });
 await api.updateUser("user-id",{ name:"User",email:"user@example.com",role:"user",active:true });
 await api.deleteUser("user-id");
 await api.clients({ q:"",page:1 });
 await api.client("client-id");
 await api.createClient({ redirect_uris:["https://example.com/callback"] });
 await api.updateClient("client-id",{ redirect_uris:["https://example.com/callback"] });
 await api.deleteClient("client-id");
 await api.rotateClientSecret("client-id");
 expect(fetch.mock.calls.map(([path]) => String(path).split("?")[0])).toEqual([
  "/api/public/config","/api/public/health","/api/auth/session","/api/auth/login","/api/auth/logout",
  "/api/user/profile","/api/user/profile/password",
  "/api/admin/users","/api/admin/users/user-id","/api/admin/users","/api/admin/users/user-id","/api/admin/users/user-id",
  "/api/admin/clients","/api/admin/clients/client-id","/api/admin/clients","/api/admin/clients/client-id","/api/admin/clients/client-id","/api/admin/clients/client-id/secret",
 ]);
});
