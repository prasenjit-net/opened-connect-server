import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "./context/AuthContext";
import { ToastProvider } from "./context/ToastContext";
import { api, ApiError, type Session, type User } from "./lib/api";
import { safeRedirect } from "./lib/navigation";
import NotFoundPage from "./pages/NotFound";
import { router } from "./router";

vi.mock("./context/ConfigContext", () => ({ useConfig: () => ({ ui: { appName: "Test App", defaultTheme: "auto" }, version: "1", startedAtMs: 0 }) }));
vi.mock("./context/ThemeContext", () => ({ useTheme: () => ({ mode: "light", setMode: vi.fn() }) }));
const admin: User = { id: "admin", name: "Admin", email: "admin@example.com", role: "admin", active: true, createdAt: "2026-01-01", updatedAt: "2026-01-01" };
const regular: User = { ...admin, id: "regular", name: "Regular", email: "regular@example.com", role: "user" };
function session(user: User): Session { return { user, csrfToken: "test-csrf", expiresAt: new Date(Date.now() + 3_600_000).toISOString() }; }
function setup(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const testRouter = createRouter({ routeTree: router.routeTree, history: createMemoryHistory({ initialEntries: [path] }), defaultNotFoundComponent: NotFoundPage });
  render(<QueryClientProvider client={client}><ToastProvider><AuthProvider><RouterProvider router={testRouter} /></AuthProvider></ToastProvider></QueryClientProvider>);
  return { client, testRouter };
}
beforeEach(() => {
  vi.spyOn(api, "session").mockResolvedValue(session(admin));
  vi.spyOn(api, "users").mockResolvedValue({ users: [admin, regular], total: 2, page: 1, pageSize: 20 });
});

describe("authentication UI", () => {
  it("guards deep links and returns to the requested page after form login", async () => {
    vi.mocked(api.session).mockRejectedValue(new ApiError("UNAUTHORIZED", 401, "Sign in"));
    const login = vi.spyOn(api, "login").mockResolvedValue(session(admin));
    const { testRouter } = setup("/users");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(api.users).not.toHaveBeenCalled();
    await userEvent.type(screen.getByLabelText("Email"), admin.email);
    await userEvent.type(screen.getByLabelText("Password"), "a long safe password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("button", { name: "Add user" })).toBeInTheDocument();
    expect(login).toHaveBeenCalledWith(admin.email, "a long safe password");
    expect(testRouter.state.location.pathname).toBe("/users");
    expect(window.localStorage.length).toBe(0);
  });
  it("prevents regular users from opening or fetching admin data", async () => {
    vi.mocked(api.session).mockResolvedValue(session(regular));
    setup("/users");
    expect(await screen.findByRole("heading", { name: "Access denied" })).toBeInTheDocument();
    expect(api.users).not.toHaveBeenCalled();
    expect(within(screen.getByRole("navigation")).queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
  });
  it("clears private cached data when the server rejects the session", async () => {
    const { client } = setup("/users");
    await screen.findByRole("button", { name: "Add user" });
    await act(async () => { window.dispatchEvent(new Event("session-expired")); });
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(client.getQueriesData({ queryKey: ["users"] })).toEqual([]);
  });
  it("rejects unsafe redirect targets", () => {
    for (const target of ["//evil.example", "https://evil.example", "/\\evil.example", "/login", "/\nevil"]) expect(safeRedirect(target)).toBe("/");
    expect(safeRedirect("/profile?tab=password")).toBe("/profile?tab=password");
  });
});

describe("account screens", () => {
  it("searches and creates a user with the default user role", async () => {
    const create = vi.spyOn(api, "createUser").mockResolvedValue(regular);
    setup("/users");
    await screen.findByRole("button", { name: "Add user" });
    await userEvent.type(screen.getByLabelText("Search users"), "regular");
    await userEvent.click(screen.getByRole("button", { name: "Search" }));
    expect(api.users).toHaveBeenLastCalledWith({ q: "regular", role: "", status: "", page: 1 });
    await userEvent.click(screen.getByRole("button", { name: "Add user" }));
    await userEvent.type(screen.getByLabelText("Name", { exact: true }), "New User");
    await userEvent.type(screen.getByLabelText("Email", { exact: true }), "new@example.com");
    await userEvent.type(screen.getByLabelText(/Initial password/), "a long safe password");
    await userEvent.click(screen.getByRole("button", { name: "Create user" }));
    expect(create).toHaveBeenCalledWith({ name: "New User", email: "new@example.com", password: "a long safe password", active: true, role: "user" });
    expect(await screen.findByText("User created.")).toBeInTheDocument();
  });
  it("updates a user's role and requires confirmation before deletion", async () => {
    const update = vi.spyOn(api, "updateUser").mockResolvedValue({ ...regular, role: "admin" });
    const remove = vi.spyOn(api, "deleteUser").mockResolvedValue(undefined);
    setup("/users");
    await userEvent.click(await screen.findByRole("button", { name: `Edit ${regular.email}` }));
    await userEvent.selectOptions(screen.getByLabelText("Role", { exact: true }), "admin");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(update).toHaveBeenCalledWith(regular.id, { name: regular.name, email: regular.email, role: "admin", active: true });
    await userEvent.click(await screen.findByRole("button", { name: `Delete ${regular.email}` }));
    expect(remove).not.toHaveBeenCalled();
    await userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Confirm delete" }));
    expect(remove).toHaveBeenCalledWith(regular.id);
  });
  it("updates the profile and signs out after a password change", async () => {
    const update = vi.spyOn(api, "updateProfile").mockResolvedValue({ ...admin, name: "Updated" });
    const change = vi.spyOn(api, "changePassword").mockResolvedValue(undefined);
    setup("/profile");
    await screen.findByRole("heading", { name: "Change password" });
    await userEvent.clear(screen.getByLabelText("Name"));
    await userEvent.type(screen.getByLabelText("Name"), "Updated");
    await userEvent.click(screen.getByRole("button", { name: "Save profile" }));
    expect(update).toHaveBeenCalledWith("Updated");
    await userEvent.type(screen.getByLabelText("Current password"), "old long password");
    await userEvent.type(screen.getByLabelText("New password", { exact: true }), "new long password");
    await userEvent.type(screen.getByLabelText("Confirm new password"), "new long password");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(change).toHaveBeenCalledWith("old long password", "new long password");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});
