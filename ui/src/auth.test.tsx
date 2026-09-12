import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
  vi.spyOn(api, "user").mockResolvedValue(regular);
  vi.spyOn(api, "users").mockResolvedValue({ users: [admin, regular], total: 2, page: 1, pageSize: 10 });
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
    expect(await screen.findByRole("link", { name: "Add user" })).toBeInTheDocument();
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
    await screen.findByRole("link", { name: "Add user" });
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
    const { testRouter } = setup("/users");
    await screen.findByRole("link", { name: "Add user" });
    expect(api.users).not.toHaveBeenCalled();
    await userEvent.type(screen.getByLabelText("Search users"), "regular");
    expect(api.users).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole("button", { name: "Search" }));
    expect(api.users).toHaveBeenLastCalledWith({ q: "regular", role: "", status: "", page: 1 }, expect.any(AbortSignal));
    await userEvent.click(screen.getByRole("link", { name: "Add user" }));
    await userEvent.type(screen.getByLabelText("Name", { exact: true }), "New User");
    await userEvent.type(screen.getByLabelText("Email", { exact: true }), "new@example.com");
    await userEvent.type(screen.getByLabelText(/Initial password/), "a long safe password");
    await userEvent.click(screen.getByRole("button", { name: "Create user" }));
    expect(create).toHaveBeenCalledWith(expect.objectContaining({ name: "New User", email: "new@example.com", password: "a long safe password", active: true, role: "user" }));
    expect(await screen.findByText("User created.")).toBeInTheDocument();
    await waitFor(() => expect(testRouter.state.location.pathname).toBe("/users/regular"));
    await act(async () => { testRouter.history.back(); });
    expect(await screen.findByLabelText("Search users")).toHaveValue("regular");
    expect(await screen.findByRole("link", { name: "Regular" })).toBeInTheDocument();
    expect(api.users).toHaveBeenCalledTimes(1);
  });
  it("updates a user's role and requires confirmation before deletion", async () => {
    const update = vi.spyOn(api, "updateUser").mockResolvedValue({ ...regular, role: "admin" });
    const remove = vi.spyOn(api, "deleteUser").mockResolvedValue(undefined);
    setup("/users/regular");
    await screen.findByRole("heading", { name: "Edit user" });
    await userEvent.selectOptions(screen.getByLabelText("Role", { exact: true }), "admin");
    await userEvent.click(screen.getByRole("button", { name: "Save changes" }));
    expect(update).toHaveBeenCalledWith(regular.id, expect.objectContaining({ name: regular.name, email: regular.email, role: "admin", active: true }));
    await userEvent.click(await screen.findByRole("button", { name: "Delete user" }));
    expect(remove).not.toHaveBeenCalled();
    await userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Confirm delete" }));
    expect(remove).toHaveBeenCalledWith(regular.id);
  });
  it("preserves page, drafts, and results when returning from detail without another search", async () => {
    vi.mocked(api.users)
      .mockResolvedValueOnce({ users: [admin], total: 11, page: 1, pageSize: 10 })
      .mockResolvedValueOnce({ users: [regular], total: 11, page: 2, pageSize: 10 });
    setup("/users");
    await userEvent.type(await screen.findByLabelText("Search users"), "submitted");
    await userEvent.click(screen.getByRole("button", { name: "Search" }));
    await screen.findByRole("link", { name: "admin@example.com" });
    await userEvent.clear(screen.getByLabelText("Search users"));
    await userEvent.type(screen.getByLabelText("Search users"), "unsent draft");
    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(api.users).toHaveBeenLastCalledWith({ q: "submitted", role: "", status: "", page: 2 }, expect.any(AbortSignal));
    await userEvent.click(await screen.findByRole("link", { name: "Regular" }));
    await screen.findByRole("heading", { name: "Edit user" });
    await userEvent.click(screen.getByRole("link", { name: /Back to user search/ }));
    expect(await screen.findByLabelText("Search users")).toHaveValue("unsent draft");
    expect(screen.getByRole("link", { name: "Regular" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    expect(api.users).toHaveBeenCalledTimes(2);
  });
  it("lets regular users edit their own claims without showing administrative controls", async () => {
    vi.mocked(api.session).mockResolvedValue(session(regular));
    const update = vi.spyOn(api, "updateProfile").mockResolvedValue(regular);
    setup("/profile");
    await userEvent.type(await screen.findByLabelText("Given name"), "Alice");
    const custom = screen.getByLabelText(/Custom attributes \(JSON\)/);
    await userEvent.clear(custom);
    fireEvent.change(custom, { target: { value: '{"department":"Research","enabled":true}' } });
    await userEvent.click(screen.getByRole("button", { name: "Save profile" }));
    expect(update).toHaveBeenCalledWith(expect.objectContaining({ given_name: "Alice", custom_attributes: { department: "Research", enabled: true } }));
    expect(update.mock.calls[0][0]).not.toHaveProperty("role");
    expect(update.mock.calls[0][0]).not.toHaveProperty("email_verified");
    expect(within(screen.getByRole("navigation")).queryByRole("link", { name: "Users" })).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Email verified")).not.toBeInTheDocument();
    expect(api.users).not.toHaveBeenCalled();
  });
  it("updates the profile and signs out after a password change", async () => {
    const update = vi.spyOn(api, "updateProfile").mockResolvedValue({ ...admin, name: "Updated" });
    const change = vi.spyOn(api, "changePassword").mockResolvedValue(undefined);
    setup("/profile");
    await screen.findByRole("heading", { name: "Change password" });
    await userEvent.clear(screen.getByLabelText("Name"));
    await userEvent.type(screen.getByLabelText("Name"), "Updated");
    await userEvent.click(screen.getByRole("button", { name: "Save profile" }));
    expect(update).toHaveBeenCalledWith(expect.objectContaining({ name: "Updated", email: admin.email }));
    await userEvent.type(screen.getByLabelText("Current password"), "old long password");
    await userEvent.type(screen.getByLabelText("New password", { exact: true }), "new long password");
    await userEvent.type(screen.getByLabelText("Confirm new password"), "new long password");
    await userEvent.click(screen.getByRole("button", { name: "Change password" }));
    expect(change).toHaveBeenCalledWith("old long password", "new long password");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
  });
});
