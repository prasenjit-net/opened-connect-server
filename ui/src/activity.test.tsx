import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "./context/AuthContext";
import { ToastProvider } from "./context/ToastContext";
import { api, ApiError, type User } from "./lib/api";
import { activityKinds, type ActivityOverview, type ActivityRecord } from "./lib/activity";
import { router } from "./router";

vi.mock("./context/ConfigContext", () => ({ useConfig: () => ({ ui: { appName: "Test App", defaultTheme: "auto" }, version: "1", startedAtMs: 0 }) }));
vi.mock("./context/ThemeContext", () => ({ useTheme: () => ({ mode: "light", setMode: vi.fn() }) }));
const admin: User = { id: "admin", name: "Admin", email: "admin@example.com", role: "admin", active: true, createdAt: "2026-01-01", updatedAt: "2026-01-01" };
const record: ActivityRecord = { id: "safe-record-id", kind: "tokens", status: "active", clientId: "portal", clientName: "Portal", userId: "alice", userEmail: "alice@example.com", scopes: ["openid", "profile"], createdAt: "2026-09-16T12:00:00Z", expiresAt: "2026-09-16T13:00:00Z", canRevoke: true };
const counts = { total: 12, active: 8, revoked: 2, expired: 1, completed: 1, consumed: 0 };
const overview: ActivityOverview = { generatedAt: "2026-09-16T12:00:00Z", protocolEnabled: true, users: 5, clients: 3, counts: { transactions: counts, codes: counts, tokens: counts, consents: counts, refresh: counts }, recent: [record] };
function setup(path: string) {
 const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
 const testRouter = createRouter({ routeTree: router.routeTree, history: createMemoryHistory({ initialEntries: [path] }) });
 render(<QueryClientProvider client={cache}><ToastProvider><AuthProvider><RouterProvider router={testRouter} /></AuthProvider></ToastProvider></QueryClientProvider>);
 return { cache, testRouter };
}
beforeEach(() => {
 vi.spyOn(api, "session").mockResolvedValue({ user: admin, csrfToken: "csrf", expiresAt: new Date(Date.now() + 3600000).toISOString() });
 vi.spyOn(api, "activity").mockImplementation(async (kind, params) => ({ records: [{ ...record, kind }], total: 11, page: params.page, pageSize: 10 }));
 vi.spyOn(api, "activityOverview").mockResolvedValue(overview);
 vi.spyOn(api, "revokeActivity").mockResolvedValue(undefined);
});
describe("admin activity monitoring", () => {
 it.each(activityKinds)("guards the %s page and hides activity links for regular users", async kind => {
  vi.mocked(api.session).mockResolvedValue({ user: { ...admin, role: "user" }, csrfToken: "csrf", expiresAt: new Date(Date.now() + 3600000).toISOString() });
  setup(`/activity/${kind}`);
  expect(await screen.findByRole("heading", { name: "Access denied" })).toBeInTheDocument();
  expect(api.activity).not.toHaveBeenCalled(); expect(api.activityOverview).not.toHaveBeenCalled();
  expect(within(screen.getByRole("navigation")).queryByRole("link", { name: "Activity" })).not.toBeInTheDocument();
 });
 it("shows overview counts and links to records", async () => {
  setup("/");
  expect(await screen.findByText("5 users")).toBeInTheDocument();
  expect(screen.getByText("3 clients")).toBeInTheDocument();
  expect(screen.getByText("OpenID Connect enabled")).toBeInTheDocument();
  expect(screen.getAllByText("8")).toHaveLength(5);
  await userEvent.click(screen.getByRole("link", { name: /Access tokens 8 active/ }));
  expect(await screen.findByLabelText("Search activity")).toBeInTheDocument();
  expect(api.activity).toHaveBeenCalledWith("tokens", { q: "", status: "", grantType: "", audience: "", page: 1 }, expect.any(AbortSignal));
 });
 it("filters only on submission and paginates with submitted values", async () => {
  setup("/activity/tokens");
  await screen.findByRole("link", { name: "Portal" });
  await userEvent.type(screen.getByLabelText("Search activity"), "Alice");
  await userEvent.selectOptions(screen.getByLabelText("Status"), "active");
  expect(api.activity).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole("button", { name: "Search" }));
  await waitFor(() => expect(api.activity).toHaveBeenLastCalledWith("tokens", { q: "Alice", status: "active", grantType: "", audience: "", page: 1 }, expect.any(AbortSignal)));
  await userEvent.type(screen.getByLabelText("Search activity"), " unsubmitted");
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
  await waitFor(() => expect(api.activity).toHaveBeenLastCalledWith("tokens", { q: "Alice", status: "active", grantType: "", audience: "", page: 2 }, expect.any(AbortSignal)));
  expect(await screen.findByText("11 records · Page 2 of 2 · 10 per page")).toBeInTheDocument();
 });
 it("confirms revocation and refreshes the list and dashboard cache", async () => {
  const { cache } = setup("/activity/tokens");
  cache.setQueryData(["activity-overview"], overview);
  await userEvent.click(await screen.findByRole("button", { name: "Revoke" }));
  expect(api.revokeActivity).not.toHaveBeenCalled();
  expect(screen.getByRole("dialog", { name: "Confirm revocation" })).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
  expect(api.revokeActivity).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Revoke" }));
  vi.mocked(api.activity).mockResolvedValue({ records: [{ ...record, status: "revoked", canRevoke: false }], total: 1, page: 1, pageSize: 10 });
  await userEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));
  expect(await screen.findByText("Revocation completed.")).toBeInTheDocument();
  expect(api.revokeActivity).toHaveBeenCalledWith("tokens", record.id);
  expect(await screen.findByText("revoked", { selector: "span" })).toBeInTheDocument();
  expect(cache.getQueryState(["activity-overview"])?.isInvalidated).toBe(true);
 });
 it("shows errors and allows retry without reporting a successful revocation", async () => {
  vi.mocked(api.revokeActivity).mockRejectedValue(new Error("Unable to revoke"));
  setup("/activity/consents");
  await userEvent.click(await screen.findByRole("button", { name: "Revoke" }));
  expect(screen.getByText(/future sign-in requires consent again/)).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Unable to revoke");
  expect(screen.queryByText("Revocation completed.")).not.toBeInTheDocument();
 });
 it("disables confirmation and refreshes when a record expires before revocation", async () => {
  vi.mocked(api.revokeActivity).mockRejectedValue(new ApiError("ACTIVITY_NOT_ACTIVE", 409, "Only active items can be revoked."));
  setup("/activity/tokens");
  await userEvent.click(await screen.findByRole("button", { name: "Revoke" }));
  vi.mocked(api.activity).mockResolvedValue({ records: [{ ...record, status: "expired", canRevoke: false }], total: 1, page: 1, pageSize: 10 });
  await userEvent.click(screen.getByRole("button", { name: "Confirm revoke" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Only active items can be revoked.");
  expect(screen.getByRole("button", { name: "Confirm revoke" })).toBeDisabled();
  await waitFor(() => expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument());
 });
 it.each(["consumed", "completed", "expired"])("does not offer revocation for %s records", async status => {
  vi.mocked(api.activity).mockResolvedValue({ records: [{ ...record, status, canRevoke: false }], total: 1, page: 1, pageSize: 10 });
  setup("/activity/tokens");
  await screen.findByRole("link", { name: "Portal" });
  expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
 });
 it("shows empty and failed loading states", async () => {
  vi.mocked(api.activity).mockResolvedValue({ records: [], total: 0, page: 1, pageSize: 10 });
  setup("/activity/codes");
  expect(await screen.findByText("No activity records match.")).toBeInTheDocument();
  vi.mocked(api.activity).mockRejectedValue(new Error("Activity unavailable"));
  await userEvent.click(screen.getByRole("button", { name: "Refresh" }));
  expect(await screen.findByRole("alert")).toHaveTextContent("Activity unavailable");
 });
 it("keeps the regular-user dashboard free of administrative requests", async () => {
  vi.mocked(api.session).mockResolvedValue({ user: { ...admin, role: "user" }, csrfToken: "csrf", expiresAt: new Date(Date.now() + 3600000).toISOString() });
  setup("/");
  expect(await screen.findByText("Manage your profile and account security.")).toBeInTheDocument();
  expect(api.activityOverview).not.toHaveBeenCalled();
 });
});
