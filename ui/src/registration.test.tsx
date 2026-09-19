import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "./context/AuthContext";
import { ToastProvider } from "./context/ToastContext";
import { api, ApiError } from "./lib/api";
import { router } from "./router";
import type { InitialToken } from "./lib/registration";

vi.mock("./context/ConfigContext", () => ({ useConfig: () => ({ ui: { appName: "Test App", defaultTheme: "auto" }, version: "1", startedAtMs: 0 }) }));
vi.mock("./context/ThemeContext", () => ({ useTheme: () => ({ mode: "light", setMode: vi.fn() }) }));
const invitation: InitialToken = { id: "invitation-id", label: "Developer", issuedBy: "admin", issuedAt: "2026-01-01", expiresAt: "2099-01-01", maxUses: 1, uses: 0, status: "active" };
function setup(path = "/activity/initial-access-tokens") {
 const cache = new QueryClient({ defaultOptions: { queries: { retry: false } } });
 const testRouter = createRouter({ routeTree: router.routeTree, history: createMemoryHistory({ initialEntries: [path] }) });
 render(<QueryClientProvider client={cache}><ToastProvider><AuthProvider><RouterProvider router={testRouter} /></AuthProvider></ToastProvider></QueryClientProvider>);
 return cache;
}
beforeEach(() => {
 Object.defineProperty(HTMLDialogElement.prototype, "showModal", { configurable: true, value: function(this: HTMLDialogElement) { this.setAttribute("open", ""); } });
 Object.defineProperty(HTMLDialogElement.prototype, "close", { configurable: true, value: function(this: HTMLDialogElement) { this.removeAttribute("open"); } });
 vi.spyOn(api, "session").mockResolvedValue({ user: { id: "admin", name: "Admin", email: "admin@example.com", role: "admin", active: true, createdAt: "2026-01-01", updatedAt: "2026-01-01" }, csrfToken: "csrf", expiresAt: "2099-01-01" });
 vi.spyOn(api, "registrationSettings").mockResolvedValue({ enabled: true, endpoint: "https://issuer.example/register" });
 vi.spyOn(api, "registrationTokens").mockResolvedValue({ tokens: [invitation], total: 1, page: 1, pageSize: 10 });
});
describe("dynamic registration administration", () => {
 it("loads the initial page automatically, applies search on submission, paginates, and confirms revocation", async () => {
  vi.mocked(api.registrationTokens).mockResolvedValueOnce({ tokens: [invitation], total: 11, page: 1, pageSize: 10 }).mockResolvedValueOnce({ tokens: [invitation], total: 11, page: 1, pageSize: 10 }).mockResolvedValueOnce({ tokens: [invitation], total: 11, page: 2, pageSize: 10 });
  const revoke = vi.spyOn(api, "revokeRegistrationToken").mockResolvedValue(undefined);
  setup(); await screen.findByText("Developer");
  expect(api.registrationTokens).toHaveBeenCalledWith("", 1);
  await userEvent.type(screen.getByLabelText("Search tokens"), "Developer"); expect(api.registrationTokens).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole("button", { name: "Search" })); await screen.findByText("Developer");
  await userEvent.type(screen.getByLabelText("Search tokens"), " unsubmitted");
  await userEvent.click(screen.getByRole("button", { name: "Next" }));
  await waitFor(() => expect(api.registrationTokens).toHaveBeenLastCalledWith("Developer", 2));
  await userEvent.click(screen.getByRole("button", { name: "Revoke" })); expect(revoke).not.toHaveBeenCalled();
  await userEvent.click(within(screen.getByRole("alertdialog")).getByRole("button", { name: "Confirm revocation" }));
  await waitFor(() => expect(revoke).toHaveBeenCalledWith(invitation.id));
 });
 it("shows newly issued tokens once without retaining them in the query cache", async () => {
  const issue = vi.spyOn(api, "issueRegistrationToken").mockResolvedValue({ credential: invitation, token: "iat_one-time-secret" });
  const cache = setup("/clients");
  await userEvent.type(await screen.findByLabelText("Search clients"), "Keep this search");
  const trigger = screen.getByRole("button", { name: "Issue initial access token" });
  await userEvent.click(trigger);
  expect(screen.getByRole("dialog", { name: "Issue an initial access token" })).toBeInTheDocument();
  await userEvent.type(await screen.findByLabelText("Label"), "Developer");
  await userEvent.click(screen.getByRole("button", { name: "Issue token" }));
  expect(await screen.findByText("iat_one-time-secret")).toBeInTheDocument();
  expect(issue).toHaveBeenCalledWith({ label: "Developer", maxUses: 1, lifetimeHours: 24 });
  expect(JSON.stringify(cache.getQueryCache().getAll().map(q => q.state.data))).not.toContain("iat_one-time-secret");
  await userEvent.click(screen.getByRole("button", { name: "Dismiss token" }));expect(screen.queryByText("iat_one-time-secret")).not.toBeInTheDocument();
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(trigger).toHaveFocus();
  expect(screen.getByLabelText("Search clients")).toHaveValue("Keep this search");
  await userEvent.click(trigger);
  expect(screen.queryByText("iat_one-time-secret")).not.toBeInTheDocument();
  expect(screen.getByLabelText("Label")).toHaveValue("");
 });
 it("keeps an in-flight issuance open and clears the token when Escape closes the dialog", async () => {
  let finish!: (value: { credential: InitialToken; token: string }) => void;
  vi.spyOn(api, "issueRegistrationToken").mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  setup("/clients");
  await userEvent.click(await screen.findByRole("button", { name: "Issue initial access token" }));
  await userEvent.type(screen.getByLabelText("Label"), "Pending");
  await userEvent.click(screen.getByRole("button", { name: "Issue token" }));
  const dialog = screen.getByRole("dialog");
  fireEvent(dialog, new Event("cancel", { cancelable: true }));
  expect(dialog).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Cancel" })).toBeDisabled();
  await act(async () => { finish({ credential: invitation, token: "iat_pending_secret" }); });
  expect(await screen.findByText("iat_pending_secret")).toBeInTheDocument();
  fireEvent(dialog, new Event("cancel", { cancelable: true }));
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  expect(screen.queryByText("iat_pending_secret")).not.toBeInTheDocument();
 });
 it("redirects the former registration page to Activity monitoring", async () => {
  setup("/clients/registration");
  await screen.findByRole("heading", { name: "Initial access tokens", level: 2 });
  expect(screen.getByRole("link", { name: "Initial access tokens" })).toHaveAttribute("aria-current", "page");
  expect(screen.queryByRole("button", { name: "Issue token" })).not.toBeInTheDocument();
  await waitFor(() => expect(api.registrationTokens).toHaveBeenCalledWith("", 1));
 });
 it("hides revocation for expired, consumed and revoked tokens and reports search failures", async () => {
  vi.mocked(api.registrationTokens).mockResolvedValue({ tokens: ["expired", "consumed", "revoked"].map((status, i) => ({ ...invitation, id: String(i), status: status as InitialToken["status"] })), total: 3, page: 1, pageSize: 10 });
  setup(); await screen.findByText("consumed");
  expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument();
  vi.mocked(api.registrationTokens).mockRejectedValue(new ApiError("FAILED", 500, "Search unavailable"));
  await userEvent.click(screen.getByRole("button", { name: "Search" }));expect(await screen.findByRole("alert")).toHaveTextContent("Search unavailable");
 });
 it("requires confirmation to replace client configuration access and clears the new credential on navigation", async () => {
  vi.spyOn(api, "client").mockResolvedValue({ client_id: "portal", client_name: "Portal", client_id_issued_at: 1, updated_at: 1, has_client_secret: false, protocol_compatible: true, registration_origin: "dynamic", registration_token_active: true, redirect_uris: ["https://rp.example/cb"] });
  const replace = vi.spyOn(api, "issueClientRegistrationToken").mockResolvedValue({ token: "rat_once" });
  const cache = setup("/clients/portal");
  await userEvent.click(await screen.findByRole("button", { name: "Replace registration token" }));expect(replace).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button", { name: "Confirm issuance" }));expect(await screen.findByText("rat_once")).toBeInTheDocument();
  expect(JSON.stringify(cache.getQueryCache().getAll().map(q => q.state.data))).not.toContain("rat_once");
  await userEvent.click(screen.getByRole("link", { name: /Back to client search/ }));await screen.findByLabelText("Search clients");expect(screen.queryByText("rat_once")).not.toBeInTheDocument();
 });
});
