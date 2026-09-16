import { StrictMode } from "react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "./context/AuthContext";
import { ToastProvider } from "./context/ToastContext";
import { api, ApiError, type User } from "./lib/api";
import type { OIDCClient } from "./lib/clients";
import { router } from "./router";

vi.mock("./context/ConfigContext", () => ({ useConfig: () => ({ ui: { appName: "Test App", defaultTheme: "auto" }, version: "1", startedAtMs: 0 }) }));
vi.mock("./context/ThemeContext", () => ({ useTheme: () => ({ mode: "light", setMode: vi.fn() }) }));
const admin: User = { id: "admin", name: "Admin", email: "admin@example.com", role: "admin", active: true, createdAt: "2026-01-01", updatedAt: "2026-01-01" };
const client: OIDCClient = { client_id: "portal-id", client_name: "Portal", client_id_issued_at: 1234567890, updated_at: 1234567890, has_client_secret: true, client_secret_expires_at: 0, redirect_uris: ["https://app.example.com/cb"], application_type: "web", token_endpoint_auth_method: "client_secret_basic", response_types: ["code"], grant_types: ["authorization_code"], protocol_compatible: true };
function setup(path: string) {
 const cache = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: 30_000 } } });
 const testRouter = createRouter({ routeTree: router.routeTree, history: createMemoryHistory({ initialEntries: [path] }) });
 render(<StrictMode><QueryClientProvider client={cache}><ToastProvider><AuthProvider><RouterProvider router={testRouter} /></AuthProvider></ToastProvider></QueryClientProvider></StrictMode>);
 return { cache, testRouter };
}
beforeEach(() => {
 vi.spyOn(api,"session").mockResolvedValue({ user: admin, csrfToken: "csrf", expiresAt: new Date(Date.now()+3600000).toISOString() });
 vi.spyOn(api,"clients").mockResolvedValue({ clients: [client], total: 1, page: 1, pageSize: 10 });
 vi.spyOn(api,"client").mockResolvedValue(client);
});
describe("client management", () => {
 it.each(["/clients","/clients/new","/clients/portal-id"])("blocks regular users at %s and hides Clients navigation", async (path) => {
  vi.mocked(api.session).mockResolvedValue({ user: { ...admin,role:"user" }, csrfToken:"csrf", expiresAt:new Date(Date.now()+3600000).toISOString() });
  setup(path);
  expect(await screen.findByRole("heading",{ name:"Access denied" })).toBeInTheDocument();
  expect(within(screen.getByRole("navigation")).queryByRole("link",{ name:"Clients" })).not.toBeInTheDocument();
  expect(api.clients).not.toHaveBeenCalled(); expect(api.client).not.toHaveBeenCalled();
 });
 it("searches only on submission and preserves drafts, page, and saved results through detail", async () => {
  vi.mocked(api.clients).mockResolvedValueOnce({ clients:[client],total:11,page:1,pageSize:10 }).mockResolvedValueOnce({ clients:[client],total:11,page:2,pageSize:10 });
  const update = vi.spyOn(api,"updateClient").mockResolvedValue({ ...client,client_name:"Updated Portal" });
  setup("/clients");
  await userEvent.type(await screen.findByLabelText("Search clients"),"Portal");
  expect(api.clients).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button",{ name:"Search" }));
  await screen.findByRole("link",{ name:"Portal" });
  await userEvent.clear(screen.getByLabelText("Search clients"));
  await userEvent.type(screen.getByLabelText("Search clients"),"Unsubmitted");
  expect(api.clients).toHaveBeenCalledTimes(1);
  await userEvent.click(screen.getByRole("button",{ name:"Next" }));
  expect(api.clients).toHaveBeenLastCalledWith({ q:"Portal",page:2 },expect.any(AbortSignal));
  await userEvent.click(await screen.findByRole("link",{ name:"Portal" }));
  await userEvent.clear(await screen.findByLabelText("Client name"));
  await userEvent.type(screen.getByLabelText("Client name"),"Updated Portal");
  await userEvent.click(screen.getByRole("button",{ name:"Save changes" }));
  await waitFor(() => expect(update).toHaveBeenCalledWith(client.client_id,expect.objectContaining({ client_name:"Updated Portal",redirect_uris:client.redirect_uris })));
  await screen.findByText("Client updated.");
  await userEvent.click(screen.getByRole("link",{ name:/Back to client search/ }));
  expect(await screen.findByLabelText("Search clients")).toHaveValue("Unsubmitted");
  expect(screen.getByRole("link",{ name:"Updated Portal" })).toBeInTheDocument();
  expect(screen.getByRole("button",{ name:"Next" })).toBeDisabled();
  expect(api.clients).toHaveBeenCalledTimes(2);
 });
 it("shows a warning banner for a client that requests unsupported protocol capabilities", async () => {
  vi.mocked(api.client).mockResolvedValue({ ...client, protocol_compatible: false, protocol_incompatibilities: ["pairwise subject identifiers are not yet implemented; this client requires public subjects"] });
  setup("/clients/portal-id");
  expect(await screen.findByRole("heading", { name: "Not usable with the OpenID Connect protocol endpoints yet" })).toBeInTheDocument();
  expect(screen.getByText(/pairwise subject identifiers/)).toBeInTheDocument();
 });
 it("creates into detail, exposes the secret once without caching it, and browser Back returns to search", async () => {
  const create = vi.spyOn(api,"createClient").mockResolvedValue({ ...client,client_secret:"one-time-secret" });
  const { cache,testRouter } = setup("/clients");
  await userEvent.click(await screen.findByRole("link",{ name:"Add client" }));
  await userEvent.type(await screen.findByLabelText("Client name"),"Portal");
  await userEvent.type(screen.getByRole("textbox",{ name:"Redirect URIs" }),"https://app.example.com/cb");
  await userEvent.click(screen.getByRole("button",{ name:"Create client" }));
  expect(await screen.findByText("one-time-secret")).toBeInTheDocument();
  expect(create).toHaveBeenCalledWith(expect.objectContaining({ client_name:"Portal",redirect_uris:["https://app.example.com/cb"] }));
  expect(testRouter.state.location.pathname).toBe("/clients/portal-id");
  expect(JSON.stringify(cache.getQueriesData({ queryKey:["client"] }))).not.toContain("one-time-secret");
  await act(async () => { testRouter.history.back(); });
  expect(await screen.findByLabelText("Search clients")).toHaveValue("");
  expect(api.clients).not.toHaveBeenCalled();
  await act(async () => { testRouter.history.forward(); });
  await screen.findByRole("heading",{ name:"Edit client" });
  expect(screen.queryByText("one-time-secret")).not.toBeInTheDocument();
 });
 it("requires confirmation for rotation and deletion", async () => {
  const rotate = vi.spyOn(api,"rotateClientSecret").mockResolvedValue({ ...client,client_secret:"rotated-secret" });
  const remove = vi.spyOn(api,"deleteClient").mockResolvedValue(undefined);
  setup("/clients/portal-id");
  await userEvent.click(await screen.findByRole("button",{ name:"Rotate secret" }));
  expect(rotate).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button",{ name:"Confirm rotation" }));
  expect(await screen.findByText("rotated-secret")).toBeInTheDocument();
  await userEvent.click(screen.getByRole("button",{ name:"Dismiss secret" }));
  expect(screen.queryByText("rotated-secret")).not.toBeInTheDocument();
  await userEvent.click(screen.getByRole("button",{ name:"Delete client" }));
  expect(remove).not.toHaveBeenCalled();
  await userEvent.click(screen.getByRole("button",{ name:"Confirm delete" }));
  expect(await screen.findByLabelText("Search clients")).toBeInTheDocument();
  expect(remove).toHaveBeenCalledWith("portal-id");
 });
 it("handles missing clients without fetching the search list", async () => {
  vi.mocked(api.client).mockRejectedValue(new ApiError("NOT_FOUND",404,"Client not found."));
  setup("/clients/missing");
  expect(await screen.findByRole("alert")).toHaveTextContent("Client not found.");
  await userEvent.click(screen.getByRole("link",{ name:/Back to client search/ }));
  expect(await screen.findByLabelText("Search clients")).toBeInTheDocument();
  expect(api.clients).not.toHaveBeenCalled();
 });
});
