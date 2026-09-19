import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, expect, it, vi } from "vitest";
import { api } from "../lib/api";
import { ToastProvider } from "../context/ToastContext";
import { ClientOAuthPermissions, UserOAuthPermissions } from "./OAuthPermissions";
import type { OAuthPolicy } from "../lib/oauth";
const empty: OAuthPolicy = { grants: [], resources: {}, defaultResource: "", introspectionEnabled: false, introspectionAudiences: [], refreshInspection: false, refreshEnabled: false, passwordEnabled: false };
function wrap(ui: React.ReactNode) { render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}><ToastProvider>{ui}</ToastProvider></QueryClientProvider>); }
beforeEach(() => {
 vi.spyOn(api, "oauthSettings").mockResolvedValue({ protocolEnabled: true, passwordGrantEnabled: false, refreshTokensEnabled: true, resources: [{ audience: "https://api.example", scopes: ["read", "write"], enabled: true }] });
 vi.spyOn(api, "oauthPolicy").mockResolvedValue(empty);
 vi.spyOn(api, "saveOAuthPolicy").mockImplementation(async (_id, p) => p);
 vi.spyOn(api, "oauthAccess").mockResolvedValue({});
 vi.spyOn(api, "saveOAuthAccess").mockImplementation(async (_id, a) => a);
});
it("keeps permissions separate and saves explicit grants and resource scopes", async () => {
 wrap(<ClientOAuthPermissions id="client" grants={["client_credentials", "password"]} confidential />);
 expect(api.oauthPolicy).not.toHaveBeenCalled();
 await userEvent.click(screen.getByRole("button", { name: "Configure OAuth permissions" }));
 const machine = await screen.findByRole("checkbox", { name: /Client credentials/ });
 expect(screen.getByRole("checkbox", { name: "Legacy password grant" })).toBeDisabled();
 await userEvent.click(machine);
 await userEvent.click(screen.getByRole("checkbox", { name: "Permit this resource" }));
 await userEvent.click(screen.getByRole("checkbox", { name: "read" }));
 const resource = screen.getByRole("group", { name: "https://api.example" });
 const reads = within(resource).getAllByRole("checkbox", { name: "read" });
 await userEvent.click(reads[1]);
 await userEvent.selectOptions(screen.getByRole("combobox", { name: "Default resource" }), "https://api.example");
 await userEvent.click(screen.getByRole("button", { name: "Save OAuth permissions" }));
 await waitFor(() => expect(api.saveOAuthPolicy).toHaveBeenCalledWith("client", expect.objectContaining({ grants: ["client_credentials"], defaultResource: "https://api.example", resources: { "https://api.example": { allowed: ["read"], default: ["read"] } } })));
});
it("does not offer confidential grants to public clients", async () => {
 wrap(<ClientOAuthPermissions id="public" grants={["authorization_code", "refresh_token"]} confidential={false} />);
 await userEvent.click(screen.getByRole("button", { name: "Configure OAuth permissions" }));
 expect(await screen.findByRole("checkbox", { name: /Client credentials/ })).toBeDisabled();
 expect(screen.getByRole("checkbox", { name: "Allow token introspection" })).toBeDisabled();
 expect(screen.getByRole("checkbox", { name: /Refresh tokens/ })).toBeEnabled();
});
it("saves user entitlements independently of profile attributes", async () => {
 wrap(<UserOAuthPermissions id="user" />);
 await userEvent.click(screen.getByRole("button", { name: "Configure resource access" }));
 await userEvent.click(await screen.findByRole("checkbox", { name: "read" }));
 await userEvent.click(screen.getByRole("button", { name: "Save resource access" }));
 await waitFor(() => expect(api.saveOAuthAccess).toHaveBeenCalledWith("user", { "https://api.example": ["read"] }));
});
