import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AuthProvider } from "./context/AuthContext";
import { ToastProvider } from "./context/ToastContext";
import { api, ApiError, type Session, type User } from "./lib/api";
import * as navigation from "./lib/navigation";
import NotFoundPage from "./pages/NotFound";
import { router } from "./router";

vi.mock("./context/ConfigContext", () => ({ useConfig: () => ({ ui: { appName: "Test App", defaultTheme: "auto" }, version: "1", startedAtMs: 0 }) }));
vi.mock("./context/ThemeContext", () => ({ useTheme: () => ({ mode: "light", setMode: vi.fn() }) }));

const user: User = { id: "u1", name: "Alice", email: "alice@example.com", role: "user", active: true, createdAt: "2026-01-01", updatedAt: "2026-01-01" };
function session(): Session { return { user, csrfToken: "test-csrf", expiresAt: new Date(Date.now() + 3_600_000).toISOString() }; }

function setup(path: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const testRouter = createRouter({ routeTree: router.routeTree, history: createMemoryHistory({ initialEntries: [path] }), defaultNotFoundComponent: NotFoundPage });
  render(<QueryClientProvider client={client}><ToastProvider><AuthProvider><RouterProvider router={testRouter} /></AuthProvider></ToastProvider></QueryClientProvider>);
  return { client, testRouter };
}

beforeEach(() => {
  vi.spyOn(api, "session").mockResolvedValue(session());
});

describe("OIDC authorization continuation", () => {
  it("redirects unauthenticated visitors to login and back to the continuation page", async () => {
    vi.spyOn(api, "session").mockRejectedValue(new ApiError("UNAUTHORIZED", 401, "Sign in"));
    const login = vi.spyOn(api, "login").mockResolvedValue(session());
    setup("/oidc/continue?tx=abc123");
    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Email"), user.email);
    await userEvent.type(screen.getByLabelText("Password"), "a long safe password");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(login).toHaveBeenCalled();
  });

  it("renders the consent screen and approves with exactly the requested scopes", async () => {
    vi.spyOn(api, "authorization").mockResolvedValue({
      status: "consent_required",
      clientName: "Example App",
      scopes: [{ scope: "openid", description: "Confirm your identity" }, { scope: "profile", description: "Your name and basic profile information" }],
    });
    const decide = vi.spyOn(api, "decideAuthorization").mockResolvedValue({ status: "complete", redirectTo: "https://rp.example.com/cb?code=abc" });
    const navigateExternal = vi.spyOn(navigation, "navigateExternal").mockImplementation(() => {});
    setup("/oidc/continue?tx=abc123");
    expect(await screen.findByRole("heading", { name: "Example App" })).toBeInTheDocument();
    expect(screen.getByText("Confirm your identity")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect(decide).toHaveBeenCalledWith("abc123", { approve: true, scopes: ["openid", "profile"] });
    await vi.waitFor(() => expect(navigateExternal).toHaveBeenCalledWith("https://rp.example.com/cb?code=abc"));
  });

  it("denies and still follows the relying party's error callback", async () => {
    vi.spyOn(api, "authorization").mockResolvedValue({
      status: "consent_required",
      clientName: "Example App",
      scopes: [{ scope: "openid", description: "Confirm your identity" }],
    });
    const decide = vi.spyOn(api, "decideAuthorization").mockResolvedValue({ status: "complete", redirectTo: "https://rp.example.com/cb?error=access_denied" });
    const navigateExternal = vi.spyOn(navigation, "navigateExternal").mockImplementation(() => {});
    setup("/oidc/continue?tx=abc123");
    await screen.findByRole("heading", { name: "Example App" });
    await userEvent.click(screen.getByRole("button", { name: "Deny" }));
    expect(decide).toHaveBeenCalledWith("abc123", { approve: false, scopes: ["openid"] });
    await vi.waitFor(() => expect(navigateExternal).toHaveBeenCalledWith("https://rp.example.com/cb?error=access_denied"));
  });

  it("shows a generic error screen for an expired or invalid transaction", async () => {
    vi.spyOn(api, "authorization").mockResolvedValue({ status: "error", message: "This sign-in request is no longer valid. Start again from the application you were using." });
    setup("/oidc/continue?tx=expired");
    expect(await screen.findByRole("heading", { name: "This sign-in request can't be completed" })).toBeInTheDocument();
    expect(screen.getByText(/no longer valid/)).toBeInTheDocument();
  });

  it("immediately follows the redirect when a covering consent already completes the request", async () => {
    vi.spyOn(api, "authorization").mockResolvedValue({ status: "complete", redirectTo: "https://rp.example.com/cb?code=xyz" });
    const navigateExternal = vi.spyOn(navigation, "navigateExternal").mockImplementation(() => {});
    setup("/oidc/continue?tx=abc123");
    await vi.waitFor(() => expect(navigateExternal).toHaveBeenCalledWith("https://rp.example.com/cb?code=xyz"));
  });
});
