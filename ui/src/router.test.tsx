import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createMemoryHistory, createRouter, RouterProvider } from "@tanstack/react-router";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ToastProvider } from "./context/ToastContext";
import NotFoundPage from "./pages/NotFound";
import { router } from "./router";

vi.mock("./context/AuthContext", () => ({
  useAuth: () => ({ user: { id: "user-1", name: "Test User", email: "test@example.com", role: "user", active: true }, loading: false, error: null, logout: vi.fn(), refresh: vi.fn() }),
}));
vi.mock("./context/ConfigContext", () => ({
  useConfig: () => ({
    ui: { appName: "OpenID Connect Server", tagline: "Administration", defaultTheme: "auto", repoUrl: null },
    version: "1.0.0", startedAtMs: 0,
  }),
}));
vi.mock("./context/ThemeContext", () => ({
  useTheme: () => ({ mode: "light", setMode: vi.fn() }),
}));

function renderRoute(path: string) {
  const testRouter = createRouter({
    routeTree: router.routeTree,
    history: createMemoryHistory({ initialEntries: [path] }),
    defaultNotFoundComponent: NotFoundPage,
  });
  render(
    <QueryClientProvider client={new QueryClient()}>
      <ToastProvider><RouterProvider router={testRouter} /></ToastProvider>
    </QueryClientProvider>,
  );
  return testRouter;
}

describe("theme routes", () => {
  it("opens settings directly and only shows neutral navigation", async () => {
    renderRoute("/settings");
    expect(await screen.findByRole("heading", { name: "Appearance" })).toBeInTheDocument();
    const nav = screen.getByRole("navigation");
    expect(within(nav).getAllByRole("link").map((link) => link.textContent)).toEqual(["Dashboard", "Components", "My profile", "Settings"]);
  });

  it("shows 404 for removed domain routes and supports returning home", async () => {
    renderRoute("/certificates/unknown");
    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("link", { name: "Back to dashboard" }));
    expect(await screen.findByText(/Your workspace is ready/)).toBeInTheDocument();
  });

  it("renders the component showcase and local notifications", async () => {
    renderRoute("/components");
    await userEvent.click(await screen.findByRole("button", { name: "Success toast" }));
    expect(await screen.findByText("Everything saved cleanly.")).toBeInTheDocument();
  });

  it("supports the previous dashboard URL", async () => {
    const testRouter = renderRoute("/dashboard");
    expect(await screen.findByText(/Your workspace is ready/)).toBeInTheDocument();
    expect(testRouter.state.location.pathname).toBe("/");
  });
});
