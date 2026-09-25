import {
  RouterProvider,
  createMemoryHistory,
  createRootRoute,
  createRoute,
  createRouter,
} from "@tanstack/react-router";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";
import Layout from "./Layout";

// Isolate shell navigation from the server configuration and theme providers.
vi.mock("../context/AuthContext", () => ({
  useAuth: () => ({ user: { id: "user-1", name: "Test User", email: "test@example.com", role: "user", active: true }, loading: false, error: null, logout: vi.fn(), refresh: vi.fn() }),
}));
vi.mock("../context/ToastContext", () => ({ useToast: () => ({ notifyError: vi.fn() }) }));
vi.mock("../context/ConfigContext", () => ({
  useConfig: () => ({
    ui: { appName: "Test App", tagline: "Testing", repoUrl: null },
    version: "0.0.0",
  }),
}));
vi.mock("../context/ThemeContext", () => ({
  useTheme: () => ({ mode: "light", setMode: vi.fn() }),
}));

// A minimal one-route test router — Layout is the root route's component
// (exactly as in src/router.tsx), with a single index child so
// useLocation()/<Outlet/> have something real to resolve against.
function buildTestRouter() {
  const rootRoute = createRootRoute({ component: Layout });
  const indexRoute = createRoute({
    getParentRoute: () => rootRoute,
    path: "/",
    component: () => <div>Page content</div>,
  });
  const routeTree = rootRoute.addChildren([indexRoute]);
  return createRouter({ routeTree, history: createMemoryHistory({ initialEntries: ["/"] }) });
}

function renderLayout() {
  return render(<RouterProvider router={buildTestRouter()} />);
}

// "Dashboard" also appears as the Topbar's page-title <h1>, so the nav
// label needs to be queried within the sidebar's <nav> specifically.
function sidebarNavLabel(text: string): HTMLElement {
  const nav = document.querySelector("nav")!;
  return within(nav).getByText(text).closest("span")!;
}

function setMobile(isMobile: boolean) {
  window.matchMedia = vi.fn().mockImplementation((query: string) => ({
    matches: isMobile && query.includes("max-width"),
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
}

describe("Layout sidebar collapse", () => {
  beforeEach(() => {
    window.localStorage.clear();
    setMobile(false);
  });

  it("starts expanded (icon + text) when nothing is saved", async () => {
    renderLayout();
    await screen.findByLabelText("Toggle sidebar");
    expect(sidebarNavLabel("Dashboard").className).not.toContain("md:hidden");
  });

  it("collapses to an icon-only rail on hamburger click and persists it", async () => {
    const user = userEvent.setup();
    renderLayout();
    await screen.findByLabelText("Toggle sidebar");

    await user.click(screen.getByLabelText("Toggle sidebar"));

    expect(sidebarNavLabel("Dashboard").className).toContain("md:hidden");
    expect(window.localStorage.getItem("openid-connect-server-sidebar")).toBe("collapsed");
  });

  it("expands again on a second hamburger click", async () => {
    const user = userEvent.setup();
    renderLayout();
    await screen.findByLabelText("Toggle sidebar");

    await user.click(screen.getByLabelText("Toggle sidebar"));
    await user.click(screen.getByLabelText("Toggle sidebar"));

    expect(sidebarNavLabel("Dashboard").className).not.toContain("md:hidden");
    expect(window.localStorage.getItem("openid-connect-server-sidebar")).toBe("expanded");
  });

  it("restores a previously collapsed state on mount", async () => {
    window.localStorage.setItem("openid-connect-server-sidebar", "collapsed");
    renderLayout();
    await screen.findByLabelText("Toggle sidebar");
    expect(sidebarNavLabel("Dashboard").className).toContain("md:hidden");
  });

  it("opens an overlay drawer instead of collapsing on mobile viewports", async () => {
    setMobile(true);
    const user = userEvent.setup();
    renderLayout();
    await screen.findByLabelText("Toggle sidebar");

    const aside = document.querySelector("aside")!;
    expect(aside.className).toContain("-translate-x-full");

    await user.click(screen.getByLabelText("Toggle sidebar"));

    expect(aside.className).toContain("translate-x-0");
    // Collapse state (desktop-only concept) must be untouched by the
    // mobile drawer toggle.
    expect(window.localStorage.getItem("openid-connect-server-sidebar")).toBeNull();
  });
});
