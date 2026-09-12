import { createRootRoute, createRoute, createRouter, redirect } from "@tanstack/react-router";
import Layout from "./components/Layout";
import ComponentsPage from "./pages/Components";
import DashboardPage from "./pages/Dashboard";
import NotFoundPage from "./pages/NotFound";
import SettingsPage from "./pages/Settings";

const rootRoute = createRootRoute({ component: Layout });
const dashboardRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  component: DashboardPage,
});
const dashboardAlias = createRoute({
  getParentRoute: () => rootRoute,
  path: "/dashboard",
  beforeLoad: () => { throw redirect({ to: "/", replace: true }); },
});
const componentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/components",
  component: ComponentsPage,
});
const settingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/settings",
  component: SettingsPage,
});

export const router = createRouter({
  routeTree: rootRoute.addChildren([dashboardRoute, dashboardAlias, componentsRoute, settingsRoute]),
  defaultNotFoundComponent: NotFoundPage,
});

declare module "@tanstack/react-router" {
  interface Register { router: typeof router; }
}
