import { createRootRoute, createRoute, createRouter, Outlet, redirect } from "@tanstack/react-router";
import { AdminGuard, AuthGuard } from "./components/AuthGuard";
import ComponentsPage from "./pages/Components";
import DashboardPage from "./pages/Dashboard";
import LoginPage from "./pages/Login";
import { safeRedirect } from "./lib/navigation";
import NotFoundPage from "./pages/NotFound";
import ProfilePage from "./pages/Profile";
import SettingsPage from "./pages/Settings";
import UsersPage from "./pages/Users";

import { UserSearchProvider } from "./context/UserSearchContext";
import UserDetailPage from "./pages/UserDetail";
import UserCreatePage from "./pages/UserCreate";

import { ClientSearchProvider } from "./context/ClientSearchContext";
import ClientsPage from "./pages/Clients";
import ClientCreatePage from "./pages/ClientCreate";
import ClientDetailPage from "./pages/ClientDetail";

const rootRoute = createRootRoute({ component: Outlet });
const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/login",
  validateSearch: (search: Record<string, unknown>) => ({ redirect: safeRedirect(search.redirect) }),
  component: LoginPage,
});
const protectedRoute = createRoute({ getParentRoute: () => rootRoute, id: "authenticated", component: AuthGuard, notFoundComponent: NotFoundPage });
const dashboardRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/", component: DashboardPage });
const dashboardAlias = createRoute({ getParentRoute: () => protectedRoute, path: "/dashboard", beforeLoad: () => { throw redirect({ to: "/", replace: true }); } });
const componentsRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/components", component: ComponentsPage });
const settingsRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/settings", component: SettingsPage });
const profileRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/profile", component: ProfilePage });
const usersRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/users", component: () => <AdminGuard><UserSearchProvider><Outlet /></UserSearchProvider></AdminGuard> });

const userSearchRoute = createRoute({ getParentRoute: () => usersRoute, path: "/", component: UsersPage });
const userCreateRoute = createRoute({ getParentRoute: () => usersRoute, path: "new", component: UserCreatePage });
const userDetailRoute = createRoute({ getParentRoute: () => usersRoute, path: "$userId", component: UserDetailPage });

const clientsRoute = createRoute({ getParentRoute: () => protectedRoute, path: "/clients", component: () => <AdminGuard><ClientSearchProvider><Outlet /></ClientSearchProvider></AdminGuard> });
const clientSearchRoute = createRoute({ getParentRoute: () => clientsRoute, path: "/", component: ClientsPage });
const clientCreateRoute = createRoute({ getParentRoute: () => clientsRoute, path: "new", component: ClientCreatePage });
const clientDetailRoute = createRoute({ getParentRoute: () => clientsRoute, path: "$clientId", component: ClientDetailPage });

export const router = createRouter({
  routeTree: rootRoute.addChildren([loginRoute, protectedRoute.addChildren([dashboardRoute, dashboardAlias, componentsRoute, settingsRoute, profileRoute, clientsRoute.addChildren([clientSearchRoute, clientCreateRoute, clientDetailRoute]), usersRoute.addChildren([userSearchRoute, userCreateRoute, userDetailRoute])])]),
  defaultNotFoundComponent: NotFoundPage,
});
declare module "@tanstack/react-router" { interface Register { router: typeof router; } }
