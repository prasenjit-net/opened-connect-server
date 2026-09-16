import { Link, useNavigate, useLocation } from "@tanstack/react-router";
import { useEffect, type ReactNode } from "react";
import { useAuth } from "../context/AuthContext";
import Layout from "./Layout";

export function AuthGuard() {
  const auth = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  useEffect(() => {
    if (!auth.loading && !auth.error && !auth.user && location.pathname !== "/login") {
      void navigate({ to: "/login", search: { redirect: location.href }, replace: true });
    }
  }, [auth.loading, auth.error, auth.user, location.pathname, location.href, navigate]);
  if (auth.loading) return <div className="flex min-h-screen items-center justify-center"><div className="spinner" aria-label="Checking session" /></div>;
  if (auth.error) return <div className="card mx-auto mt-16 max-w-md text-center"><h1 className="font-semibold">Unable to check your session</h1><p className="my-3 text-ink-muted">Check your connection and try again.</p><button className="btn btn-primary" onClick={() => void auth.refresh()}>Retry</button></div>;
  if (!auth.user) return null;
  return <Layout />;
}

export function AdminGuard({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  if (user?.role !== "admin") return <section className="card"><h2 className="text-lg font-semibold">Access denied</h2><p className="my-3 text-ink-muted">Only administrators can access this page.</p><Link to="/" className="btn btn-primary">Back to dashboard</Link></section>;
  return children;
}
