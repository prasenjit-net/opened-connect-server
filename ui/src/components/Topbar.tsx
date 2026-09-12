import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { Link, useLocation } from "@tanstack/react-router";
import { IconMenu } from "../icons";
import ThemeToggle from "./ThemeToggle";

const TITLES: Record<string, string> = {
  "/": "Dashboard",
  "/dashboard": "Dashboard",
  "/components": "Components",
  "/settings": "Settings",
  "/profile": "My profile",
  "/users": "Users",
  "/clients": "Clients",
  "/clients/": "Clients",
  "/clients/new": "Add client",
};

export default function Topbar({ onMenu }: { onMenu: () => void }) {
  const { pathname } = useLocation();
  const { user, logout } = useAuth();
  const { notifyError } = useToast();
  const [busy, setBusy] = useState(false);
  const signOut = async () => { if (busy) return; setBusy(true); try { await logout(); } catch (error) { notifyError(error); } finally { setBusy(false); } };
  const title = TITLES[pathname] ?? (pathname === "/users/new" ? "Add user" : pathname === "/users/" ? "Users" : /^\/users\/[^/]+$/.test(pathname) ? "User detail" : /^\/clients\/[^/]+$/.test(pathname) ? "Client detail" : "Not found");
  return (
    <header className="sticky top-0 z-30 flex h-[60px] items-center gap-3 border-b border-line bg-canvas/80 px-4 backdrop-blur-md md:px-6">
      <button className="icon-btn" onClick={onMenu} aria-label="Toggle sidebar">
        <IconMenu size={20} />
      </button>
      <h1 className="mr-auto text-[1.02rem] font-semibold">{title}</h1>
      <div className="flex items-center gap-2">
        <Link to="/profile" className="hidden max-w-[160px] truncate text-sm text-ink-muted hover:text-ink sm:block" title={user?.email}>{user?.name}</Link>
        <ThemeToggle />
        <button className="btn btn-secondary btn-sm" disabled={busy} onClick={() => void signOut()}>{busy ? "Signing out…" : "Sign out"}</button>
      </div>
    </header>
  );
}
