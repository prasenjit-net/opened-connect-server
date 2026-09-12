import { useNavigate, useLocation, useSearch } from "@tanstack/react-router";
import { useEffect, useState, type FormEvent } from "react";
import Logo from "../components/Logo";
import ThemeToggle from "../components/ThemeToggle";
import { useAuth } from "../context/AuthContext";
import { useConfig } from "../context/ConfigContext";

import { safeRedirect } from "../lib/navigation";

export default function LoginPage() {
  const auth = useAuth();
  const { ui } = useConfig();
  const search = useSearch({ from: "/login" });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const redirect = safeRedirect(search.redirect);
  const navigate = useNavigate();
  const location = useLocation();
  useEffect(() => {
    if (auth.user && location.pathname === "/login") void navigate({ to: redirect, replace: true });
  }, [auth.user, location.pathname, redirect, navigate]);
  if (auth.user) return null;
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (busy) return;
    setBusy(true); setError("");
    try { await auth.login(email, password); setPassword(""); }
    catch (error) { setError(error instanceof Error ? error.message : "Unable to sign in."); }
    finally { setBusy(false); }
  };
  return <div className="flex min-h-screen flex-col items-center justify-center px-4 py-10">
    <div className="absolute right-4 top-4"><ThemeToggle /></div>
    <section className="card w-full max-w-[420px] p-8">
      <Logo size={44} />
      <h1 className="mt-5 text-xl font-semibold">Sign in</h1>
      <p className="mb-6 mt-1 text-sm text-ink-muted">{ui.appName}</p>
      <form onSubmit={submit} className="flex flex-col gap-4">
        <label className="flex flex-col gap-1.5 text-sm font-medium">Email<input className="input" type="email" autoComplete="username" required maxLength={254} value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Password<input className="input" type="password" autoComplete="current-password" required maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        {error && <p role="alert" className="rounded-lg bg-err-soft p-3 text-sm text-err">{error}</p>}
        <button type="submit" className="btn btn-primary mt-1" disabled={busy || auth.loading}>{busy ? "Signing in…" : "Sign in"}</button>
      </form>
      <p className="mt-5 text-xs leading-relaxed text-ink-faint">Need an account? Contact your administrator.</p>
    </section>
  </div>;
}
