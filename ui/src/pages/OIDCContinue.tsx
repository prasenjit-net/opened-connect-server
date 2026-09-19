import { useQuery } from "@tanstack/react-query";
import { useNavigate, useLocation, useSearch } from "@tanstack/react-router";
import { useEffect, useState, type ReactNode } from "react";
import ConsentScreen from "../components/ConsentScreen";
import ProtocolErrorScreen from "../components/ProtocolErrorScreen";
import Logo from "../components/Logo";
import ThemeToggle from "../components/ThemeToggle";
import { useAuth } from "../context/AuthContext";
import { api } from "../lib/api";
import { navigateExternal } from "../lib/navigation";

export default function OIDCContinuePage() {
  const auth = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const search = useSearch({ from: "/oidc/continue" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!auth.loading && !auth.error && !auth.user) {
      void navigate({ to: "/login", search: { redirect: location.href }, replace: true });
    }
  }, [auth.loading, auth.error, auth.user, location.href, navigate]);

  const query = useQuery({
    queryKey: ["oidc-authorization", search.tx],
    queryFn: () => api.authorization(search.tx),
    enabled: !!auth.user,
    staleTime: 0,
    retry: false,
  });

  useEffect(() => {
    if (query.data?.status === "complete" && query.data.redirectTo) {
      navigateExternal(query.data.redirectTo);
    }
  }, [query.data]);

  const decide = async (approve: boolean) => {
    if (busy || !query.data?.scopes) return;
    setBusy(true); setError("");
    try {
      const result = await api.decideAuthorization(search.tx, { approve, scopes: query.data.scopes.map((s) => s.scope) });
      if (result.redirectTo) navigateExternal(result.redirectTo);
      else setError(result.message || "Unable to complete this sign-in request.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unable to complete this sign-in request.");
    } finally {
      setBusy(false);
    }
  };

  let content: ReactNode = null;
  if (auth.loading || !auth.user || query.isPending) {
    content = <div className="spinner" aria-label="Loading" />;
  } else if (query.isError) {
    content = <ProtocolErrorScreen message={query.error instanceof Error ? query.error.message : "Unable to load this sign-in request."} />;
  } else if (query.data.status === "error") {
    content = <ProtocolErrorScreen message={query.data.message || "This sign-in request is no longer valid."} />;
  } else if (query.data.status === "consent_required") {
    content = <ConsentScreen clientName={query.data.clientName || "This application"} scopes={query.data.scopes ?? []} busy={busy} error={error} onApprove={() => void decide(true)} onDeny={() => void decide(false)} />;
  } else {
    content = <div className="spinner" aria-label="Redirecting" />;
  }

  return <div className="flex min-h-screen flex-col items-center justify-center gap-5 px-4 py-10">
    <div className="absolute right-4 top-4"><ThemeToggle /></div>
    <Logo size={44} />
    {content}
  </div>;
}
