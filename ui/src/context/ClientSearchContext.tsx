import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { useLocation } from "@tanstack/react-router";
import { api } from "../lib/api";
import type { OIDCClient, ClientList } from "../lib/clients";

export interface ClientFilters { q: string; }
interface ClientSearchState {
 secret: { id: string; value: string } | null;
 setSecret: (secret: { id: string; value: string } | null) => void;
  draft: ClientFilters;
  setDraft: (filters: ClientFilters) => void;
  result: ClientList | null;
  pending: boolean;
  error: string;
  searched: boolean;
  search: () => void;
  goToPage: (page: number) => void;
  updateResult: (client: OIDCClient) => void;
  removeResult: (id: string) => void;
}
const ClientSearchContext = createContext<ClientSearchState | null>(null);

// This provider lives on the /clients parent route, so list snapshots and draft
// filters survive detail/create navigation without remounting or refetching.
export function ClientSearchProvider({ children }: { children: ReactNode }) {
  const [secret, setSecret] = useState<{ id: string; value: string } | null>(null);
  const { pathname } = useLocation();
  useEffect(() => { setSecret((current) => current && pathname !== `/clients/${current.id}` ? null : current); }, [pathname]);
  const [draft, setDraft] = useState<ClientFilters>({ q: "" });
  const [submitted, setSubmitted] = useState<ClientFilters | null>(null);
  const [result, setResult] = useState<ClientList | null>(null);
  const [searched, setSearched] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<AbortController | null>(null);

  useEffect(() => () => request.current?.abort(), []);

  const run = useCallback(async (filters: ClientFilters, page: number) => {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setPending(true);
    setError("");
    setSearched(true);
    try {
      const data = await api.clients({ ...filters, page }, controller.signal);
      if (!controller.signal.aborted) { setResult(data); setSubmitted(filters); }
    } catch (error) {
      if (!controller.signal.aborted) setError(error instanceof Error ? error.message : "Unable to search clients.");
    } finally {
      if (!controller.signal.aborted) setPending(false);
    }
  }, []);

  const updateResult = (client: OIDCClient) => setResult((current) => current ? {
    ...current, clients: current.clients.map((item) => item.client_id === client.client_id ? client : item),
  } : current);
  const removeResult = (id: string) => setResult((current) => current && current.clients.some((item) => item.client_id === id) ? {
    ...current, clients: current.clients.filter((item) => item.client_id !== id), total: Math.max(0, current.total - 1),
  } : current);

  return <ClientSearchContext.Provider value={{
    secret, setSecret, draft, setDraft, result, pending, error, searched,
    search: () => { void run({ ...draft }, 1); },
    goToPage: (page) => { if (submitted) void run(submitted, page); },
    updateResult, removeResult,
  }}>{children}</ClientSearchContext.Provider>;
}

export function useClientSearch() {
  const state = useContext(ClientSearchContext);
  if (!state) throw new Error("useClientSearch must be used inside ClientSearchProvider");
  return state;
}
