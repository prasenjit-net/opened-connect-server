import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api, type User, type UserList } from "../lib/api";

export interface UserFilters { q: string; role: string; status: string; }
interface UserSearchState {
  draft: UserFilters;
  setDraft: (filters: UserFilters) => void;
  result: UserList | null;
  pending: boolean;
  error: string;
  searched: boolean;
  search: () => void;
  goToPage: (page: number) => void;
  updateResult: (user: User) => void;
  removeResult: (id: string) => void;
}
const UserSearchContext = createContext<UserSearchState | null>(null);

// This provider lives on the /users parent route, so list snapshots and draft
// filters survive detail/create navigation without remounting or refetching.
export function UserSearchProvider({ children }: { children: ReactNode }) {
  const [draft, setDraft] = useState<UserFilters>({ q: "", role: "", status: "" });
  const [submitted, setSubmitted] = useState<UserFilters | null>(null);
  const [result, setResult] = useState<UserList | null>(null);
  const [searched, setSearched] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const request = useRef<AbortController | null>(null);

  useEffect(() => () => request.current?.abort(), []);

  const run = useCallback(async (filters: UserFilters, page: number) => {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setPending(true);
    setError("");
    setSearched(true);
    try {
      const data = await api.users({ ...filters, page }, controller.signal);
      if (!controller.signal.aborted) { setResult(data); setSubmitted(filters); }
    } catch (error) {
      if (!controller.signal.aborted) setError(error instanceof Error ? error.message : "Unable to search users.");
    } finally {
      if (!controller.signal.aborted) setPending(false);
    }
  }, []);

  const updateResult = (user: User) => setResult((current) => current ? {
    ...current, users: current.users.map((item) => item.id === user.id ? user : item),
  } : current);
  const removeResult = (id: string) => setResult((current) => current && current.users.some((item) => item.id === id) ? {
    ...current, users: current.users.filter((item) => item.id !== id), total: Math.max(0, current.total - 1),
  } : current);

  return <UserSearchContext.Provider value={{
    draft, setDraft, result, pending, error, searched,
    search: () => { void run({ ...draft }, 1); },
    goToPage: (page) => { if (submitted) void run(submitted, page); },
    updateResult, removeResult,
  }}>{children}</UserSearchContext.Provider>;
}

export function useUserSearch() {
  const state = useContext(UserSearchContext);
  if (!state) throw new Error("useUserSearch must be used inside UserSearchProvider");
  return state;
}
