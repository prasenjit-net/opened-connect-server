import { useQuery, useQueryClient } from "@tanstack/react-query";
import { createContext, useCallback, useContext, useEffect, type ReactNode } from "react";
import { api, ApiError, setCSRFToken, type Session, type User } from "../lib/api";

interface AuthState {
  user: User | null;
  loading: boolean;
  error: Error | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
  forget: () => void;
}
const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const client = useQueryClient();
  const query = useQuery<Session | null>({
    queryKey: ["session"],
    queryFn: async () => {
      try { return await api.session(); }
      catch (error) { if (error instanceof ApiError && error.status === 401) return null; throw error; }
    },
    retry: false,
    staleTime: 0,
    refetchInterval: 60_000,
  });
  const forget = useCallback(() => {
    setCSRFToken(null);
    // Cancel in-flight private requests before removing cached data, so a
    // response from a previous account cannot repopulate another user's UI.
    void client.cancelQueries({ predicate: (q) => q.queryKey[0] !== "config" });
    client.removeQueries({ predicate: (q) => !["config", "session"].includes(String(q.queryKey[0])) });
    client.setQueryData(["session"], null);
  }, [client]);

  useEffect(() => {
    setCSRFToken(query.data?.csrfToken ?? null);
    if (query.data === null) {
      void client.cancelQueries({ predicate: (q) => !["config", "session"].includes(String(q.queryKey[0])) });
      client.removeQueries({ predicate: (q) => !["config", "session"].includes(String(q.queryKey[0])) });
    }
  }, [query.data, client]);
  useEffect(() => {
    window.addEventListener("session-expired", forget);
    return () => window.removeEventListener("session-expired", forget);
  }, [forget]);
  useEffect(() => {
    if (!query.data) return;
    const delay = Math.max(0, new Date(query.data.expiresAt).getTime() - Date.now());
    const timer = window.setTimeout(forget, Math.min(delay, 2_147_483_647));
    return () => clearTimeout(timer);
  }, [query.data, forget]);

  const login = async (email: string, password: string) => {
    const session = await api.login(email, password);
    await client.cancelQueries({ predicate: (q) => q.queryKey[0] !== "config" });
    client.removeQueries({ predicate: (q) => !["config", "session"].includes(String(q.queryKey[0])) });
    setCSRFToken(session.csrfToken);
    client.setQueryData(["session"], session);
  };
  const logout = async () => { await api.logout(); forget(); };
  const refresh = async () => { await query.refetch(); };

  return <AuthContext.Provider value={{ user: query.data?.user ?? null, loading: query.isPending, error: query.error, login, logout, refresh, forget }}>{children}</AuthContext.Provider>;
}
export function useAuth() {
  const auth = useContext(AuthContext);
  if (!auth) throw new Error("useAuth must be used inside AuthProvider");
  return auth;
}
