import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api } from "../lib/api";
import type { InitialToken } from "../lib/registration";
import ActivityNavigation from "../components/ActivityNavigation";

export default function InitialAccessTokensPage() {
 const [draft, setDraft] = useState("");
 const [filters, setFilters] = useState({ q: "", page: 1 });
 const [selected, setSelected] = useState<InitialToken | null>(null);
 const cache = useQueryClient();
 const query = useQuery({
  queryKey: ["initial-access-tokens", filters],
  queryFn: () => api.registrationTokens(filters.q, filters.page),
  refetchInterval: selected ? false : 15_000,
 });
 const revocation = useMutation({
  mutationFn: (item: InitialToken) => api.revokeRegistrationToken(item.id),
  onSettled: async () => {
   setSelected(null);
   await cache.invalidateQueries({ queryKey: ["initial-access-tokens"] });
  },
 });
 const result = query.data;
 const busy = query.isFetching || revocation.isPending;
 const error = revocation.error ?? query.error;
 const search = () => {
  revocation.reset();
  if (filters.q === draft && filters.page === 1) void query.refetch();
  else setFilters({ q: draft, page: 1 });
 };
 const active = (item: InitialToken) => item.status === "active" && new Date(item.expiresAt).getTime() > Date.now();
 return <div className="flex min-w-0 flex-col gap-4">
  <ActivityNavigation current="initial-access-tokens" />
  <p className="text-sm text-ink-muted">Monitor initial access tokens, remaining registrations, and expiry. Refreshes every 15 seconds. Issue new tokens from the client list.</p>
  <Link to="/clients" className="self-start text-sm text-accent hover:underline">Go to clients</Link>
  {error && <p role="alert" className="rounded-lg bg-err-soft p-3 text-sm text-err">{error.message}</p>}
  <section className="card"><h2 className="mb-3 font-semibold">Initial access tokens</h2>
    <form className="flex flex-wrap items-end gap-3" onSubmit={e => { e.preventDefault(); search(); }}><label className="flex min-w-0 flex-1 flex-col gap-1.5 text-sm">Search tokens<input className="input" type="search" maxLength={254} value={draft} onChange={e => setDraft(e.target.value)} placeholder="Label, token ID, or status" /></label><button type="submit" className="btn btn-secondary" disabled={busy}>Search</button><button type="button" className="btn btn-secondary" disabled={busy} onClick={() => void query.refetch()}>Refresh</button></form>
   {query.isPending && <p role="status" className="mt-3 text-sm">Loading initial access tokens…</p>}
   {result && <><div className="mt-4 overflow-x-auto"><table className="w-full min-w-[650px] text-left text-sm"><thead className="bg-surface-2"><tr>{["Label", "Status", "Remaining uses", "Expires", "Action"].map(x => <th key={x} className="p-3 font-medium">{x}</th>)}</tr></thead><tbody>
    {result.tokens.map(item => <tr key={item.id} className="border-t border-line"><td className="max-w-64 break-words p-3">{item.label}<span className="mt-1 block break-all font-mono text-xs text-ink-muted">{item.id}</span></td><td className="p-3">{item.status === "active" && !active(item) ? "expired" : item.status}</td><td className="p-3">{Math.max(0, item.maxUses - item.uses)} / {item.maxUses}</td><td className="p-3">{new Date(item.expiresAt).toLocaleString()}</td><td className="p-3">{active(item) && <button type="button" className="btn btn-secondary btn-sm" disabled={busy} onClick={() => { revocation.reset(); setSelected(item); }}>Revoke</button>}</td></tr>)}
    {!result.tokens.length && <tr><td colSpan={5} className="p-8 text-center text-ink-muted">No tokens match.</td></tr>}
    </tbody></table></div><div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm"><span>{result.total} tokens · Page {result.page} of {Math.max(1, Math.ceil(result.total / 10))} · 10 per page</span><div className="flex gap-2"><button type="button" className="btn btn-secondary" disabled={busy || result.page <= 1} onClick={() => setFilters({ ...filters, page: result.page - 1 })}>Previous</button><button type="button" className="btn btn-secondary" disabled={busy || result.page * 10 >= result.total} onClick={() => setFilters({ ...filters, page: result.page + 1 })}>Next</button></div></div></>}
    {selected && <div role="alertdialog" aria-labelledby="revoke-registration-title" className="mt-4 rounded-lg border border-line p-4"><h3 id="revoke-registration-title" className="font-semibold">Revoke {selected.label}?</h3><p className="my-3 text-sm text-ink-muted">This stops future registrations. Clients already created with this token remain available.</p><div className="flex gap-2"><button type="button" className="btn btn-danger" disabled={busy || !active(selected)} onClick={() => revocation.mutate(selected)}>Confirm revocation</button><button type="button" className="btn btn-secondary" disabled={busy} onClick={() => setSelected(null)}>Cancel</button></div></div>}
  </section>
 </div>;
}
