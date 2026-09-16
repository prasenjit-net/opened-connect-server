import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api, ApiError } from "../lib/api";
import { activityKinds, activityLabels, type ActivityKind, type ActivityRecord } from "../lib/activity";
import ActivityTable from "../components/ActivityTable";
import { useToast } from "../context/ToastContext";

const consequences: Record<ActivityKind, string> = {
 transactions: "This cancels the active transaction and prevents it from completing.",
 codes: "This prevents this unused authorization code from being exchanged.",
 tokens: "This immediately blocks this access token from UserInfo. Already-issued ID tokens remain valid until expiry.",
 consents: "This revokes consent, pending requests, authorization codes, and access tokens for this user and client. A future sign-in requires consent again.",
};
export default function ActivityPage({ kind }: { kind: ActivityKind }) {
 const [draft, setDraft] = useState({ q: "", status: "" });
 const [filters, setFilters] = useState({ q: "", status: "", page: 1 });
 const [selected, setSelected] = useState<ActivityRecord | null>(null);
 const confirmation = useRef<HTMLElement>(null);
 useEffect(() => { if (selected) confirmation.current?.focus(); }, [selected]);
 const client = useQueryClient(); const { push } = useToast();
 const query = useQuery({ queryKey: ["activity", kind, filters], queryFn: ({ signal }) => api.activity(kind, filters, signal), refetchInterval: selected ? false : 15_000 });
 const revoke = useMutation({ mutationFn: (record: ActivityRecord) => api.revokeActivity(kind, record.id), onError: error => {
  if (error instanceof ApiError && error.code === "ACTIVITY_NOT_ACTIVE") {
   void client.invalidateQueries({ queryKey: ["activity"] });
   void client.invalidateQueries({ queryKey: ["activity-overview"] });
  }
 }, onSuccess: async () => {
  setSelected(null); push("success", "Revocation completed.");
  await Promise.all([client.invalidateQueries({ queryKey: ["activity"] }), client.invalidateQueries({ queryKey: ["activity-overview"] })]);
 } });
 const result = query.data; const pages = Math.max(1, Math.ceil((result?.total ?? 0) / 10));
 return <div className="flex flex-col gap-4">
  <div className="flex flex-wrap gap-2" aria-label="Activity categories">{activityKinds.map(k => <Link key={k} to={`/activity/${k}`} className={`btn ${kind === k ? "btn-primary" : "btn-secondary"}`}>{activityLabels[k]}</Link>)}</div>
  <p className="text-sm text-ink-muted">Monitor retained {activityLabels[kind].toLowerCase()}. Refreshes every 15 seconds. Expired records are periodically removed; these results are not a complete audit history.</p>
  {kind === "tokens" && <p className="text-sm text-ink-muted">Access tokens can be revoked. Signed ID tokens cannot be recalled; their expiry is shown in record details when available.</p>}
  <section className="card">
   <form className="mb-4 flex flex-wrap items-end gap-3" onSubmit={e => { e.preventDefault(); setFilters({ ...draft, page: 1 }); }}>
    <label className="flex min-w-48 flex-1 flex-col gap-1.5 text-sm font-medium">Search activity<input type="search" className="input" placeholder="Client, user, email, or record ID" maxLength={254} value={draft.q} onChange={e => setDraft({ ...draft, q: e.target.value })} /></label>
    <label className="flex flex-col gap-1.5 text-sm font-medium">Status<select className="input" value={draft.status} onChange={e => setDraft({ ...draft, status: e.target.value })}><option value="">All statuses</option>{["active", "revoked", "expired", ...(kind === "transactions" ? ["completed"] : kind === "codes" ? ["consumed"] : [])].map(s => <option key={s} value={s}>{s}</option>)}</select></label>
    <button className="btn btn-primary" disabled={query.isFetching}>Search</button>
    <button type="button" className="btn btn-secondary" disabled={query.isFetching} onClick={() => void query.refetch()}>Refresh</button>
   </form>
   {query.isPending && <p role="status">Loading activity…</p>}
   {query.error && <p role="alert" className="mb-4 text-err">{query.error.message}</p>}
   {result && <><ActivityTable records={result.records} busy={query.isFetching || revoke.isPending} onRevoke={record => { revoke.reset(); setSelected(record); }} />
    <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-ink-muted"><span>{result.total} records · Page {result.page} of {pages} · 10 per page</span><div className="flex gap-2"><button className="btn btn-secondary btn-sm" disabled={query.isFetching || result.page <= 1} onClick={() => setFilters({ ...filters, page: result.page - 1 })}>Previous</button><button className="btn btn-secondary btn-sm" disabled={query.isFetching || result.page >= pages} onClick={() => setFilters({ ...filters, page: result.page + 1 })}>Next</button></div></div>
   </>}
  </section>
  {selected && <section ref={confirmation} tabIndex={-1} role="dialog" aria-modal="false" aria-labelledby="revoke-title" className="card border border-err">
   <h2 id="revoke-title" className="text-lg font-semibold">Confirm revocation</h2><p className="my-3 text-sm">{consequences[kind]}</p><p className="mb-3 break-all text-xs text-ink-muted">{selected.clientName || selected.clientId} · {selected.userEmail || selected.userId || "Awaiting sign-in"} · {selected.id}</p>
   {revoke.error && <p role="alert" className="mb-3 text-err">{revoke.error.message}</p>}
   <div className="flex gap-2"><button className="btn btn-danger" disabled={revoke.isPending || (revoke.error instanceof ApiError && revoke.error.code === "ACTIVITY_NOT_ACTIVE")} onClick={() => revoke.mutate(selected)}>{revoke.isPending ? "Revoking…" : "Confirm revoke"}</button><button className="btn btn-secondary" disabled={revoke.isPending} onClick={() => setSelected(null)}>Cancel</button></div>
  </section>}
 </div>;
}
