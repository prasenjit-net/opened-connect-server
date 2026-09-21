import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "../lib/api";
import { sessionKinds, sessionLabels, type SessionKind, type SessionRecord } from "../lib/sessions";
import ActivityNavigation from "../components/ActivityNavigation";
import { useAuth } from "../context/AuthContext";

const stamp = (value: string) => !value || value.startsWith("0001-") ? "—" : new Date(value).toLocaleString();
export default function SessionsPage({kind: initialKind = "op-sessions", admin = false}: {kind?: SessionKind; admin?: boolean}) {
 const [kind, setKind] = useState(initialKind);
 const [filters, setFilters] = useState({q: new URLSearchParams(window.location.search).get("q") ?? "", status: "", page: 1});
 const [selected, setSelected] = useState<{record?: SessionRecord; scope?: string; revoke?: boolean; userId?: string} | null>(null);
 const [password, setPassword] = useState(""); const [offline, setOffline] = useState(false);
 const dialog = useRef<HTMLDialogElement>(null); const cache = useQueryClient(); const auth = useAuth();
 const [message, setMessage] = useState("");
 const query = useQuery({queryKey: ["session-activity", admin, kind, filters], queryFn: ({signal}) => api.sessionActivity(kind, admin, filters, signal), refetchInterval: selected ? false : 15_000});
 useEffect(() => { if (selected) dialog.current?.showModal(); else dialog.current?.close(); }, [selected]);
 const mutation = useMutation({mutationFn: async () => {
  if (selected?.userId) return api.endUserSessions(selected.userId, password, offline);
  if (selected?.revoke && selected.record?.clientId) return api.revokeAppAccess(selected.record.clientId, password);
  return api.endSession(kind, selected?.record?.id ?? "", admin, {scope: selected?.scope, password, revokeOffline: offline});
 }, onSuccess: async result => {
  const endsCurrent = kind === "op-sessions" && (selected?.record?.current || selected?.scope === "all" || selected?.userId === auth.user?.id);
  setSelected(null);setPassword("");setOffline(false);
  if (result.continueTo) { auth.forget(); window.location.assign(result.continueTo); return; }
  if (endsCurrent) { auth.forget(); return; }
  setMessage("Provider state updated. App notifications may be pending, unsupported, or unconfirmed.");
  await cache.invalidateQueries({queryKey:["session-activity"]});
 }});
 const select = (value: NonNullable<typeof selected>) => {mutation.reset();setPassword("");setOffline(false);setSelected(value);};
 const rows = query.data?.records ?? [];
 return <div className="flex flex-col gap-4">
  {admin ? <ActivityNavigation current={kind}/> : <><h2 className="text-xl font-semibold">Manage your sessions</h2><nav className="flex flex-wrap gap-2" aria-label="Your session categories">{sessionKinds.map(value => <button key={value} className={`btn ${kind === value ? "btn-primary" : "btn-secondary"}`} onClick={() => {setKind(value);setFilters({...filters,page:1});}}>{sessionLabels[value]}</button>)}</nav></>}
  <h2 className="text-lg font-semibold">{sessionLabels[kind]}</h2>
  <p className="text-sm text-ink-muted">These are sessions known to the provider. App-only logout and activity inside an app are not observable here. Last seen means the last provider interaction. Ended records are retained for 30 days.</p>
  {!admin && kind === "op-sessions" && <div className="flex flex-wrap gap-2"><button className="btn btn-secondary" onClick={() => select({scope:"other"})}>Sign out other sessions</button><button className="btn btn-secondary" onClick={() => select({scope:"all"})}>Sign out all sessions</button></div>}
  {message && <p role="status">{message}</p>}
  <section className="card">
   <form className="flex flex-wrap items-end gap-3 mb-4" onSubmit={e => e.preventDefault()}>
    <label className="flex flex-col gap-1">Search<input className="input" type="search" maxLength={254} value={filters.q} onChange={e => setFilters({...filters,q:e.target.value,page:1})} placeholder="User, app, or session ID"/></label>
    <label className="flex flex-col gap-1">Status<select className="input" value={filters.status} onChange={e => setFilters({...filters,status:e.target.value,page:1})}><option value="">All statuses</option>{(kind === "logout-events" ? ["ended","pending","delivering","acknowledged","failed","unconfirmed","browser_unavailable","unsupported"] : ["active","ended","expired"]).map(s => <option key={s}>{s}</option>)}</select></label>
   </form>
   {query.isPending && <p role="status">Loading sessions…</p>}
   {query.error && <p role="alert">{query.error.message}</p>}
   {!query.isPending && !query.error && rows.length === 0 && <p>No matching records.</p>}
   {rows.length > 0 && <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr><th className="p-2 text-left">Session / application</th><th className="p-2 text-left">State</th><th className="p-2 text-left">Activity</th><th className="p-2 text-left">Actions</th></tr></thead><tbody>{rows.map(row => <tr key={row.id} className="border-t border-line">
    <td className="p-2"><strong>{row.clientName || row.clientId || row.userName || "Provider session"}</strong>{row.current && <span className="ml-2">Current session</span>}<p className="text-ink-muted">{row.device || row.userName}</p><details><summary>Details</summary><dl><dt>ID</dt><dd className="break-all">{row.id}</dd><dt>Provider session</dt><dd className="break-all">{row.opSessionId}</dd><dt>Created</dt><dd>{stamp(row.createdAt)}</dd><dt>Expiry</dt><dd>{stamp(row.expiresAt)}</dd><dt>Ended</dt><dd>{stamp(row.endedAt)}</dd>{row.reason && <><dt>Reason</dt><dd>{row.reason}</dd></>}{row.actor && <><dt>Actor</dt><dd>{row.actor}</dd></>}{row.channel && <><dt>Channel / attempts</dt><dd>{row.channel} / {row.attempts ?? 0}{row.httpStatus ? ` (HTTP ${row.httpStatus})` : ""}</dd></>}{row.errorCode && <><dt>Last delivery error</dt><dd>{row.errorCode}</dd><dt>Next attempt</dt><dd>{stamp(row.nextAttempt ?? "")}</dd></>}{row.history?.map((attempt,index) => <div key={index}><dt>Attempt {index+1}</dt><dd>{stamp(attempt.at)} · {attempt.httpStatus || attempt.errorCode || "pending"}</dd></div>)}</dl></details></td>
    <td className="p-2">{row.status}{row.deliveryStatuses.map(status => <p key={status} className="text-ink-muted">{status}</p>)}</td>
    <td className="p-2">{stamp(row.lastSeenAt)}{kind === "op-sessions" && <p>{row.appCount} known app associations</p>}</td>
    <td className="p-2"><div className="flex flex-col gap-2">{kind !== "logout-events" && row.status === "active" && <button className="btn btn-secondary" onClick={() => select({record:row})}>Sign out</button>}{admin && kind === "logout-events" && row.channel === "backchannel" && row.status === "failed" && <button className="btn btn-secondary" onClick={() => select({record:row})}>Retry notification</button>}{!admin && kind === "app-sessions" && <button className="btn btn-secondary" onClick={() => select({record:row,revoke:true})}>Revoke app access</button>}{admin && kind === "op-sessions" && <button className="btn btn-secondary" onClick={() => select({userId:row.userId})}>Sign out user sessions</button>}{kind === "op-sessions" && <button className="btn btn-secondary" onClick={() => {if(admin){window.location.assign(`/activity/app-sessions?q=${encodeURIComponent(row.id)}`);return;}setKind("app-sessions");setFilters({q:row.id,status:"",page:1});}}>View apps</button>}</div></td>
   </tr>)}</tbody></table></div>}
   <div className="flex items-center gap-3 mt-4"><button className="btn btn-secondary" disabled={(query.data?.page ?? 1) <= 1} onClick={() => setFilters({...filters,page:Math.max(1,filters.page-1)})}>Previous</button><span>Page {query.data?.page ?? 1} · {query.data?.total ?? 0} records</span><button className="btn btn-secondary" disabled={(query.data?.page ?? 1)*10 >= (query.data?.total ?? 0)} onClick={() => setFilters({...filters,page:filters.page+1})}>Next</button></div>
  </section>
  <dialog aria-label="Confirm session action" ref={dialog} className="card max-w-lg bg-surface text-ink" onCancel={() => setSelected(null)}>
   <form onSubmit={e => {e.preventDefault();mutation.mutate();}} className="flex flex-col gap-4"><h2 className="text-lg font-semibold">{selected?.revoke ? "Revoke app access?" : kind === "logout-events" ? "Retry notification?" : "Confirm sign out"}</h2>
    <p>{selected?.revoke ? "This revokes consent and tokens, including approved offline access, for this application." : kind === "app-sessions" ? "End this app association. Provider SSO remains available, so a later sign-in may restore access. Offline grants are preserved." : kind === "logout-events" ? "Retry the server logout notification within its delivery window." : `End ${selected?.userId ? "all provider sessions for this user" : selected?.scope === "all" ? "all your provider sessions" : selected?.scope === "other" ? "your other provider sessions" : "this provider session"} and request logout from their connected apps. Remote browser-only logout cannot be confirmed.`}</p>
    {(selected?.scope || selected?.userId) && <label><input type="checkbox" checked={offline} onChange={e => setOffline(e.target.checked)}/> Also revoke all approved offline access</label>}
    {(selected?.scope || selected?.revoke || selected?.userId) && <label className="flex flex-col gap-1">Confirm your password<input className="input" type="password" autoComplete="current-password" required value={password} onChange={e => setPassword(e.target.value)}/></label>}
    {mutation.error && <p role="alert">{mutation.error.message}</p>}
	    <div className="flex gap-2"><button className="btn btn-primary" type="submit" disabled={mutation.isPending}>Confirm</button><button className="btn btn-secondary" type="button" onClick={() => setSelected(null)}>Cancel</button></div>
   </form>
  </dialog>
 </div>;
}
