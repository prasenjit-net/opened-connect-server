import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useState } from "react";
import ClientEditor from "../components/ClientEditor";
import { useClientSearch } from "../context/ClientSearchContext";
import { useToast } from "../context/ToastContext";
import { api } from "../lib/api";
import type { ClientMetadata, ClientResult } from "../lib/clients";

export default function ClientDetailPage() {
 const { clientId } = useParams({ from: "/authenticated/clients/$clientId" });
 const cache = useQueryClient();
 const navigate = useNavigate();
 const { updateResult, removeResult, secret, setSecret } = useClientSearch();
 const { push } = useToast();
 const [action, setAction] = useState<"delete" | "rotate" | null>(null);
 const [busy, setBusy] = useState(false);
 const [error, setError] = useState("");
 const query = useQuery({ queryKey: ["client",clientId], queryFn: () => api.client(clientId) });
 const accept = (result: ClientResult) => {
  const { client_secret, ...client } = result;
  cache.setQueryData(["client",clientId],client);
  updateResult(client);
  if (client_secret) setSecret({ id: clientId, value: client_secret });
  else if (!client.has_client_secret) setSecret(null);
 };
 const save = async (input: ClientMetadata) => { accept(await api.updateClient(clientId,input)); push("success","Client updated."); };
 const confirm = async () => {
  if (busy) return; setBusy(true); setError("");
  try {
   if (action === "delete") {
    await api.deleteClient(clientId); removeResult(clientId); setSecret(null);
    await navigate({ to: "/clients", replace: true });
    cache.removeQueries({ queryKey: ["client",clientId] });
    push("success","Client deleted.");
   } else {
    accept(await api.rotateClientSecret(clientId));
    setAction(null); push("success","Client secret rotated.");
   }
  } catch (error) { setError(error instanceof Error ? error.message : "Unable to complete the action."); }
  finally { setBusy(false); }
 };
 return <div className="flex w-full min-w-0 flex-col gap-4">
  <Link to="/clients" className="self-start text-sm text-accent hover:underline">← Back to client search</Link>
  {query.isPending ? <p role="status" className="card">Loading client…</p> : query.isError ? <section role="alert" className="card"><p className="mb-3 text-err">{query.error.message}</p><button className="btn btn-secondary" onClick={() => void query.refetch()}>Retry</button></section> : <>
   <section className="card">
    <h2 className="break-words text-lg font-semibold">{query.data.client_name || "Unnamed client"}</h2>
    <p className="mt-2 break-all font-mono text-sm">Client ID: {query.data.client_id}</p>
    <p className="mt-2 text-xs text-ink-faint">Created {new Date(query.data.client_id_issued_at*1000).toLocaleString()} · Updated {new Date(query.data.updated_at*1000).toLocaleString()}</p>
   </section>
   {!query.data.protocol_compatible && <section role="alert" className="card border border-warn">
    <h2 className="font-semibold text-warn">Not usable with the OpenID Connect protocol endpoints yet</h2>
    <p className="my-3 text-sm text-ink-muted">This client's registered settings request capabilities this provider does not implement yet. It will be rejected at /authorize and /token until its metadata is adjusted:</p>
    <ul className="list-inside list-disc text-sm text-ink-muted">
     {query.data.protocol_incompatibilities?.map((reason) => <li key={reason}>{reason}</li>)}
    </ul>
   </section>}
   {secret?.id === clientId && <section className="card border border-accent" aria-label="New client secret">
    <h2 className="font-semibold">Save your client secret</h2>
    <p className="my-3 text-sm text-ink-muted">Copy this secret now. It will not be shown again after you leave this page or dismiss it.</p>
    <code className="block break-all rounded bg-surface-2 p-3 text-sm">{secret.value}</code>
    <button className="btn btn-secondary mt-3" onClick={() => setSecret(null)}>Dismiss secret</button>
   </section>}
   <ClientEditor key={clientId} client={query.data} onSave={save} onCancel={() => { void navigate({ to: "/clients" }); }} />
   <section className="card">
    <h2 className="mb-3 font-semibold">Client credentials and deletion</h2>
    <p className="mb-3 text-sm text-ink-muted">{query.data.has_client_secret ? "A client secret is configured and does not expire. Rotation immediately replaces it." : "This client does not use a shared secret."}</p>
    {action ? <div role="alertdialog" aria-labelledby="client-action-title">
     <h3 id="client-action-title" className="mb-3 font-medium">{action === "delete" ? "Permanently delete this client?" : "Replace the current client secret?"}</h3>
     {error && <p role="alert" className="mb-3 text-err">{error}</p>}
     <div className="flex gap-2"><button className="btn btn-danger" disabled={busy} onClick={() => void confirm()}>{action === "delete" ? "Confirm delete" : "Confirm rotation"}</button><button className="btn btn-secondary" disabled={busy} onClick={() => setAction(null)}>Cancel</button></div>
    </div> : <div className="flex gap-2">{query.data.has_client_secret && <button className="btn btn-secondary" onClick={() => { setError(""); setAction("rotate"); }}>Rotate secret</button>}<button className="btn btn-danger" onClick={() => { setError(""); setAction("delete"); }}>Delete client</button></div>}
   </section>
  </>}
 </div>;
}
