import { useState } from "react";
import { api } from "../lib/api";
import RegistrationSecret from "./RegistrationSecret";

export default function ClientRegistrationAccess({ clientId, active, onChanged }: {clientId: string; active: boolean; onChanged: (active: boolean) => void}) {
 const [action, setAction] = useState<"issue" | "revoke" | null>(null);
 const [token, setToken] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
 const confirm = async () => {
  if (busy || !action) return; setBusy(true); setError("");
  try {
   if (action === "issue") { const result = await api.issueClientRegistrationToken(clientId); setToken(result.token); }
   else { await api.revokeClientRegistrationToken(clientId); setToken(""); }
   onChanged(action === "issue"); setAction(null);
  } catch (e) { setError(e instanceof Error ? e.message : "Unable to change registration access."); }
  finally { setBusy(false); }
 };
 return <section className="card">
  <h2 className="mb-3 font-semibold">Registration configuration access</h2>
  <p className="mb-3 text-sm text-ink-muted">{active ? "A registration access token is active." : "No registration access token is active."} This credential can read this client's configuration, including its client secret. It does not grant user or admin access and does not expire automatically.</p>
  {token && <RegistrationSecret key={token} token={token} onDismiss={() => setToken("")} />}
  {error && <p role="alert" className="my-3 text-sm text-err">{error}</p>}
    {action ? <div role="alertdialog" aria-labelledby="registration-action-title" className="mt-3"><h3 id="registration-action-title" className="font-medium">{action === "revoke" ? "Revoke configuration access?" : active ? "Replace the registration access token?" : "Issue a registration access token?"}</h3><p className="my-3 text-sm text-ink-muted">{active ? "The current registration token will stop working immediately. " : ""}Client login credentials and existing user grants stay unchanged.</p><div className="flex flex-wrap gap-2"><button type="button" className="btn btn-danger" disabled={busy} onClick={() => void confirm()}>Confirm {action === "revoke" ? "revocation" : "issuance"}</button><button type="button" className="btn btn-secondary" disabled={busy} onClick={() => setAction(null)}>Cancel</button></div></div> : <div className="mt-3 flex flex-wrap gap-2"><button type="button" className="btn btn-secondary" disabled={busy || !!token} onClick={() => setAction("issue")}>{active ? "Replace registration token" : "Issue registration token"}</button>{active && <button type="button" className="btn btn-danger" disabled={busy} onClick={() => setAction("revoke")}>Revoke registration access</button>}</div>}
 </section>;
}
