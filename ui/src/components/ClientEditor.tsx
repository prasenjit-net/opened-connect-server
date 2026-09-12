import { useState, type FormEvent } from "react";
import { clientMetadata, metadataSections, type ClientMetadata, type OIDCClient } from "../lib/clients";

export default function ClientEditor({ client, onSave, onCancel }: {
 client?: OIDCClient; onSave: (input: ClientMetadata) => Promise<void>; onCancel: () => void;
}) {
 const [initial] = useState(() => clientMetadata(client));
 const [fields, setFields] = useState<Record<string, string>>(() => Object.fromEntries(Object.entries(initial).map(([k,v]) => [k, Array.isArray(v) ? v.join("\n") : String(v ?? "")])));
 const [authTime, setAuthTime] = useState(initial.require_auth_time === true);
 const [jwks, setJwks] = useState(initial.jwks ? JSON.stringify(initial.jwks, null, 2) : "");
 const [localized, setLocalized] = useState(JSON.stringify(Object.fromEntries(Object.entries(initial).filter(([k]) => k.includes("#"))),null,2));
 const [busy, setBusy] = useState(false);
 const [error, setError] = useState("");
 const submit = async (event: FormEvent) => {
  event.preventDefault(); if (busy) return; setBusy(true); setError("");
  try {
   const input: ClientMetadata = { require_auth_time: authTime };
   for (const section of metadataSections) for (const [key,,kind] of section.fields) {
    const value = fields[key] ?? "";
    if (value.trim() !== "") input[key as string] = kind === "list" ? value.split("\n").map((item) => item.trim()).filter(Boolean) : kind === "number" ? Number(value) : value.trim();
   }
   if (jwks.trim()) {
    const value: unknown = JSON.parse(jwks);
    if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("JWKS must be a JSON object.");
    input.jwks = value as Record<string, unknown>;
   }
   const translated: unknown = JSON.parse(localized);
   if (!translated || typeof translated !== "object" || Array.isArray(translated)) throw new Error("Localized metadata must be a JSON object.");
   for (const [k,v] of Object.entries(translated)) {
    if (!/^(client_name|logo_uri|client_uri|policy_uri|tos_uri)#[A-Za-z0-9-]+$/.test(k) || typeof v !== "string") throw new Error("Use language-tagged display metadata names and string values.");
    input[k] = v;
   }
   await onSave(input);
  } catch (error) { setError(error instanceof Error ? error.message : "Unable to save client."); }
  finally { setBusy(false); }
 };
 const options: Record<string,string[]> = {
  application: ["web","native"], auth: ["client_secret_basic","client_secret_post","client_secret_jwt","private_key_jwt","none"], subject: ["","public","pairwise"],
 };
 return <section className="card">
  <div className="card-head"><h2>{client ? "Edit client" : "Create client"}</h2></div>
  <form onSubmit={submit} className="flex flex-col gap-6">
   {metadataSections.map((section) => <fieldset key={section.title}>
    <legend className="mb-3 font-semibold">{section.title}</legend>
    <div className="grid gap-4 md:grid-cols-2">
     {section.fields.map(([key,label,kind]) => <label key={key} className="flex flex-col gap-1.5 text-sm font-medium">{label}
      {kind === "list" ? <textarea className="input min-h-24 font-mono text-sm" required={key === "redirect_uris"} maxLength={12000} value={fields[key] ?? ""} onChange={(e) => setFields({ ...fields, [key]: e.target.value })} placeholder={key === "redirect_uris" ? "https://app.example.com/callback" : "One value per line"} />
       : options[kind] ? <select className="input" value={fields[key] ?? ""} onChange={(e) => setFields({ ...fields, [key]: e.target.value })}>{options[kind].map((v) => <option key={v} value={v}>{v || "Provider default"}</option>)}</select>
       : <input className="input" type={kind} min={kind === "number" ? 0 : undefined} step={kind === "number" ? 1 : undefined} maxLength={2048} value={fields[key] ?? ""} onChange={(e) => setFields({ ...fields, [key]: e.target.value })} />}
      {kind === "list" && <span className="text-xs font-normal text-ink-faint">{key === "response_types" ? "One response per line; for example, code id_token stays on one line." : "One value per line."}</span>}
     </label>)}
    </div>
   </fieldset>)}
   <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={authTime} onChange={(e) => setAuthTime(e.target.checked)} />Require authentication time</label>
   <label className="flex flex-col gap-1.5 text-sm font-medium">JWKS (JSON)
    <textarea className="input min-h-32 font-mono" maxLength={12000} value={jwks} onChange={(e) => setJwks(e.target.value)} />
    <span className="text-xs font-normal text-ink-faint">Public keys only. Specify this or a JWKS URI.</span>
   </label>
   <label className="flex flex-col gap-1.5 text-sm font-medium">Localized metadata (JSON)
    <textarea className="input min-h-24 font-mono" maxLength={12000} value={localized} onChange={(e) => setLocalized(e.target.value)} />
    <span className="text-xs font-normal text-ink-faint">For example: {"{"}"client_name#fr": "Mon application"{"}"}</span>
   </label>
   {error && <p role="alert" className="rounded-lg bg-err-soft p-3 text-sm text-err">{error}</p>}
   <div className="flex gap-2"><button className="btn btn-primary" disabled={busy}>{busy ? "Saving…" : client ? "Save changes" : "Create client"}</button><button type="button" className="btn btn-secondary" disabled={busy} onClick={onCancel}>Cancel</button></div>
  </form>
 </section>;
}
