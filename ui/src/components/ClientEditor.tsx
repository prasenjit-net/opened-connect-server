import ListField from "./ListField";
import { useId, useState, type FormEvent } from "react";
import { clientMetadata, metadataSections, signingAlgorithms, encryptionAlgorithms, encryptionMethods, clientListChoices, type ClientMetadata, type OIDCClient } from "../lib/clients";

export default function ClientEditor({ client, onSave, onCancel }: {
 client?: OIDCClient; onSave: (input: ClientMetadata) => Promise<void>; onCancel: () => void;
}) {
 const sectionId = useId();
 const [initial] = useState(() => clientMetadata(client));
 const [fields, setFields] = useState<Record<string, string>>(() => Object.fromEntries(Object.entries(initial).map(([k,v]) => [k, Array.isArray(v) ? v.join("\n") : String(v ?? "")])));
 const oauthOnly = !!fields.grant_types && !fields.grant_types.split("\n").some(g => g === "authorization_code" || g === "implicit");
 const sections = metadataSections.filter(section => !oauthOnly || !["Login requirements", "Subject privacy", "ID token protection", "UserInfo protection", "Request objects"].includes(section.title));
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
    if (oauthOnly && (key === "response_types" || key === "redirect_uris")) { input[key] = []; continue; }
    const value = fields[key] ?? "";
    if (clientListChoices[key] && !value.trim()) throw new Error(`Select at least one ${key === "response_types" ? "response type" : "grant type"}.`);
    if (value.trim() !== "") input[key as string] = kind === "list" ? [...new Set(value.split("\n").map((item) => item.trim()).filter(Boolean))] : kind === "number" ? Number(value) : value.trim();
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
 return <section className="card min-w-0">
  <div className="card-head"><h2>{client ? "Edit client" : "Create client"}</h2></div>
  <nav aria-label="Client settings sections" className="mb-6 flex flex-wrap gap-2">{sections.map((section, index) => <a key={section.title} className="rounded-lg border border-line px-3 py-2 text-xs font-medium text-ink-muted hover:bg-surface-2 hover:text-ink" href={`#${sectionId}-${index}`}>{section.title}</a>)}</nav>
  <form onSubmit={submit} className="flex flex-col gap-6">
   <label className="flex flex-col gap-1.5 text-sm font-medium">Client purpose<select className="input" value={oauthOnly ? "oauth" : "openid"} onChange={e => setFields(current => ({ ...current, grant_types: e.target.value === "oauth" ? "client_credentials" : "authorization_code", response_types: e.target.value === "oauth" ? "" : "code" }))}><option value="openid">OpenID Connect sign-in</option><option value="oauth">OAuth API access</option></select><span className="text-xs text-ink-muted">API clients do not need sign-in redirects. After saving, configure OAuth permissions below.</span></label>
   {sections.map((section, index) => <fieldset id={`${sectionId}-${index}`} key={section.title} className="form-section scroll-mt-24">
    <legend className="form-section-title">{section.title}</legend>
    <p className="form-section-description">{section.description}</p>
    <div className="grid min-w-0 gap-4 lg:grid-cols-2">
     {section.fields.map(([key,label,kind]) => {
      if (oauthOnly && (key === "redirect_uris" || key === "response_types")) return null;
      const value = fields[key] ?? "";
      const change = (next: string) => setFields(current => ({ ...current, [key]: next }));
      if (clientListChoices[key]) {
       const selected = value.split("\n").filter(Boolean);
       const choices = [...new Set([...clientListChoices[key], ...selected])];
       return <fieldset key={key} className="min-w-0 rounded-lg border border-line p-3"><legend className="px-1 text-sm font-medium">{label}</legend><div className="grid gap-2 sm:grid-cols-2">{choices.map(choice => <label key={choice} className="flex min-w-0 items-start gap-2 text-sm"><input type="checkbox" className="mt-1 shrink-0" checked={selected.includes(choice)} onChange={e => change((e.target.checked ? [...selected, choice] : selected.filter(item => item !== choice)).join("\n"))} /><span className="min-w-0 break-words [overflow-wrap:anywhere]">{choice}{!["code", "authorization_code", "client_credentials", "password", "refresh_token"].includes(choice) && <span className="block text-xs text-ink-faint">Not supported by this provider yet</span>}{["client_credentials", "password", "refresh_token"].includes(choice) && <span className="block text-xs text-ink-faint">Requires explicit OAuth permission</span>}</span></label>)}</div></fieldset>;
      }
      if (kind === "list") return <ListField key={key} label={label} value={value} onChange={change} required={key === "redirect_uris"} type={key === "contacts" ? "email" : key.endsWith("uris") ? "url" : "text"} placeholder={key === "redirect_uris" ? "https://app.example.com/callback" : key === "contacts" ? "admin@example.com" : undefined} />;
      const algorithms = key.endsWith("_enc") ? encryptionMethods : key.includes("encryption_alg") || key.includes("encrypted_response_alg") ? encryptionAlgorithms : key.endsWith("_alg") ? signingAlgorithms.filter(alg => key !== "token_endpoint_auth_signing_alg" || alg !== "none") : undefined;
      const choices = algorithms ? ["", ...algorithms] : options[kind];
      return <label key={key} className="flex min-w-0 flex-col gap-1.5 text-sm font-medium">{label}
       {choices ? <select className="input" value={value} onChange={e => change(e.target.value)}>{[...new Set([...choices, ...(value ? [value] : [])])].map(choice => <option key={choice} value={choice}>{choice || (key === "id_token_signed_response_alg" ? "Provider default (RS256)" : "Not specified / provider default")}</option>)}</select>
        : <input className="input" type={kind} min={kind === "number" ? 0 : undefined} step={kind === "number" ? 1 : undefined} maxLength={2048} value={value} onChange={e => change(e.target.value)} />}
       {key === "default_max_age" && <span className="text-xs font-normal text-ink-faint">Leave empty to use the provider default; 0 requires a fresh login.</span>}
      </label>;
     })}
    </div>
    {section.title === "Client authentication and keys" && <>
   <label className="flex flex-col gap-1.5 text-sm font-medium">JWKS (JSON)
    <textarea className="input min-h-32 font-mono" maxLength={12000} value={jwks} onChange={(e) => setJwks(e.target.value)} />
    <span className="text-xs font-normal text-ink-faint">Public keys only. Specify this or a JWKS URI.</span>
   </label>
    </>}
    {section.title === "Login requirements" && <>
   <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={authTime} onChange={(e) => setAuthTime(e.target.checked)} />Require authentication time</label>
    </>}
    {section.title === "Branding and contacts" && <details className="form-disclosure"><summary>Translations <span className="font-normal text-ink-muted">· Optional localized branding</span></summary>
   <label className="flex flex-col gap-1.5 text-sm font-medium">Localized metadata (JSON)
    <textarea className="input min-h-24 font-mono" maxLength={12000} value={localized} onChange={(e) => setLocalized(e.target.value)} />
    <span className="text-xs font-normal text-ink-faint">For example: {"{"}"client_name#fr": "Mon application"{"}"}</span>
   </label>
    </details>}
   </fieldset>)}
   {error && <p role="alert" className="rounded-lg bg-err-soft p-3 text-sm text-err">{error}</p>}
    <div className="form-actions"><button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Saving…" : client ? "Save changes" : "Create client"}</button><button type="button" className="btn btn-secondary" disabled={busy} onClick={onCancel}>Cancel</button></div>
  </form>
 </section>;
}
