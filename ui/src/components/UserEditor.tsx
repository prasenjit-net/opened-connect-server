import { useState, type FormEvent } from "react";
import ProfileFields from "./ProfileFields";
import { editableClaims, parseCustomAttributes } from "../lib/profile";
import type { Role, User, UserInput } from "../lib/api";

export default function UserEditor({ user, onSave, onCancel }: { user: User | null; onSave: (input: UserInput, password: string) => Promise<void>; onCancel: () => void }) {
  const [claims, setClaims] = useState(() => editableClaims(user));
  const [custom, setCustom] = useState(JSON.stringify(user?.custom_attributes ?? {}, null, 2));
  const [emailVerified, setEmailVerified] = useState(user?.email_verified ?? false);
  const [phoneVerified, setPhoneVerified] = useState(user?.phone_number_verified ?? false);
  const [name, setName] = useState(user?.name ?? "");
  const [email, setEmail] = useState(user?.email ?? "");
  const [role, setRole] = useState<Role>(user?.role ?? "user");
  const [active, setActive] = useState(user?.active ?? true);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (busy) return; setBusy(true); setError("");
    try { await onSave({ ...claims, custom_attributes: parseCustomAttributes(custom), name, email, role, active, email_verified: emailVerified, phone_number_verified: phoneVerified }, password); setPassword(""); }
    catch (error) { setError(error instanceof Error ? error.message : "Unable to save user."); }
    finally { setBusy(false); }
  };
  return <section className="card min-w-0">
    <div className="card-head"><h2>{user ? "Edit user" : "Create user"}</h2></div>
    <form onSubmit={submit} className="flex flex-col gap-6">
      <fieldset className="form-section"><legend className="form-section-title">Account essentials</legend><p className="form-section-description">Display name and email used to sign in.</p><div className="grid min-w-0 gap-4 md:grid-cols-2">
        <label className="flex min-w-0 flex-col gap-1.5 text-sm font-medium">Name<input className="input" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="flex min-w-0 flex-col gap-1.5 text-sm font-medium">Email<input className="input" type="email" required maxLength={254} value={email} onChange={(e) => { setEmail(e.target.value); setEmailVerified(false); }} /></label>
      </div></fieldset>
      <fieldset className="form-section"><legend className="form-section-title">Access and security</legend><p className="form-section-description">Users manage their own profile. Admins also manage users, clients, and server activity.</p><div className="grid min-w-0 gap-4 md:grid-cols-2">
        <label className="flex min-w-0 flex-col gap-1.5 text-sm font-medium">Role<select className="input" value={role} onChange={(e) => setRole(e.target.value as Role)}><option value="user">User</option><option value="admin">Admin</option></select></label>
        {user ? <label className="flex min-w-0 flex-col gap-1.5 text-sm font-medium">Status<select className="input" value={active ? "active" : "disabled"} onChange={(e) => setActive(e.target.value === "active")}><option value="active">Active</option><option value="disabled">Disabled</option></select></label> : <label className="flex min-w-0 flex-col gap-1.5 text-sm font-medium">Initial password<input className="input" type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} /><span className="text-xs font-normal text-ink-faint">12–128 characters. Share it securely with the user.</span></label>}
      </div>
      <div className="mt-5 flex flex-wrap gap-4 border-t border-line pt-4 text-sm">
       <label className="flex items-center gap-2"><input type="checkbox" checked={emailVerified} onChange={(e) => setEmailVerified(e.target.checked)} />Email verified</label>
       <label className="flex items-center gap-2"><input type="checkbox" checked={phoneVerified} disabled={!claims.phone_number} onChange={(e) => setPhoneVerified(e.target.checked)} />Phone number verified</label>
      </div>
      {user && <p className="mt-3 text-sm leading-relaxed text-ink-muted">Changing email, role, or status signs this user out of all devices. The last active admin cannot be disabled or demoted.</p>}
      </fieldset>
      <ProfileFields value={claims} onChange={(value) => { if (value.phone_number !== claims.phone_number) setPhoneVerified(false); setClaims(value); }} custom={custom} onCustomChange={setCustom} />
      {error && <p role="alert" className="rounded-lg bg-err-soft p-3 text-sm text-err">{error}</p>}
      <div className="form-actions"><button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Saving…" : user ? "Save changes" : "Create user"}</button><button type="button" className="btn btn-secondary" disabled={busy} onClick={onCancel}>Cancel</button></div>
    </form>
  </section>;
}

