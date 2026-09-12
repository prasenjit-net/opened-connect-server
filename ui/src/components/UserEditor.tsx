import { useState, type FormEvent } from "react";
import type { Role, User, UserInput } from "../lib/api";

export default function UserEditor({ user, onSave, onCancel }: { user: User | null; onSave: (input: UserInput, password: string) => Promise<void>; onCancel: () => void }) {
  const [name, setName] = useState(user?.name ?? "");
  const [email, setEmail] = useState(user?.email ?? "");
  const [role, setRole] = useState<Role>(user?.role ?? "user");
  const [active, setActive] = useState(user?.active ?? true);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const submit = async (event: FormEvent) => {
    event.preventDefault(); if (busy) return; setBusy(true); setError("");
    try { await onSave({ name, email, role, active }, password); setPassword(""); }
    catch (error) { setError(error instanceof Error ? error.message : "Unable to save user."); }
    finally { setBusy(false); }
  };
  return <section className="card">
    <div className="card-head"><h2>{user ? "Edit user" : "Create user"}</h2></div>
    <form onSubmit={submit} className="flex flex-col gap-4">
      <div className="grid gap-4 md:grid-cols-2">
        <label className="flex flex-col gap-1.5 text-sm font-medium">Name<input className="input" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} /></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Email<input className="input" type="email" required maxLength={254} value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Role<select className="input" value={role} onChange={(e) => setRole(e.target.value as Role)}><option value="user">User</option><option value="admin">Admin</option></select></label>
        {user ? <label className="flex flex-col gap-1.5 text-sm font-medium">Status<select className="input" value={active ? "active" : "disabled"} onChange={(e) => setActive(e.target.value === "active")}><option value="active">Active</option><option value="disabled">Disabled</option></select></label> : <label className="flex flex-col gap-1.5 text-sm font-medium">Initial password<input className="input" type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} /><span className="text-xs font-normal text-ink-faint">12–128 characters. Share it securely with the user.</span></label>}
      </div>
      {user && <p className="text-xs text-ink-faint">Changing email, role, or status signs this user out of all devices. The last active admin cannot be disabled or demoted.</p>}
      {error && <p role="alert" className="rounded-lg bg-err-soft p-3 text-sm text-err">{error}</p>}
      <div className="flex gap-2"><button className="btn btn-primary" disabled={busy}>{busy ? "Saving…" : user ? "Save changes" : "Create user"}</button><button type="button" className="btn btn-secondary" disabled={busy} onClick={onCancel}>Cancel</button></div>
    </form>
  </section>;
}

