import { useState, type FormEvent } from "react";
import Badge from "../components/Badge";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api } from "../lib/api";

export default function ProfilePage() {
  const auth = useAuth();
  const { push } = useToast();
  const [name, setName] = useState(auth.user?.name ?? "");
  const [currentPassword, setCurrent] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [saving, setSaving] = useState(false);
  const [changing, setChanging] = useState(false);
  const [profileError, setProfileError] = useState("");
  const [passwordError, setPasswordError] = useState("");
  const save = async (event: FormEvent) => {
    event.preventDefault(); if (saving) return; setSaving(true); setProfileError("");
    try { await api.updateProfile(name); await auth.refresh(); push("success", "Profile updated."); }
    catch (error) { setProfileError(error instanceof Error ? error.message : "Unable to save profile."); }
    finally { setSaving(false); }
  };
  const changePassword = async (event: FormEvent) => {
    event.preventDefault(); if (changing) return; setPasswordError("");
    if (password !== confirm) { setPasswordError("Passwords do not match."); return; }
    setChanging(true);
    try { await api.changePassword(currentPassword, password); setCurrent(""); setPassword(""); setConfirm(""); auth.forget(); push("success", "Password changed. Sign in again with your new password."); }
    catch (error) { setPasswordError(error instanceof Error ? error.message : "Unable to change password."); }
    finally { setChanging(false); }
  };
  return <div className="flex max-w-[720px] flex-col gap-4">
    <section className="card">
      <div className="card-head"><h2>My profile</h2><Badge tone="accent">{auth.user?.role}</Badge></div>
      <form onSubmit={save} className="flex flex-col gap-4">
        <label className="flex flex-col gap-1.5 text-sm font-medium">Name<input className="input" autoComplete="name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} /></label>
        <div><p className="text-sm font-medium">Email</p><p className="mt-1 break-all text-sm text-ink-muted">{auth.user?.email}</p><p className="mt-1 text-xs text-ink-faint">Contact an administrator to change your email address or role.</p></div>
        {profileError && <p role="alert" className="text-sm text-err">{profileError}</p>}
        <button className="btn btn-primary self-start" disabled={saving}>{saving ? "Saving…" : "Save profile"}</button>
      </form>
    </section>
    <section className="card">
      <div className="card-head"><h2>Change password</h2></div>
      <p className="mb-4 text-sm text-ink-muted">Use 12–128 characters. Changing your password signs you out of all devices.</p>
      <form onSubmit={changePassword} className="flex flex-col gap-4">
        <label className="flex flex-col gap-1.5 text-sm font-medium">Current password<input className="input" type="password" autoComplete="current-password" required maxLength={128} value={currentPassword} onChange={(e) => setCurrent(e.target.value)} /></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">New password<input className="input" type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Confirm new password<input className="input" type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={confirm} onChange={(e) => setConfirm(e.target.value)} /></label>
        {passwordError && <p role="alert" className="text-sm text-err">{passwordError}</p>}
        <button className="btn btn-primary self-start" disabled={changing}>{changing ? "Changing…" : "Change password"}</button>
      </form>
    </section>
  </div>;
}
