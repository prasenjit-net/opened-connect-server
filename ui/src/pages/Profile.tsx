import { useState, type FormEvent } from "react";
import ProfileFields from "../components/ProfileFields";
import { editableClaims, parseCustomAttributes } from "../lib/profile";
import Badge from "../components/Badge";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api } from "../lib/api";

export default function ProfilePage() {
  const auth = useAuth();
  const { push } = useToast();
  const [claims, setClaims] = useState(() => editableClaims(auth.user));
  const [custom, setCustom] = useState(JSON.stringify(auth.user?.custom_attributes ?? {}, null, 2));
  const [email, setEmail] = useState(auth.user?.email ?? "");
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
    try {
      const saved = await api.updateProfile({ ...claims, custom_attributes: parseCustomAttributes(custom), name, email });
      if (saved.email !== auth.user?.email) {
        auth.forget();
        push("success", "Email updated. Sign in again with your new email address.");
      } else {
        await auth.refresh(); push("success", "Profile updated.");
      }
    }
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
  return <div className="flex w-full min-w-0 flex-col gap-4">
    <section className="card">
      <div className="card-head"><h2>My profile</h2><Badge tone="accent">{auth.user?.role}</Badge></div>
      <form onSubmit={save} className="flex flex-col gap-6">
        <fieldset className="form-section"><legend className="form-section-title">Account essentials</legend><p className="form-section-description">Manage your display name and sign-in email.</p><div className="grid gap-4 md:grid-cols-2">
          <label className="flex flex-col gap-1.5 text-sm font-medium">Name<input className="input" autoComplete="name" required maxLength={100} value={name} onChange={(e) => setName(e.target.value)} /></label>
          <label className="flex flex-col gap-1.5 text-sm font-medium">Email<input className="input" type="email" required maxLength={254} value={email} onChange={(e) => setEmail(e.target.value)} /></label>
        </div><p className="mt-4 text-sm leading-relaxed text-ink-muted">Email verified: {auth.user?.email_verified ? "Yes" : "No"} · Phone verified: {auth.user?.phone_number_verified ? "Yes" : "No"}. Changing either value clears its verification. Changing your email also signs you out of all devices and revokes connected app access.</p>
          <p className="break-all text-xs text-ink-faint">Subject: {auth.user?.sub ?? auth.user?.id} · Updated: {auth.user?.updatedAt}</p>
        </fieldset>
        <ProfileFields value={claims} onChange={setClaims} custom={custom} onCustomChange={setCustom} />
        {profileError && <p role="alert" className="text-sm text-err">{profileError}</p>}
        <div className="form-actions"><button type="submit" className="btn btn-primary" disabled={saving}>{saving ? "Saving…" : "Save profile"}</button></div>
      </form>
    </section>
    <section className="card">
      <div className="card-head"><h2>Change password</h2></div>
      <p className="mb-4 text-sm text-ink-muted">Use 12–128 characters. Changing your password signs you out of all devices.</p>
      <form onSubmit={changePassword} className="grid gap-4 lg:grid-cols-3">
        <label className="flex flex-col gap-1.5 text-sm font-medium">Current password<input className="input" type="password" autoComplete="current-password" required maxLength={128} value={currentPassword} onChange={(e) => setCurrent(e.target.value)} /></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">New password<input className="input" type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Confirm new password<input className="input" type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={confirm} onChange={(e) => setConfirm(e.target.value)} /></label>
        {passwordError && <p role="alert" className="text-sm text-err">{passwordError}</p>}
        <button type="submit" className="btn btn-primary justify-self-start lg:col-span-3" disabled={changing}>{changing ? "Changing…" : "Change password"}</button>
      </form>
    </section>
  </div>;
}
