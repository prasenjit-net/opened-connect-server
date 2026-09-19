import { useEffect, useRef, useState, type FormEvent } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { api } from "../lib/api";
import RegistrationSecret from "./RegistrationSecret";

export default function IssueInitialTokenDialog({ onClose }: { onClose: () => void }) {
    const dialog = useRef<HTMLDialogElement>(null);
    const [trigger] = useState(() => document.activeElement instanceof HTMLElement ? document.activeElement : null);
    const settings = useQuery({ queryKey: ["registration-settings"], queryFn: api.registrationSettings });
    const [label, setLabel] = useState(""); const [uses, setUses] = useState(1); const [hours, setHours] = useState(24);
    const [token, setToken] = useState(""); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
    useEffect(() => {
        const element = dialog.current!;
        const overflow = document.body.style.overflow;
        element.showModal(); document.body.style.overflow = "hidden";
        return () => { element.close(); document.body.style.overflow = overflow; trigger?.focus(); };
    }, [trigger]);
    useEffect(() => { if (token) dialog.current?.querySelector<HTMLButtonElement>("button")?.focus(); }, [token]);
    const issue = async (event: FormEvent) => {
        event.preventDefault(); if (busy || token) return; setBusy(true); setError("");
        try { const result = await api.issueRegistrationToken({ label, maxUses: uses, lifetimeHours: hours }); setToken(result.token); }
        catch (e) { setError(e instanceof Error ? e.message : "Unable to issue token."); }
        finally { setBusy(false); }
    };
    return <dialog ref={dialog} aria-modal="true" aria-labelledby="issue-iat-title" onCancel={event => { event.preventDefault(); if (!busy) onClose(); }} className="m-auto max-h-[90dvh] w-[calc(100%-2rem)] max-w-2xl overflow-y-auto rounded-xl border border-line bg-surface p-5 text-ink shadow-xl backdrop:bg-black/50 sm:p-6">
        <h2 id="issue-iat-title" className="text-lg font-semibold">Issue an initial access token</h2>
        {token ? <div className="mt-4"><RegistrationSecret token={token} onDismiss={onClose} /></div> : <>
            <p className="my-3 text-sm text-ink-muted">Allow a developer to register a limited number of clients. This token grants no administration or user access.</p>
            {settings.data && <div className="mb-4 rounded-lg bg-surface-2 p-3 text-sm"><p>New registrations are <strong>{settings.data.enabled ? "enabled" : "disabled"}</strong>.</p>{settings.data.endpoint && <code className="mt-2 block break-all">POST {settings.data.endpoint}</code>}{!settings.data.enabled && <p className="mt-2 text-ink-muted">Enable oidc.registrationEnabled in server configuration to accept registrations. Tokens expire from the moment they are issued.</p>}</div>}
            {settings.error && <p role="alert" className="mb-3 text-sm text-err">Unable to load registration settings. {settings.error.message}</p>}
            <form onSubmit={issue} className="flex flex-col gap-4">
                <label className="flex flex-col gap-1.5 text-sm">Label<input autoFocus className="input" required maxLength={100} value={label} onChange={e => setLabel(e.target.value)} placeholder="Developer or integration name" /></label>
                <div className="grid gap-4 sm:grid-cols-2">
                    <label className="flex flex-col gap-1.5 text-sm">Maximum registrations<input className="input" type="number" min={1} max={100} required value={uses} onChange={e => setUses(Number(e.target.value))} /></label>
                    <label className="flex flex-col gap-1.5 text-sm">Lifetime (hours)<input className="input" type="number" min={1} max={720} required value={hours} onChange={e => setHours(Number(e.target.value))} /></label>
                </div>
                {error && <p role="alert" className="text-sm text-err">{error}</p>}
                <div className="flex flex-wrap gap-2 border-t border-line pt-4"><button type="submit" className="btn btn-primary" disabled={busy}>{busy ? "Issuing…" : "Issue token"}</button><button type="button" className="btn btn-secondary" disabled={busy} onClick={onClose}>Cancel</button></div>
            </form>
        </>}
        <Link to="/activity/initial-access-tokens" disabled={busy} className="mt-4 inline-block text-sm text-accent hover:underline aria-disabled:cursor-not-allowed aria-disabled:opacity-50">View initial access token activity</Link>
    </dialog>;
}
