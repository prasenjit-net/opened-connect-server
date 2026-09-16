import type { ScopeInfo } from "../lib/oidc";

export default function ConsentScreen({ clientName, scopes, busy, error, onApprove, onDeny }: {
  clientName: string;
  scopes: ScopeInfo[];
  busy: boolean;
  error: string;
  onApprove: () => void;
  onDeny: () => void;
}) {
  return <section className="card w-full max-w-[420px] p-8">
    <h1 className="text-xl font-semibold">{clientName}</h1>
    <p className="mb-4 mt-1 text-sm text-ink-muted">This application would like to:</p>
    <ul className="mb-6 flex flex-col gap-2 text-sm">
      {scopes.map((s) => <li key={s.scope} className="flex items-start gap-2">
        <span aria-hidden className="mt-0.5 text-accent">•</span>
        <span>{s.description || s.scope}</span>
      </li>)}
    </ul>
    {error && <p role="alert" className="mb-4 rounded-lg bg-err-soft p-3 text-sm text-err">{error}</p>}
    <div className="flex gap-3">
      <button type="button" className="btn btn-secondary flex-1" disabled={busy} onClick={onDeny}>Deny</button>
      <button type="button" className="btn btn-primary flex-1" disabled={busy} onClick={onApprove}>{busy ? "Approving…" : "Approve"}</button>
    </div>
  </section>;
}
