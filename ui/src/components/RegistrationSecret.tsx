import { useState } from "react";

export default function RegistrationSecret({ token, onDismiss }: { token: string; onDismiss: () => void }) {
 const [message, setMessage] = useState("");
 return <section className="card border-accent" aria-label="New registration credential">
  <h2 className="font-semibold">Save this registration token</h2>
  <p className="my-3 text-sm text-ink-muted">Copy it now and share it securely. It will disappear when you leave this page or dismiss it.</p>
  <code className="block break-all rounded-lg bg-surface-2 p-3 text-sm">{token}</code>
  <div className="mt-3 flex flex-wrap gap-2"><button type="button" className="btn btn-secondary" onClick={async () => { try { await navigator.clipboard.writeText(token); setMessage("Copied."); } catch { setMessage("Unable to copy. Select and copy the token above."); } }}>Copy token</button><button type="button" className="btn btn-secondary" onClick={onDismiss}>Dismiss token</button></div>
  {message && <p role="status" className="mt-2 text-sm">{message}</p>}
 </section>;
}
