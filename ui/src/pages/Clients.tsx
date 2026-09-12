import { Link } from "@tanstack/react-router";
import { useClientSearch } from "../context/ClientSearchContext";

export default function ClientsPage() {
 const { draft, setDraft, result, pending, error, searched, search, goToPage } = useClientSearch();
 const pages = Math.max(1,Math.ceil((result?.total ?? 0)/10));
 return <div className="flex flex-col gap-4">
  <div className="flex flex-wrap items-center justify-between gap-3">
   <p className="text-sm text-ink-muted">Search OpenID Connect clients by name or client ID.</p>
   <Link to="/clients/new" className="btn btn-primary">Add client</Link>
  </div>
  <section className="card">
   <form className="mb-4 flex items-end gap-3" onSubmit={(e) => { e.preventDefault(); search(); }}>
    <label className="flex flex-1 flex-col gap-1.5 text-sm font-medium">Search clients<input className="input" type="search" maxLength={254} value={draft.q} onChange={(e) => setDraft({ q: e.target.value })} placeholder="Name or client ID" /></label>
    <button className="btn btn-secondary" disabled={pending}>{pending ? "Searching…" : "Search"}</button>
   </form>
   {error && <p role="alert" className="mb-4 text-sm text-err">{error}</p>}
   {!searched && <p className="py-10 text-center text-sm text-ink-muted">Click Search to find clients. Leave the field empty to find all clients.</p>}
   {pending && <p role="status" className="py-4 text-sm text-ink-muted">Loading clients…</p>}
   {result && <>
    <div className="overflow-x-auto rounded-lg border border-line" aria-busy={pending}>
     <table className="w-full min-w-[640px] text-left text-sm">
      <thead className="bg-surface-2 font-mono text-xs text-ink-faint"><tr>{["Name","Client ID","Application","Authentication"].map((label) => <th key={label} className="px-4 py-3 font-medium">{label}</th>)}</tr></thead>
      <tbody>{result.clients.map((client) => <tr key={client.client_id} className="border-t border-line hover:bg-surface-2">
       <td className="px-4 py-3"><Link to="/clients/$clientId" params={{ clientId: client.client_id }} className="text-accent hover:underline">{client.client_name || "Unnamed client"}</Link></td>
       <td className="break-all px-4 py-3 font-mono text-xs"><Link to="/clients/$clientId" params={{ clientId: client.client_id }} className="hover:text-accent">{client.client_id}</Link></td>
       <td className="px-4 py-3">{client.application_type}</td><td className="px-4 py-3">{client.token_endpoint_auth_method}</td>
      </tr>)}
      {result.clients.length === 0 && <tr><td colSpan={4} className="py-10 text-center text-ink-muted">No clients match your search.</td></tr>}
      </tbody>
     </table>
    </div>
    <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-ink-muted">
     <span>{result.total} clients · Page {result.page} of {Math.max(pages,result.page)} · 10 per page</span>
     <div className="flex gap-2"><button className="btn btn-secondary btn-sm" disabled={pending || result.page <= 1} onClick={() => goToPage(result.page-1)}>Previous</button><button className="btn btn-secondary btn-sm" disabled={pending || result.page >= pages} onClick={() => goToPage(result.page+1)}>Next</button></div>
    </div>
   </>}
  </section>
 </div>;
}
