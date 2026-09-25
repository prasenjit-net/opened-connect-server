import { Link } from "@tanstack/react-router";
import Badge from "../components/Badge";
import { useAuth } from "../context/AuthContext";
import { useUserSearch } from "../context/UserSearchContext";

export default function UsersPage() {
  const { user: currentUser } = useAuth();
  const { draft, setDraft, result, pending, error, searched, search, goToPage } = useUserSearch();
  const pages = Math.max(1, Math.ceil((result?.total ?? 0) / 10));

  return <div className="flex flex-col gap-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <p className="text-sm text-ink-muted">Search for a user to view and manage their account.</p>
      <Link to="/users/new" className="btn btn-primary">Add user</Link>
    </div>
    <section className="card">
      <form onSubmit={(event) => { event.preventDefault(); search(); }} className="mb-4 flex flex-wrap items-end gap-3">
        <label className="flex min-w-[180px] flex-1 flex-col gap-1.5 text-sm font-medium">
          Search users
          <input className="input" type="search" placeholder="Name or email" maxLength={254} value={draft.q} onChange={(event) => setDraft({ ...draft, q: event.target.value })} />
        </label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">
          Filter by role
          <select className="input" value={draft.role} onChange={(event) => setDraft({ ...draft, role: event.target.value })}>
            <option value="">All roles</option><option value="user">User</option><option value="admin">Admin</option>
          </select>
        </label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">
          Filter by status
          <select className="input" value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>
            <option value="">All statuses</option><option value="active">Active</option><option value="disabled">Disabled</option>
          </select>
        </label>
        <button type="submit" className="btn btn-secondary" disabled={pending}>{pending ? "Searching…" : "Search"}</button>
      </form>
      {error && <p role="alert" className="mb-4 rounded-lg bg-err-soft p-3 text-sm text-err">{error}</p>}
      {!searched && <p className="py-10 text-center text-sm text-ink-muted">Enter search criteria and click Search. Leave the fields empty to find all users.</p>}
      {pending && <div role="status" className="flex items-center gap-3 py-4 text-sm text-ink-muted"><div className="spinner" />Loading users…</div>}
      {result && <>
        <div className="overflow-x-auto rounded-lg border border-line" aria-busy={pending}>
          <table className="w-full min-w-[640px] border-collapse text-sm">
            <thead className="bg-surface-2 text-left font-mono text-xs text-ink-faint">
              <tr>{["Name", "Email", "Role", "Status"].map((label) => <th key={label} className="border-b border-line px-4 py-3 font-medium">{label}</th>)}</tr>
            </thead>
            <tbody>
              {result.users.map((user) => <tr key={user.id} className="border-b border-line last:border-b-0 hover:bg-surface-2">
                <td className="px-4 py-3 font-medium">
                  <Link to="/users/$userId" params={{ userId: user.id }} className="text-accent hover:underline">{user.name}</Link>
                  {user.id === currentUser?.id && <span className="ml-2 text-xs text-ink-faint">You</span>}
                </td>
                <td className="px-4 py-3"><Link to="/users/$userId" params={{ userId: user.id }} className="hover:text-accent hover:underline">{user.email}</Link></td>
                <td className="px-4 py-3"><Badge tone={user.role === "admin" ? "accent" : "neutral"}>{user.role}</Badge></td>
                <td className="px-4 py-3"><Badge tone={user.active ? "ok" : "warn"}>{user.active ? "Active" : "Disabled"}</Badge></td>
              </tr>)}
              {result.users.length === 0 && <tr><td colSpan={4} className="px-4 py-10 text-center text-ink-muted">No users match your search.</td></tr>}
            </tbody>
          </table>
        </div>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-ink-muted">
          <span>{result.total} users · Page {result.page} of {Math.max(pages, result.page)} · 10 per page</span>
          <div className="flex gap-2">
            <button className="btn btn-secondary btn-sm" disabled={pending || result.page <= 1} onClick={() => goToPage(result.page - 1)}>Previous</button>
            <button className="btn btn-secondary btn-sm" disabled={pending || result.page >= pages} onClick={() => goToPage(result.page + 1)}>Next</button>
          </div>
        </div>
      </>}
    </section>
  </div>;
}
