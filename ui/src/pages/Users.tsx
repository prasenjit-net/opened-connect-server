import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useState, type FormEvent } from "react";
import Badge from "../components/Badge";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { api, type Role, type User, type UserInput } from "../lib/api";

function UserEditor({ user, onSave, onCancel }: { user: User | null; onSave: (input: UserInput, password: string) => Promise<void>; onCancel: () => void }) {
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

export default function UsersPage() {
  const client = useQueryClient();
  const auth = useAuth();
  const { push } = useToast();
  const [search, setSearch] = useState("");
  const [query, setQuery] = useState("");
  const [role, setRole] = useState("");
  const [status, setStatus] = useState("");
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState<User | null | undefined>(undefined);
  const [deleting, setDeleting] = useState<User | null>(null);
  const [deleteBusy, setDeleteBusy] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const users = useQuery({ queryKey: ["users", query, role, status, page], queryFn: () => api.users({ q: query, role, status, page }) });
  const save = async (input: UserInput, password: string) => {
    if (editing) await api.updateUser(editing.id, input);
    else await api.createUser({ ...input, password });
    push("success", editing ? "User updated." : "User created."); setEditing(undefined);
    await client.invalidateQueries({ queryKey: ["users"] });
    await auth.refresh();
  };
  const remove = async () => {
    if (!deleting || deleteBusy) return; setDeleteBusy(true); setDeleteError("");
    try { await api.deleteUser(deleting.id); setDeleting(null); push("success", "User deleted."); await client.invalidateQueries({ queryKey: ["users"] }); await auth.refresh(); }
    catch (error) { setDeleteError(error instanceof Error ? error.message : "Unable to delete user."); }
    finally { setDeleteBusy(false); }
  };
  const data = users.data;
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / (data?.pageSize ?? 20)));
  return <div className="flex flex-col gap-4">
    <div className="flex flex-wrap items-center justify-between gap-3"><p className="text-sm text-ink-muted">Manage accounts, roles, and access.</p><button className="btn btn-primary" onClick={() => { setEditing(null); setDeleting(null); }}>Add user</button></div>
    {editing !== undefined && <UserEditor key={editing?.id ?? "create"} user={editing} onSave={save} onCancel={() => setEditing(undefined)} />}
    {deleting && <section className="card border-err" role="alertdialog" aria-labelledby="delete-title" aria-describedby="delete-description">
      <h2 id="delete-title" className="font-semibold">Delete {deleting.name}?</h2><p id="delete-description" className="my-3 text-sm text-ink-muted">This permanently deletes {deleting.email} and signs them out of all devices.</p>
      {deleteError && <p role="alert" className="mb-3 text-sm text-err">{deleteError}</p>}
      <div className="flex gap-2"><button className="btn btn-danger" disabled={deleteBusy} onClick={() => void remove()}>{deleteBusy ? "Deleting…" : "Confirm delete"}</button><button className="btn btn-secondary" disabled={deleteBusy} onClick={() => setDeleting(null)}>Cancel</button></div>
    </section>}
    <section className="card">
      <form onSubmit={(e) => { e.preventDefault(); setQuery(search); setPage(1); }} className="mb-4 flex flex-wrap items-end gap-3">
        <label className="flex min-w-[180px] flex-1 flex-col gap-1.5 text-sm font-medium">Search users<input className="input" type="search" placeholder="Name or email" maxLength={254} value={search} onChange={(e) => setSearch(e.target.value)} /></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Filter by role<select className="input" value={role} onChange={(e) => { setRole(e.target.value); setPage(1); }}><option value="">All roles</option><option value="user">User</option><option value="admin">Admin</option></select></label>
        <label className="flex flex-col gap-1.5 text-sm font-medium">Filter by status<select className="input" value={status} onChange={(e) => { setStatus(e.target.value); setPage(1); }}><option value="">All statuses</option><option value="active">Active</option><option value="disabled">Disabled</option></select></label>
        <button className="btn btn-secondary">Search</button>
      </form>
      {users.isPending ? <div className="flex items-center gap-3 py-8 text-sm text-ink-muted"><div className="spinner" />Loading users…</div> : users.isError ? <div role="alert"><p className="mb-3 text-sm text-err">{users.error.message}</p><button className="btn btn-secondary" onClick={() => void users.refetch()}>Retry</button></div> : <>
        <div className="overflow-x-auto rounded-lg border border-line"><table className="w-full min-w-[720px] border-collapse text-sm">
          <thead className="bg-surface-2 text-left font-mono text-xs text-ink-faint"><tr>{["Name", "Email", "Role", "Status", "Actions"].map((label) => <th key={label} className="border-b border-line px-4 py-3 font-medium">{label}</th>)}</tr></thead>
          <tbody>{data?.users.map((user) => <tr key={user.id} className="border-b border-line last:border-b-0 hover:bg-surface-2">
            <td className="px-4 py-3 font-medium">{user.name}{user.id === auth.user?.id && <span className="ml-2 text-xs text-ink-faint">You</span>}</td><td className="px-4 py-3">{user.email}</td><td className="px-4 py-3"><Badge tone={user.role === "admin" ? "accent" : "neutral"}>{user.role}</Badge></td><td className="px-4 py-3"><Badge tone={user.active ? "ok" : "warn"}>{user.active ? "Active" : "Disabled"}</Badge></td><td className="px-4 py-3"><div className="flex gap-2"><button className="btn btn-secondary btn-sm" aria-label={`Edit ${user.email}`} onClick={() => { setEditing(user); setDeleting(null); }}>Edit</button><button className="btn btn-danger btn-sm" aria-label={`Delete ${user.email}`} onClick={() => { setDeleting(user); setDeleteError(""); setEditing(undefined); }}>Delete</button></div></td>
          </tr>)}{data?.users.length === 0 && <tr><td colSpan={5} className="px-4 py-10 text-center text-ink-muted">No users match your search.</td></tr>}</tbody>
        </table></div>
        <div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-sm text-ink-muted"><span>{data?.total ?? 0} users · Page {data?.page ?? 1} of {pages}</span><div className="flex gap-2"><button className="btn btn-secondary btn-sm" disabled={(data?.page ?? 1) <= 1} onClick={() => setPage((data?.page ?? 1) - 1)}>Previous</button><button className="btn btn-secondary btn-sm" disabled={(data?.page ?? 1) >= pages} onClick={() => setPage((data?.page ?? 1) + 1)}>Next</button></div></div>
      </>}
    </section>
  </div>;
}
