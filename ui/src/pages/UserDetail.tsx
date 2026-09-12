import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useState } from "react";
import UserEditor from "../components/UserEditor";
import { useAuth } from "../context/AuthContext";
import { useToast } from "../context/ToastContext";
import { useUserSearch } from "../context/UserSearchContext";
import { api, type UserInput } from "../lib/api";

export default function UserDetailPage() {
  const { userId } = useParams({ from: "/authenticated/users/$userId" });
  const client = useQueryClient();
  const auth = useAuth();
  const { push } = useToast();
  const { updateResult, removeResult } = useUserSearch();
  const navigate = useNavigate();
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState("");
  const query = useQuery({ queryKey: ["user", userId], queryFn: () => api.user(userId) });

  const save = async (input: UserInput) => {
    const saved = await api.updateUser(userId, input);
    client.setQueryData(["user", userId], saved);
    updateResult(saved);
    push("success", "User updated.");
    await auth.refresh();
  };
  const remove = async () => {
    if (deleting) return;
    setDeleting(true); setDeleteError("");
    try {
      await api.deleteUser(userId);
      removeResult(userId);
      client.removeQueries({ queryKey: ["user", userId] });
      push("success", "User deleted.");
      await auth.refresh();
      await navigate({ to: "/users", replace: true });
    } catch (error) {
      setDeleteError(error instanceof Error ? error.message : "Unable to delete user.");
    } finally { setDeleting(false); }
  };

  return <div className="flex max-w-[900px] flex-col gap-4">
    <Link to="/users" className="self-start text-sm text-accent hover:underline">← Back to user search</Link>
    {query.isPending ? <div role="status" className="card flex items-center gap-3"><div className="spinner" />Loading user…</div> : query.isError ? <section className="card" role="alert"><p className="mb-3 text-sm text-err">{query.error.message}</p><button className="btn btn-secondary" onClick={() => void query.refetch()}>Retry</button></section> : <>
      <section className="card">
        <h2 className="text-lg font-semibold">{query.data.name}</h2>
        <p className="mt-1 break-all text-sm text-ink-muted">{query.data.email}</p>
        <p className="mt-3 text-xs text-ink-faint">Created {new Date(query.data.createdAt).toLocaleString()}</p>
      </section>
      <UserEditor key={query.data.id} user={query.data} onSave={save} onCancel={() => { void navigate({ to: "/users" }); }} />
      <section className="card">
        <h2 className="mb-3 font-semibold">Delete user</h2>
        {confirmDelete ? <div role="alertdialog" aria-labelledby="delete-title" aria-describedby="delete-description">
          <h3 id="delete-title" className="font-medium">Delete {query.data.name}?</h3>
          <p id="delete-description" className="my-3 text-sm text-ink-muted">This permanently deletes {query.data.email} and signs them out of all devices.</p>
          {deleteError && <p role="alert" className="mb-3 text-sm text-err">{deleteError}</p>}
          <div className="flex gap-2"><button className="btn btn-danger" disabled={deleting} onClick={() => void remove()}>{deleting ? "Deleting…" : "Confirm delete"}</button><button className="btn btn-secondary" disabled={deleting} onClick={() => setConfirmDelete(false)}>Keep user</button></div>
        </div> : <button className="btn btn-danger" onClick={() => setConfirmDelete(true)}>Delete user</button>}
      </section>
    </>}
  </div>;
}
