import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import UserEditor from "../components/UserEditor";
import { useToast } from "../context/ToastContext";
import { api, type UserInput } from "../lib/api";

export default function UserCreatePage() {
  const client = useQueryClient();
  const navigate = useNavigate();
  const { push } = useToast();
  const save = async (input: UserInput, password: string) => {
    const user = await api.createUser({ ...input, password });
    client.setQueryData(["user", user.id], user);
    push("success", "User created.");
    // Replace the create entry: browser Back from the new detail returns to search.
    await navigate({ to: "/users/$userId", params: { userId: user.id }, replace: true });
  };
  return <div className="flex max-w-[900px] flex-col gap-4">
    <Link to="/users" className="self-start text-sm text-accent hover:underline">← Back to user search</Link>
    <UserEditor user={null} onSave={save} onCancel={() => { void navigate({ to: "/users" }); }} />
  </div>;
}
