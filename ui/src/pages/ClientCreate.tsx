import { useQueryClient } from "@tanstack/react-query";
import { Link, useNavigate } from "@tanstack/react-router";
import ClientEditor from "../components/ClientEditor";
import { useClientSearch } from "../context/ClientSearchContext";
import { useToast } from "../context/ToastContext";
import { api } from "../lib/api";
import type { ClientMetadata } from "../lib/clients";

export default function ClientCreatePage() {
 const cache = useQueryClient();
 const navigate = useNavigate();
 const { setSecret } = useClientSearch();
 const { push } = useToast();
 const save = async (input: ClientMetadata) => {
  const { client_secret, ...client } = await api.createClient(input);
  cache.setQueryData(["client",client.client_id],client);
  setSecret(client_secret ? { id: client.client_id, value: client_secret } : null);
  push("success","Client created.");
  await navigate({ to: "/clients/$clientId", params: { clientId: client.client_id }, replace: true });
 };
 return <div className="flex w-full min-w-0 flex-col gap-4">
  <Link to="/clients" className="self-start text-sm text-accent hover:underline">← Back to client search</Link>
  <ClientEditor onSave={save} onCancel={() => { void navigate({ to: "/clients" }); }} />
 </div>;
}
