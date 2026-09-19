import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "../context/AuthContext";
import { api } from "../lib/api";
import { activityKinds, activityLabels, activityDate } from "../lib/activity";
import ActivityTable from "../components/ActivityTable";
import Badge from "../components/Badge";

export default function DashboardPage() {
 const { user } = useAuth();
 if (user?.role !== "admin") return <section className="card"><h2 className="text-lg font-semibold">Welcome, {user?.name}</h2><p className="my-3 text-sm text-ink-muted">Manage your profile and account security.</p><Link to="/profile" className="btn btn-primary">My profile</Link></section>;
 return <AdminOverview />;
}
function AdminOverview() {
 const query = useQuery({ queryKey: ["activity-overview"], queryFn: ({ signal }) => api.activityOverview(signal), refetchInterval: 15_000 });
 const data = query.data;
 return <div className="flex flex-col gap-5">
  <div className="flex flex-wrap items-center justify-between gap-3"><div><h2 className="text-lg font-semibold">Server overview</h2><p className="mt-1 text-sm text-ink-muted">Current retained activity · Updates every 15 seconds</p></div><button className="btn btn-secondary" disabled={query.isFetching} onClick={() => void query.refetch()}>Refresh overview</button></div>
  {query.isPending && <p role="status">Loading overview…</p>}{query.error && <p role="alert" className="text-err">{query.error.message}</p>}
  {data && <>
   <div className="flex flex-wrap items-center gap-3 text-sm"><Badge tone={data.protocolEnabled ? "ok" : "warn"}>OpenID Connect {data.protocolEnabled ? "enabled" : "disabled"}</Badge><Link to="/users" className="text-accent hover:underline">{data.users} users</Link><Link to="/clients" className="text-accent hover:underline">{data.clients} clients</Link><span className="ml-auto text-xs text-ink-faint">Updated {activityDate(data.generatedAt)}</span></div>
   <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">{activityKinds.map(kind => <Link key={kind} to={`/activity/${kind}`} className="card transition-colors hover:bg-surface-2"><h3 className="text-sm font-medium text-ink-muted">{activityLabels[kind]}</h3><p className="my-3 text-3xl font-semibold">{(data.counts[kind]?.active ?? 0)}<span className="ml-2 text-sm font-normal text-ink-muted">active</span></p><p className="text-xs text-ink-faint">{(data.counts[kind]?.total ?? 0)} retained · {(data.counts[kind]?.revoked ?? 0)} revoked · {(data.counts[kind]?.expired ?? 0)} expired</p></Link>)}</div>
   <section className="card"><div className="card-head"><h2>Recent retained activity</h2></div><p className="mb-4 text-sm text-ink-muted">The 10 newest records across transactions, codes, tokens, refresh tokens, and consents. Expired records may be removed during cleanup.</p><ActivityTable records={data.recent} /></section>
  </>}
 </div>;
}
