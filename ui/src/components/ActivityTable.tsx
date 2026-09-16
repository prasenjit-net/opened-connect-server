import { Link } from "@tanstack/react-router";
import Badge from "./Badge";
import { activityDate, activityLabels, type ActivityRecord } from "../lib/activity";

export default function ActivityTable({ records, onRevoke, busy = false }: { records: ActivityRecord[]; onRevoke?: (record: ActivityRecord) => void; busy?: boolean }) {
 return <div className="min-w-0 max-w-full overflow-x-auto rounded-lg border border-line" aria-busy={busy}>
  <table className="w-full min-w-[880px] table-fixed text-left text-sm">
   <thead className="bg-surface-2 font-mono text-xs text-ink-faint"><tr>{["Record", "Client / user", "Status", "Scopes", "Created / expires", ...(onRevoke ? ["Action"] : [])].map(label => <th key={label} className="px-4 py-3 font-medium">{label}</th>)}</tr></thead>
   <tbody>{records.map(record => <tr key={record.id} className="border-t border-line align-top hover:bg-surface-2">
    <td className="px-4 py-3"><span className="font-medium">{activityLabels[record.kind]}</span><details className="mt-1 text-xs text-ink-muted"><summary className="cursor-pointer">Record details</summary><p className="mt-2 max-w-52 break-all font-mono">{record.id}</p>{record.idTokenExpiresAt && <p className="mt-2">ID token expires: {activityDate(record.idTokenExpiresAt)}</p>}</details></td>
    <td className="px-4 py-3"><Link to="/clients/$clientId" params={{ clientId: record.clientId }} className="block break-words text-accent [overflow-wrap:anywhere] hover:underline">{record.clientName || record.clientId}</Link><div className="mt-1 text-xs text-ink-muted">{record.userId ? <Link to="/users/$userId" params={{ userId: record.userId }} className="break-words hover:underline [overflow-wrap:anywhere]">{record.userEmail || record.userName || record.userId}</Link> : "Awaiting sign-in"}</div></td>
    <td className="px-4 py-3"><Badge tone={record.status === "active" ? "ok" : record.status === "revoked" ? "err" : "neutral"}>{record.status}</Badge></td>
    <td className="max-w-48 break-words px-4 py-3 text-xs text-ink-muted">{record.scopes?.join(", ") || "—"}</td>
    <td className="px-4 py-3 text-xs"><div>{activityDate(record.createdAt)}</div><div className="mt-1 text-ink-muted">Expires: {activityDate(record.expiresAt)}</div></td>
    {onRevoke && <td className="px-4 py-3">{record.canRevoke ? <button className="btn btn-danger btn-sm" disabled={busy} onClick={() => onRevoke(record)}>Revoke</button> : <span className="text-ink-faint">—</span>}</td>}
   </tr>)}
   {records.length === 0 && <tr><td colSpan={onRevoke ? 6 : 5} className="py-10 text-center text-ink-muted">No activity records match.</td></tr>}
   </tbody>
  </table>
 </div>;
}
