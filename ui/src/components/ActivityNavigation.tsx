import { Link } from "@tanstack/react-router";
import { activityKinds, activityLabels, type ActivityKind } from "../lib/activity";

export default function ActivityNavigation({ current }: { current: ActivityKind | "initial-access-tokens" }) {
 return <nav className="flex flex-wrap gap-2" aria-label="Activity categories">
  {activityKinds.map(kind => <Link key={kind} to={`/activity/${kind}`} aria-current={current === kind ? "page" : undefined} className={`btn ${current === kind ? "btn-primary" : "btn-secondary"}`}>{activityLabels[kind]}</Link>)}
  <Link to="/activity/initial-access-tokens" aria-current={current === "initial-access-tokens" ? "page" : undefined} className={`btn ${current === "initial-access-tokens" ? "btn-primary" : "btn-secondary"}`}>Initial access tokens</Link>
 </nav>;
}
