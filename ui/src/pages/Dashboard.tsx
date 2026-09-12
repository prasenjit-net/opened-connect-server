import { Link } from "@tanstack/react-router";
import { useConfig } from "../context/ConfigContext";
import { IconDashboard } from "../icons";

export default function DashboardPage() {
  const { ui } = useConfig();
  return (
    <section className="card flex min-h-[360px] flex-col items-center justify-center gap-4 text-center">
      <span className="inline-flex rounded-xl bg-accent-soft p-3 text-accent">
        <IconDashboard size={28} />
      </span>
      <div>
        <h2 className="text-lg font-semibold">{ui.appName}</h2>
        <p className="mt-2 max-w-md text-sm text-ink-muted">Your workspace is ready. There’s nothing to display yet.</p>
      </div>
      <div className="mt-1 flex flex-wrap justify-center gap-2">
        <Link to="/components" className="btn btn-primary">Explore components</Link>
        <Link to="/settings" className="btn btn-secondary">Settings</Link>
      </div>
    </section>
  );
}
