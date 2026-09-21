import { Link } from "@tanstack/react-router";
import {
  IconActivity, IconClock, IconFileText, IconKey, IconLayers,
  IconMonitor, IconServer, IconShield, IconExternal,
} from "../icons";
import { sessionKinds, sessionLabels, type SessionKind } from "../lib/sessions";
import { activityKinds, activityLabels, type ActivityKind } from "../lib/activity";

type ActivityCategory = ActivityKind | SessionKind | "initial-access-tokens";

const categoryIcons = {
  "op-sessions": IconServer,
  "app-sessions": IconMonitor,
  "logout-events": IconExternal,
  transactions: IconActivity,
  codes: IconFileText,
  tokens: IconKey,
  consents: IconShield,
  refresh: IconClock,
  "initial-access-tokens": IconLayers,
};

const categories: { kind: ActivityCategory; label: string }[] = [
  ...sessionKinds.map(kind => ({ kind, label: sessionLabels[kind] })),
  ...activityKinds.map(kind => ({ kind, label: activityLabels[kind] })),
  { kind: "initial-access-tokens", label: "Initial access tokens" },
];

export default function ActivityNavigation({ current }: { current: ActivityCategory }) {
  return (
    <nav className="border-b border-line" aria-label="Activity categories">
      <ul className="m-0 flex list-none gap-1 overflow-x-auto p-0 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {categories.map(({ kind, label }) => {
          const Icon = categoryIcons[kind];
          const active = current === kind;
          return (
            <li key={kind} className="shrink-0">
              <Link
                to={`/activity/${kind}`}
                aria-current={active ? "page" : undefined}
                className={`relative flex items-center gap-2 border-b-2 px-3 py-2.5 text-sm whitespace-nowrap transition-colors motion-reduce:transition-none ${
                  active
                    ? "border-accent font-semibold text-accent"
                    : "border-transparent text-ink-muted hover:border-line-strong hover:text-ink"
                }`}
              >
                <Icon size={16} className="shrink-0" />
                <span>{label}</span>
              </Link>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}
