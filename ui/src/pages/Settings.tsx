import { useMutation } from "@tanstack/react-query";
import type { ReactElement, ReactNode } from "react";
import { useConfig } from "../context/ConfigContext";
import { useTheme, type ThemeMode } from "../context/ThemeContext";
import { useToast } from "../context/ToastContext";
import { IconMonitor, IconMoon, IconServer, IconSun } from "../icons";
import { api } from "../lib/api";

const MODES: { mode: ThemeMode; label: string; icon: ReactElement }[] = [
  { mode: "light", label: "Light", icon: <IconSun size={16} /> },
  { mode: "auto", label: "System", icon: <IconMonitor size={16} /> },
  { mode: "dark", label: "Dark", icon: <IconMoon size={16} /> },
];

function ConfigRow({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-4 border-b border-line py-2 text-sm last:border-b-0">
      <dt className="shrink-0 text-ink-muted">{label}</dt>
      <dd className="m-0 text-right font-medium [overflow-wrap:anywhere]">{children}</dd>
    </div>
  );
}

export default function SettingsPage() {
  const config = useConfig();
  const { mode, setMode } = useTheme();
  const { push, notifyError } = useToast();

  const healthCheck = useMutation({
    mutationFn: api.health,
    onSuccess: (health) => push("success", `Server is ${health.status} — v${health.version}`),
    onError: notifyError,
  });

  return (
    <div className="flex max-w-[720px] flex-col gap-4">
      <section className="card">
        <div className="card-head">
          <h2>Appearance</h2>
          <span className="card-hint">stored in this browser</span>
        </div>
        <div className="inline-flex gap-1 self-start rounded-lg bg-surface-2 p-1">
          {MODES.map((entry) => (
            <button
              key={entry.mode}
              className={`inline-flex cursor-pointer items-center gap-1.5 rounded-md px-3.5 py-1.5 text-[0.85rem] font-medium transition-colors ${
                mode === entry.mode
                  ? "bg-surface text-ink shadow-sm"
                  : "text-ink-muted hover:text-ink"
              }`}
              onClick={() => setMode(entry.mode)}
            >
              {entry.icon} {entry.label}
            </button>
          ))}
        </div>
        <p className="mt-3 text-[0.8rem] leading-relaxed text-ink-faint">
          “System” follows the operating system preference. Until a choice is saved
          here, the UI uses the server-side default (<code>{config.ui.defaultTheme}</code>).
        </p>
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Server configuration</h2>
          <span className="card-hint">from config.yaml</span>
        </div>
        <dl className="mb-1 flex flex-col">
          <ConfigRow label="App name">{config.ui.appName}</ConfigRow>
          <ConfigRow label="Tagline">{config.ui.tagline}</ConfigRow>
          <ConfigRow label="Default theme">{config.ui.defaultTheme}</ConfigRow>
          <ConfigRow label="Server version">v{config.version}</ConfigRow>
          <ConfigRow label="Server started">
            {new Date(config.startedAtMs).toLocaleString()}
          </ConfigRow>
          <ConfigRow label="Repository">
            {config.ui.repoUrl ? (
              <a
                className="text-accent hover:underline"
                href={config.ui.repoUrl}
                target="_blank"
                rel="noreferrer"
              >
                {config.ui.repoUrl}
              </a>
            ) : (
              "—"
            )}
          </ConfigRow>
        </dl>
        <p className="mt-3 text-[0.8rem] leading-relaxed text-ink-faint">
          Served by <code>GET /api/public/config</code>. Edit <code>config.yaml</code> or pass CLI
          flags (e.g. <code>--port 9000</code>) to change these — no UI rebuild needed.
        </p>
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Server health</h2>
          <span className="card-hint">on-demand check</span>
        </div>
        <button
          className="btn btn-secondary"
          onClick={() => healthCheck.mutate()}
          disabled={healthCheck.isPending}
        >
          <IconServer size={16} /> Check server health
        </button>
      </section>
    </div>
  );
}
