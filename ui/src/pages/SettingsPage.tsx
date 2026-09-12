import { useQuery } from '@tanstack/react-query'
import SectionHeader from '../components/SectionHeader'
import { metaApi } from '../services/api'

export default function SettingsPage() {
  const metaQuery = useQuery({ queryKey: ['meta'], queryFn: metaApi.get })

  if (metaQuery.isLoading) {
    return <div className="p-8 text-sm text-gray-500 dark:text-slate-400">Loading application metadata…</div>
  }

  if (metaQuery.error || !metaQuery.data) {
    return <div className="p-8 text-sm text-red-600 dark:text-red-300">Failed to load application metadata.</div>
  }

  const meta = metaQuery.data

  return (
    <div className="space-y-8 p-8">
      <SectionHeader
        title="Template Settings"
        description="The backend exposes starter metadata so you can verify config, linker flags, and local development wiring."
      />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h2 className="text-base font-semibold text-gray-900 dark:text-slate-100">Application</h2>
          <dl className="mt-4 space-y-3 text-sm">
            <div className="flex items-center justify-between gap-4 border-b border-gray-100 pb-3 dark:border-slate-800">
              <dt className="text-gray-500 dark:text-slate-400">Name</dt>
              <dd className="font-medium text-gray-900 dark:text-slate-100">{meta.name}</dd>
            </div>
            <div className="flex items-center justify-between gap-4 border-b border-gray-100 pb-3 dark:border-slate-800">
              <dt className="text-gray-500 dark:text-slate-400">Environment</dt>
              <dd className="font-medium text-gray-900 dark:text-slate-100">{meta.environment}</dd>
            </div>
            <div className="flex items-center justify-between gap-4 border-b border-gray-100 pb-3 dark:border-slate-800">
              <dt className="text-gray-500 dark:text-slate-400">Public URL</dt>
              <dd className="font-medium text-gray-900 dark:text-slate-100">{meta.url}</dd>
            </div>
            <div className="flex items-center justify-between gap-4">
              <dt className="text-gray-500 dark:text-slate-400">Vite Proxy URL</dt>
              <dd className="font-medium text-gray-900 dark:text-slate-100">{meta.uiProxy}</dd>
            </div>
          </dl>
        </section>

        <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h2 className="text-base font-semibold text-gray-900 dark:text-slate-100">Build Metadata</h2>
          <dl className="mt-4 space-y-3 text-sm">
            <div className="flex items-center justify-between gap-4 border-b border-gray-100 pb-3 dark:border-slate-800">
              <dt className="text-gray-500 dark:text-slate-400">Version</dt>
              <dd className="font-medium text-gray-900 dark:text-slate-100">{meta.version.version}</dd>
            </div>
            <div className="flex items-center justify-between gap-4 border-b border-gray-100 pb-3 dark:border-slate-800">
              <dt className="text-gray-500 dark:text-slate-400">Commit</dt>
              <dd className="font-medium text-gray-900 dark:text-slate-100">{meta.version.commit}</dd>
            </div>
            <div className="flex items-center justify-between gap-4">
              <dt className="text-gray-500 dark:text-slate-400">Build date</dt>
              <dd className="font-medium text-gray-900 dark:text-slate-100">{meta.version.buildDate}</dd>
            </div>
          </dl>
        </section>
      </div>

      <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <h2 className="text-base font-semibold text-gray-900 dark:text-slate-100">Rename Checklist</h2>
        <ul className="mt-4 space-y-3 text-sm text-gray-600 dark:text-slate-300">
          <li>Update `go.mod` to the final module path.</li>
          <li>Replace the starter app name in `config.yaml` and `.env`.</li>
          <li>Swap example pages and sample API responses for your domain modules.</li>
          <li>Push to GitHub and enable the repository’s template setting.</li>
        </ul>
      </section>
    </div>
  )
}
