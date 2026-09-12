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
        title="Server Settings"
        description="View the current application configuration and build information."
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
        <h2 className="text-base font-semibold text-gray-900 dark:text-slate-100">Configuration</h2>
        <p className="mt-4 text-sm text-gray-600 dark:text-slate-300">
          These values are read-only. Update config.yaml or the APP_ environment variables and restart the server to apply changes.
        </p>
      </section>
    </div>
  )
}
