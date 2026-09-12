import { useQuery } from '@tanstack/react-query'
import { Activity, Binary, Box, Globe } from 'lucide-react'
import SectionHeader from '../components/SectionHeader'
import StatCard from '../components/StatCard'
import StatusBadge from '../components/StatusBadge'
import { exampleApi, healthApi, metaApi } from '../services/api'

export default function DashboardPage() {
  const healthQuery = useQuery({ queryKey: ['health'], queryFn: healthApi.get, refetchInterval: 10000 })
  const exampleQuery = useQuery({ queryKey: ['example'], queryFn: exampleApi.get })
  const metaQuery = useQuery({ queryKey: ['meta'], queryFn: metaApi.get })

  if (healthQuery.isLoading || exampleQuery.isLoading || metaQuery.isLoading) {
    return (
      <div className="p-8">
        <div className="space-y-6 animate-pulse">
          <div className="h-8 w-56 rounded bg-gray-200 dark:bg-slate-800" />
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            {Array.from({ length: 4 }).map((_, index) => (
              <div key={index} className="h-36 rounded-xl bg-gray-200 dark:bg-slate-800" />
            ))}
          </div>
        </div>
      </div>
    )
  }

  if (healthQuery.error || exampleQuery.error || metaQuery.error) {
    return (
      <div className="p-8">
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-700 dark:border-red-900/40 dark:bg-red-950/40 dark:text-red-300">
          Failed to load dashboard data.
        </div>
      </div>
    )
  }

  if (!healthQuery.data || !exampleQuery.data || !metaQuery.data) {
    return null
  }

  const health = healthQuery.data
  const example = exampleQuery.data
  const meta = metaQuery.data

  return (
    <div className="space-y-8 p-8">
      <SectionHeader
        title="Dashboard"
        description="A generalized admin shell based on the reference project’s layout and card system."
        action={<StatusBadge status={health.status} />}
      />

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Status" value={health.status.toUpperCase()} description="Server health from /api/health" icon={Activity} tone="bg-emerald-50 text-emerald-600 dark:bg-emerald-900/20 dark:text-emerald-300" />
        <StatCard label="Environment" value={meta.environment} description="Current app environment" icon={Globe} tone="bg-sky-50 text-sky-600 dark:bg-sky-900/20 dark:text-sky-300" />
        <StatCard label="Frontend" value={example.frontendDir} description="Embedded Vite output directory" icon={Box} tone="bg-violet-50 text-violet-600 dark:bg-violet-900/20 dark:text-violet-300" />
        <StatCard label="Version" value={meta.version.version} description="Injected by Go linker flags" icon={Binary} tone="bg-amber-50 text-amber-600 dark:bg-amber-900/20 dark:text-amber-300" />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h2 className="text-base font-semibold text-gray-900 dark:text-slate-100">Template Features</h2>
          <p className="mt-1 text-sm text-gray-500 dark:text-slate-400">{example.summary}</p>
          <div className="mt-4 flex flex-wrap gap-2">
            {example.features.map((feature) => (
              <span key={feature} className="rounded-full bg-primary-50 px-3 py-1 text-sm font-medium text-primary-700 dark:bg-primary-900/30 dark:text-primary-200">
                {feature}
              </span>
            ))}
          </div>
        </section>

        <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <h2 className="text-base font-semibold text-gray-900 dark:text-slate-100">Quickstart</h2>
          <div className="mt-4 space-y-3">
            {example.quickstart.map((step, index) => (
              <div key={step} className="flex items-start gap-3 rounded-lg border border-gray-200 p-3 dark:border-slate-800">
                <span className="flex h-7 w-7 items-center justify-center rounded-full bg-slate-100 text-sm font-semibold text-slate-700 dark:bg-slate-800 dark:text-slate-200">
                  {index + 1}
                </span>
                <code className="code-chip">{step}</code>
              </div>
            ))}
          </div>
        </section>
      </div>

      <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <h2 className="text-base font-semibold text-gray-900 dark:text-slate-100">Starter File Guide</h2>
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
          {health.documents.map((document) => (
            <div key={document} className="rounded-lg border border-dashed border-gray-300 p-4 dark:border-slate-700">
              <div className="text-sm font-semibold text-gray-900 dark:text-slate-100">{document}</div>
              <p className="mt-1 text-sm text-gray-500 dark:text-slate-400">Use this area for your own domain modules once the template has been renamed.</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
