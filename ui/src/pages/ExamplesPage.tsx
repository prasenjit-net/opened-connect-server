import { useQuery } from '@tanstack/react-query'
import { ArrowRight, TerminalSquare } from 'lucide-react'
import SectionHeader from '../components/SectionHeader'
import { exampleApi, healthApi } from '../services/api'

export default function ExamplesPage() {
  const healthQuery = useQuery({ queryKey: ['health'], queryFn: healthApi.get })
  const exampleQuery = useQuery({ queryKey: ['example'], queryFn: exampleApi.get })

  if (healthQuery.isLoading || exampleQuery.isLoading) {
    return <div className="p-8 text-sm text-gray-500 dark:text-slate-400">Loading examples…</div>
  }

  if (healthQuery.error || exampleQuery.error) {
    return <div className="p-8 text-sm text-red-600 dark:text-red-300">Unable to load example API payloads.</div>
  }

  return (
    <div className="space-y-8 p-8">
      <SectionHeader
        title="Example API Layer"
        description="Simple React Query fetchers and typed payloads are included so the template starts with a clean integration boundary."
      />

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-500 dark:text-slate-400">
            <TerminalSquare className="h-4 w-4" />
            GET /api/health
          </div>
          <pre className="mt-4 overflow-x-auto rounded-lg bg-slate-950 p-4 text-sm text-slate-100">
{JSON.stringify(healthQuery.data, null, 2)}
          </pre>
        </section>

        <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-500 dark:text-slate-400">
            <TerminalSquare className="h-4 w-4" />
            GET /api/example
          </div>
          <pre className="mt-4 overflow-x-auto rounded-lg bg-slate-950 p-4 text-sm text-slate-100">
{JSON.stringify(exampleQuery.data, null, 2)}
          </pre>
        </section>
      </div>

      <section className="rounded-xl border border-gray-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <h2 className="text-base font-semibold text-gray-900 dark:text-slate-100">Suggested starter workflow</h2>
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
          {[
            ['1', 'Add domain routes', 'Create handlers in internal/api and mount them under /api.'],
            ['2', 'Replace starter pages', 'Swap the example screens in ui/src/pages with your own modules.'],
            ['3', 'Ship one binary', 'Use make build to regenerate ui/dist and compile the embedded executable.'],
          ].map(([step, title, description]) => (
            <div key={step} className="rounded-lg border border-gray-200 p-4 dark:border-slate-800">
              <div className="flex items-center gap-2 text-sm font-semibold text-primary-700 dark:text-primary-300">
                Step {step}
                <ArrowRight className="h-4 w-4" />
              </div>
              <h3 className="mt-2 text-sm font-semibold text-gray-900 dark:text-slate-100">{title}</h3>
              <p className="mt-1 text-sm text-gray-500 dark:text-slate-400">{description}</p>
            </div>
          ))}
        </div>
      </section>
    </div>
  )
}
