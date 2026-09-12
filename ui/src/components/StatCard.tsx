import type { LucideIcon } from 'lucide-react'

interface StatCardProps {
  label: string
  value: string
  description: string
  icon: LucideIcon
  tone: string
}

export default function StatCard({ label, value, description, icon: Icon, tone }: StatCardProps) {
  return (
    <div className="rounded-xl border border-gray-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className={`mb-3 inline-flex rounded-lg p-2 ${tone}`}>
        <Icon className="h-5 w-5" />
      </div>
      <p className="text-xs font-medium uppercase tracking-wide text-gray-500 dark:text-slate-400">{label}</p>
      <p className="mt-1 text-2xl font-bold text-gray-900 dark:text-slate-100">{value}</p>
      <p className="mt-1 text-sm text-gray-500 dark:text-slate-400">{description}</p>
    </div>
  )
}
