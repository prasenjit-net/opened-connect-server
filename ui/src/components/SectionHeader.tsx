import type { ReactNode } from 'react'

interface SectionHeaderProps {
  title: string
  description: string
  action?: ReactNode
}

export default function SectionHeader({ title, description, action }: SectionHeaderProps) {
  return (
    <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-slate-100">{title}</h1>
        <p className="mt-1 text-sm text-gray-500 dark:text-slate-400">{description}</p>
      </div>
      {action}
    </div>
  )
}
