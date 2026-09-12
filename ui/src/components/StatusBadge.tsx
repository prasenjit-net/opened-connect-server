import clsx from 'clsx'

interface StatusBadgeProps {
  status: string
}

export default function StatusBadge({ status }: StatusBadgeProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold uppercase tracking-wide',
        status === 'ok'
          ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
          : 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
      )}
    >
      {status}
    </span>
  )
}
