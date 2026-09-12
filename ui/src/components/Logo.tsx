interface LogoIconProps {
  size?: number
  className?: string
}

export function LogoIcon({ size = 36, className }: LogoIconProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 100 100"
      width={size}
      height={size}
      className={className}
      role="img"
      aria-label="Go app template logo"
    >
      <rect
        x="28"
        y="22"
        width="50"
        height="64"
        rx="10"
        fill="#818cf8"
        fillOpacity="0.10"
        stroke="#6366f1"
        strokeWidth="2"
        strokeDasharray="5,3.5"
        strokeOpacity="0.65"
      />
      <rect x="12" y="8" width="52" height="66" rx="10" fill="#4f46e5" fillOpacity="0.07" stroke="#4f46e5" strokeWidth="2.5" />
      <path d="M 12 22 L 12 18 Q 12 8 22 8 L 54 8 Q 64 8 64 18 L 64 22 Z" fill="#4f46e5" fillOpacity="0.18" />
      <line x1="21" y1="34" x2="55" y2="34" stroke="#4338ca" strokeWidth="2.8" strokeLinecap="round" />
      <line x1="21" y1="43" x2="50" y2="43" stroke="#4f46e5" strokeWidth="2" strokeLinecap="round" opacity="0.65" />
      <line x1="21" y1="51" x2="54" y2="51" stroke="#4f46e5" strokeWidth="2" strokeLinecap="round" opacity="0.65" />
      <line x1="21" y1="59" x2="40" y2="59" stroke="#4f46e5" strokeWidth="2" strokeLinecap="round" opacity="0.45" />
      <circle cx="72" cy="78" r="14" fill="#059669" />
      <circle cx="72" cy="78" r="14" fill="white" fillOpacity="0.10" />
      <polyline points="64.5,78 70.5,84.5 80.5,71" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

interface LogoFullProps {
  iconSize?: number
  title?: string
}

export function LogoFull({ iconSize = 36, title = 'go-app' }: LogoFullProps) {
  return (
    <div className="flex items-center gap-2.5">
      <LogoIcon size={iconSize} />
      <span className="select-none text-lg font-bold tracking-tight leading-none">
        <span className="text-indigo-700 dark:text-indigo-300">{title.split('-')[0]}</span>
        <span className="text-slate-400 dark:text-slate-500">-</span>
        <span className="text-violet-700 dark:text-violet-300">{title.split('-')[1] ?? 'template'}</span>
      </span>
    </div>
  )
}
