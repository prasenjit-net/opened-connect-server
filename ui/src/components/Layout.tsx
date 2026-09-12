import { useEffect, useMemo, useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { BookOpen, LayoutDashboard, Menu, Moon, Monitor, Settings, Sparkles, Sun, X } from 'lucide-react'
import clsx from 'clsx'
import { LogoFull } from './Logo'
import { metaApi } from '../services/api'

type ThemeMode = 'light' | 'dark' | 'system'

const themeStorageKey = 'go-app-template-theme'

const navItems = [
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/examples', label: 'Examples', icon: Sparkles },
  { to: '/settings', label: 'Settings', icon: Settings },
]

const appRepoUrl = 'https://github.com/prasenjit-net/go-app-template'

const getInitialTheme = (): ThemeMode => {
  if (typeof window === 'undefined') {
    return 'system'
  }

  const stored = window.localStorage.getItem(themeStorageKey)
  if (stored === 'light' || stored === 'dark' || stored === 'system') {
    return stored
  }

  return 'system'
}

const applyTheme = (mode: ThemeMode) => {
  if (typeof window === 'undefined') {
    return
  }

  const root = document.documentElement
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  const useDark = mode === 'dark' || (mode === 'system' && prefersDark)
  root.classList.toggle('dark', useDark)
  root.style.colorScheme = useDark ? 'dark' : 'light'
}

export default function Layout() {
  const [themeMode, setThemeMode] = useState<ThemeMode>(getInitialTheme)
  const [isDrawerOpen, setIsDrawerOpen] = useState(false)
  const { data: meta } = useQuery({
    queryKey: ['meta'],
    queryFn: metaApi.get,
    staleTime: Infinity,
  })

  useEffect(() => {
    applyTheme(themeMode)
    window.localStorage.setItem(themeStorageKey, themeMode)
  }, [themeMode])

  useEffect(() => {
    document.title = meta?.name || 'Go App Template'
  }, [meta?.name])

  useEffect(() => {
    if (!isDrawerOpen) {
      return
    }

    document.body.style.overflow = 'hidden'
    return () => {
      document.body.style.overflow = ''
    }
  }, [isDrawerOpen])

  const themeOptions = useMemo(
    () => [
      { value: 'light' as const, label: 'Light', icon: Sun },
      { value: 'system' as const, label: 'System', icon: Monitor },
      { value: 'dark' as const, label: 'Dark', icon: Moon },
    ],
    [],
  )

  return (
    <div className="flex h-screen overflow-hidden bg-gray-50 text-gray-900 dark:bg-slate-950 dark:text-slate-100">
      <aside className="hidden h-screen w-64 flex-col border-r border-gray-200 bg-white lg:flex dark:border-slate-800 dark:bg-slate-900">
        <div className="flex h-16 items-center border-b border-gray-200 px-5 dark:border-slate-800">
          <LogoFull iconSize={36} title="go-app" />
        </div>

        <nav className="flex-1 overflow-y-auto px-4 py-6">
          <ul className="space-y-1">
            {navItems.map((item) => (
              <li key={item.to}>
                <NavLink
                  to={item.to}
                  onClick={() => setIsDrawerOpen(false)}
                  className={({ isActive }) =>
                    clsx(
                      'flex items-center rounded-lg px-4 py-2.5 text-sm font-medium transition-colors',
                      isActive
                        ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/30 dark:text-primary-200'
                        : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100',
                    )
                  }
                >
                  <item.icon className="mr-3 h-5 w-5" />
                  {item.label}
                </NavLink>
              </li>
            ))}
            <li>
              <a
                href={appRepoUrl}
                target="_blank"
                rel="noreferrer"
                onClick={() => setIsDrawerOpen(false)}
                className="flex items-center rounded-lg px-4 py-2.5 text-sm font-medium text-gray-600 transition-colors hover:bg-gray-100 hover:text-gray-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100"
              >
                <BookOpen className="mr-3 h-5 w-5" />
                App Repo
              </a>
            </li>
          </ul>
        </nav>

        <div className="mt-auto">
          <div className="px-4 pb-4">
            <div className="mb-2 text-xs font-semibold text-gray-500 dark:text-slate-400">Theme</div>
            <div className="grid grid-cols-3 gap-1 rounded-lg bg-gray-100 p-1 dark:bg-slate-800">
              {themeOptions.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setThemeMode(option.value)}
                  className={clsx(
                    'flex items-center justify-center gap-1 rounded-md px-2 py-1 text-xs font-medium transition-colors',
                    themeMode === option.value
                      ? 'bg-white text-gray-900 shadow-sm dark:bg-slate-700 dark:text-slate-100'
                      : 'text-gray-500 hover:text-gray-900 dark:text-slate-400 dark:hover:text-slate-100',
                  )}
                >
                  <option.icon className="h-3.5 w-3.5" />
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          <div className="border-t border-gray-200 p-4 dark:border-slate-800">
            <div className="text-xs text-gray-500 dark:text-slate-400">
              <p className="font-medium">{meta?.name ?? 'Go App Template'}</p>
              <p>{meta?.description ?? 'Embedded Go + React starter'}</p>
            </div>
          </div>
        </div>
      </aside>

      <div className="flex flex-1 flex-col overflow-hidden">
        <header className="border-b border-gray-200 bg-white px-4 py-3 lg:hidden dark:border-slate-800 dark:bg-slate-900">
          <div className="flex items-center justify-between gap-4">
            <button
              type="button"
              onClick={() => setIsDrawerOpen(true)}
              className="inline-flex h-10 w-10 items-center justify-center rounded-lg border border-gray-200 text-gray-600 transition-colors hover:bg-gray-100 hover:text-gray-900 dark:border-slate-700 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100"
              aria-label="Open navigation"
              aria-expanded={isDrawerOpen}
              aria-controls="mobile-navigation"
            >
              <Menu className="h-5 w-5" />
            </button>
            <LogoFull iconSize={32} title="go-app" />
            <div className="flex items-center gap-1 rounded-lg bg-gray-100 p-1 dark:bg-slate-800">
              {themeOptions.map((option) => (
                <button
                  key={option.value}
                  type="button"
                  onClick={() => setThemeMode(option.value)}
                  className={clsx(
                    'rounded-md px-2 py-1 text-xs font-medium transition-colors',
                    themeMode === option.value
                      ? 'bg-white text-gray-900 dark:bg-slate-700 dark:text-slate-100'
                      : 'text-gray-500 dark:text-slate-400',
                  )}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>
        </header>

        <div
          className={clsx(
            'fixed inset-0 z-40 bg-slate-950/40 backdrop-blur-sm transition-opacity lg:hidden',
            isDrawerOpen ? 'pointer-events-auto opacity-100' : 'pointer-events-none opacity-0',
          )}
          onClick={() => setIsDrawerOpen(false)}
        />

        <aside
          id="mobile-navigation"
          className={clsx(
            'fixed inset-y-0 left-0 z-50 flex w-72 max-w-[85vw] flex-col border-r border-gray-200 bg-white shadow-2xl transition-transform duration-200 ease-out lg:hidden dark:border-slate-800 dark:bg-slate-900',
            isDrawerOpen ? 'translate-x-0' : '-translate-x-full',
          )}
          aria-hidden={!isDrawerOpen}
        >
          <div className="flex h-16 items-center justify-between border-b border-gray-200 px-5 dark:border-slate-800">
            <LogoFull iconSize={34} title="go-app" />
            <button
              type="button"
              onClick={() => setIsDrawerOpen(false)}
              className="inline-flex h-9 w-9 items-center justify-center rounded-lg text-gray-500 transition-colors hover:bg-gray-100 hover:text-gray-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100"
              aria-label="Close navigation"
            >
              <X className="h-5 w-5" />
            </button>
          </div>

          <nav className="flex-1 overflow-y-auto px-4 py-6">
            <ul className="space-y-1">
              {navItems.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    onClick={() => setIsDrawerOpen(false)}
                    className={({ isActive }) =>
                      clsx(
                        'flex items-center rounded-lg px-4 py-2.5 text-sm font-medium transition-colors',
                        isActive
                          ? 'bg-primary-50 text-primary-700 dark:bg-primary-900/30 dark:text-primary-200'
                          : 'text-gray-600 hover:bg-gray-100 hover:text-gray-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100',
                      )
                    }
                  >
                    <item.icon className="mr-3 h-5 w-5" />
                    {item.label}
                  </NavLink>
                </li>
              ))}
              <li>
                <a
                  href={appRepoUrl}
                  target="_blank"
                  rel="noreferrer"
                  onClick={() => setIsDrawerOpen(false)}
                  className="flex items-center rounded-lg px-4 py-2.5 text-sm font-medium text-gray-600 transition-colors hover:bg-gray-100 hover:text-gray-900 dark:text-slate-300 dark:hover:bg-slate-800 dark:hover:text-slate-100"
                >
                  <BookOpen className="mr-3 h-5 w-5" />
                  App Repo
                </a>
              </li>
            </ul>
          </nav>

          <div className="border-t border-gray-200 p-4 text-xs text-gray-500 dark:border-slate-800 dark:text-slate-400">
            <p className="font-medium">{meta?.name ?? 'Go App Template'}</p>
            <p>{meta?.description ?? 'Embedded Go + React starter'}</p>
          </div>
        </aside>

        <main className="flex-1 overflow-y-auto">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
