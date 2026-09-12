import { Link } from 'react-router-dom'
import SectionHeader from '../components/SectionHeader'

export default function NotFoundPage() {
  return (
    <div className="p-8">
      <section className="mx-auto max-w-xl rounded-xl border border-gray-200 bg-white p-8 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <p className="mb-4 text-sm font-semibold text-primary-700 dark:text-primary-300">404</p>
        <SectionHeader
          title="Page not found"
          description="The page you’re looking for doesn’t exist. Check the address or return to the dashboard."
        />
        <Link
          to="/dashboard"
          className="mt-6 inline-flex rounded-lg bg-primary-700 px-4 py-2.5 text-sm font-medium text-white transition-colors hover:bg-primary-800 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-primary-600 dark:bg-primary-600 dark:hover:bg-primary-500"
        >
          Back to dashboard
        </Link>
      </section>
    </div>
  )
}
