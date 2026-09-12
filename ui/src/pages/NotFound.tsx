import { Link } from "@tanstack/react-router";

export default function NotFoundPage() {
  return (
    <div className="flex flex-col items-center gap-3 px-4 py-12 text-center">
      <div className="text-7xl leading-none font-bold tracking-wider text-accent opacity-35">
        404
      </div>
      <h2 className="text-lg font-semibold">Page not found</h2>
      <p className="max-w-md text-ink-muted">
        The page you’re looking for doesn’t exist. Check the address or return
        to the dashboard.
      </p>
      <Link className="btn btn-primary" to="/">
        Back to dashboard
      </Link>
    </div>
  );
}
