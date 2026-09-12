# OpenID Connect Server

OpenID Connect Server is a Go application with an embedded React administration console. The console includes cookie-based login, admin user management, profiles, password changes, appearance settings, and the Grove theme from Lizard.

Repository: https://github.com/prasenjit-net/opened-connect-server

## What You Get

- `serve`, `init`, and `version` CLI commands
- `chi`-based API routing under `/api`
- User/admin roles enforced in the API and UI
- Argon2id passwords and expiring, revocable cookie sessions
- Local identity storage behind a transactional interface
- UI configuration at `/api/config` and a health check at `/api/health`
- Embedded React build via Go `embed`
- Development mode with Vite proxy support
- Structured logging with `slog`
- GitHub Actions for lint, test, and build

## Folder Structure

```text
.
├── .github/
│   └── workflows/
├── cmd/
│   └── app/
├── internal/
│   ├── api/
│   ├── config/
│   ├── identity/
│   ├── logging/
│   ├── server/
│   └── version/
├── ui/
│   ├── dist/
│   ├── public/
│   └── src/
├── .env.example
├── config.yaml
├── main.go
├── ui_embed.go
├── Makefile
└── README.md
```

## How Embedding Works

1. The frontend lives in `ui/`.
2. `npm run build` writes the production bundle to `ui/dist`.
3. `ui_embed.go` embeds `ui/dist` into the Go binary.
4. The server mounts API routes under `/api` and serves the React SPA for every other route.

That gives you one deployment artifact: the compiled Go executable.

## Development Workflow

### Prerequisites

- Go 1.23+
- Node.js 22.12+
- npm

### Initial Setup

```bash
cp .env.example .env
make install-deps
make build-ui
go run . init --admin-email admin@example.com
make dev-all
```

Open:

- UI: `http://localhost:8080`
- Login: `http://localhost:8080/login`
- Health: `http://localhost:8080/api/health`

### Common Commands

```bash
make dev        # backend only, proxies UI requests to Vite when APP_UI_DEV_PROXY_URL is set
make dev-ui     # Vite dev server on :5173
make dev-all    # backend + Vite together
make build      # build UI, embed it, compile one binary
make run        # build and run the production binary
make test       # run Go tests
make test-ui    # run frontend tests
make lint       # go vet
make lint-ui    # eslint for the React app
```

## Production Build

```bash
make build
./build/opened-connect-server serve
```

The binary contains the compiled React app. No separate Node.js server is required in production.

## Configuration

Configuration is loaded in this order:

1. defaults from the Go config package
2. `config.yaml`
3. `.env` and `.env.local`
4. environment variables prefixed with `APP_`
5. CLI flags

Example environment overrides:

```bash
APP_SERVER_PORT=9090
APP_LOGGING_LEVEL=debug
APP_UI_DEV_PROXY_URL=http://localhost:5173
```

## Files to Review First

- `main.go`
- `ui_embed.go`
- `cmd/app/root.go`
- `cmd/app/serve.go`
- `internal/config/config.go`
- `internal/server/server.go`
- `ui/src/router.tsx`
- `ui/src/components/Layout.tsx`

## UI theme

The UI uses React 19, TanStack Router, and Tailwind CSS 4. Theme tokens and shared styles live in `ui/src/styles/index.css`. The responsive sidebar, components, and light/dark/system modes are copied from Lizard, with this app’s own branding and browser preference keys.

Routes: `/login`, `/` (dashboard), `/users` (admin only), `/profile`, `/components` (local style previews), `/settings`, and a catch-all 404 page. Application pages require login. `/dashboard` redirects to `/` for existing bookmarks. Direct navigation and refresh preserve the requested page.

Set `ui.defaultTheme` to `auto`, `light`, or `dark` and `ui.repoURL` in `config.yaml`. `app.name` and `app.description` supply the visible branding. The server injects the default theme before the first paint; a saved browser preference takes priority.

Unknown API routes return a JSON 404. The old `/api/example` and `/api/meta` endpoints have been removed. See `THIRD_PARTY_NOTICES.md` for theme attribution.

## Initial administrator

There are no default accounts or passwords. Initialize the first administrator before signing in:

```sh
./build/opened-connect-server init --admin-email admin@example.com --admin-name "Administrator"
./build/opened-connect-server serve
```

The command prompts for a password without echoing it, then asks for confirmation. Passwords must contain 12–128 characters. For automation, pass `--password-stdin` and supply the password through stdin from a secret manager. Passwords are never accepted as command-line flags or printed. `--path` selects the project directory; `--data-dir` overrides the storage location on both `init` and `serve`.

Initialization refuses to modify any existing user store, even with `--force`. The force flag only applies to generated configuration files. Use the Users screen for subsequent accounts; it supports search, role/status filters, pagination, creation, editing, role changes, disabling, and confirmed deletion. The last active administrator cannot be demoted, disabled, or deleted.

## Authentication and authorization

- Users sign in with their email address and password. Email uniqueness is case-insensitive.
- `user` can use the application, view their profile, edit their display name, and change their own password after verifying the current password.
- `admin` additionally manages users. Role, email, and status changes revoke the affected user's sessions. Deletion also revokes sessions.
- Sessions expire after `auth.sessionTTL` (8 hours by default). Logout revokes the current session; password changes revoke all sessions, including the current one.
- The browser receives an opaque `HttpOnly`, `SameSite=Lax` session cookie. The server stores only its SHA-256 digest. Authentication tokens are never placed in browser local storage.
- Authenticated writes require `X-CSRF-Token`, obtained from the login/session response and held in browser memory. Writes accept JSON only and reject cross-site origins. Login attempts are throttled by remote IP and email, with bounded concurrent password checks.
- The UI checks the session before rendering protected pages, guards admin routes, and clears private cached data after sign-out or session rejection. The API independently enforces authorization.

| Endpoint | Access |
| --- | --- |
| `GET /api/config`, `GET /api/health`, `GET /livez` | Public bootstrap/health information |
| `POST /api/auth/login` | Public; JSON and same-origin checks; throttled |
| `GET /api/auth/session`, `POST /api/auth/logout` | Signed-in user |
| `GET /api/profile`, `PUT /api/profile` | Own profile; only display name is editable |
| `POST /api/profile/password` | Own account; current password required |
| `GET /api/users`, `POST /api/users` | Admin |
| `PUT /api/users/{id}`, `DELETE /api/users/{id}` | Admin |

The API returns JSON errors with 401 for unauthenticated requests, 403 for unauthorized actions, and 409 for duplicate emails or removal of the last active admin.

## Local storage and future database adapters

`internal/identity.Store` defines atomic `Read` and `Write` transactions over `ReadTx`/`Tx`. The identity service depends only on that interface. A database implementation can provide database transactions and be injected through `server.Options.Store` without changing handlers or UI code.

The default `FileStore` stores users, salted Argon2id password hashes, and sessions in `data/identity.json`. Writes use a synced temporary file and atomic rename; an OS file lock serializes transactions across server and CLI processes. Failed transactions leave the previous file intact. The directory is mode 0700 and the identity file is mode 0600 on POSIX systems. The schema is versioned, and malformed/unsupported data fails closed. The data directory is ignored by Git and is never served as static content.

Set `storage.dataDir` or pass `--data-dir /absolute/path`. Relative storage paths are resolved from the working directory (`--path` for `init`). Back up the directory as private application data. Login rate-limit counters are process-local and reset on restart; deployments with multiple replicas should add a shared rate limiter along with a database adapter.

## HTTPS deployment

Terminate TLS at a reverse proxy and set the public URL and environment:

```yaml
app:
  env: production
  url: https://identity.example.com
auth:
  sessionTTL: 8h
  cookieSecure: true
storage:
  dataDir: /var/lib/opened-connect-server
```

Merge these settings into `config.yaml`. Outside `development`/`test`, startup requires an HTTPS public URL and forces Secure cookies. The server also adds HSTS for Secure-cookie deployments, frame denial, MIME-sniffing protection, and a same-origin referrer policy. Restrict access to the backend HTTP port to the reverse proxy. In development, HTTP cookies support localhost, and the configured Vite origin is allowed for API calls.

The environment setting is `APP_APP_ENV` (not `APP_ENV`). Examples: `APP_APP_ENV=production`, `APP_APP_URL=https://identity.example.com`, `APP_STORAGE_DATADIR=/var/lib/opened-connect-server`.
