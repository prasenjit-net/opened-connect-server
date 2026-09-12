# OpenID Connect Server

OpenID Connect Server is a Go application with an embedded React administration console. The console provides an empty dashboard, appearance settings, a component showcase, and a 404 page using the Grove theme from Lizard.

Repository: https://github.com/prasenjit-net/opened-connect-server

## What You Get

- `serve`, `init`, and `version` CLI commands
- `chi`-based API routing under `/api`
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
make dev-all
```

Open:

- UI: `http://localhost:8080`
- API: `http://localhost:8080/api`
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

Routes: `/` (empty dashboard), `/components` (local style previews), `/settings`, and a catch-all 404 page. `/dashboard` redirects to `/` for existing bookmarks. Direct navigation and refresh preserve the requested page.

Set `ui.defaultTheme` to `auto`, `light`, or `dark` and `ui.repoURL` in `config.yaml`. `app.name` and `app.description` supply the visible branding. The server injects the default theme before the first paint; a saved browser preference takes priority.

The only application APIs are `GET /api/config` and `GET /api/health`; unknown API routes return a JSON 404. The old `/api/example` and `/api/meta` endpoints have been removed. There are no certificate, ACME, task, metrics, or WebSocket services. See `THIRD_PARTY_NOTICES.md` for theme attribution.
