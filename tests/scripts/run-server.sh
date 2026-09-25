#!/usr/bin/env bash
# Optional helper: provisions and starts a disposable, fully-OIDC-enabled
# server instance you can point the e2e suite at. Run this yourself in its
# own terminal — Playwright does NOT start or manage this; it only ever
# targets whatever server is already running at E2E_BASE_URL. If you
# already have a suitable instance running (your own `make dev`/`serve`),
# you don't need this script at all — see tests/README.md.
#
# Safe to re-run: the workspace directory is wiped on every start.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TESTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
ROOT_DIR="$(cd "$TESTS_DIR/.." && pwd)"
WORKDIR="$TESTS_DIR/.server-workspace"
BIN="$ROOT_DIR/build/openid-connect-server"

PORT="${E2E_PORT:-8099}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-e2e-admin@example.test}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-e2e admin password not a real secret}"

if [ ! -x "$BIN" ]; then
  echo "==> Building openid-connect-server binary (not found at $BIN)" >&2
  (cd "$ROOT_DIR" && make build-go) >&2
fi

echo "==> Resetting workspace at $WORKDIR" >&2
rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/data"

cat > "$WORKDIR/config.yaml" <<YAML
app:
  name: OIDC E2E Test Server
  env: test
  url: http://127.0.0.1:$PORT
  description: Disposable instance for the Playwright e2e suite.

server:
  host: 127.0.0.1
  port: $PORT

storage:
  dataDir: $WORKDIR/data

auth:
  sessionTTL: 8h
  cookieSecure: false

oidc:
  enabled: true
  refreshMaxTTL: 720h
  refreshInactivityTTL: 168h
  registrationEnabled: true
  issuer: http://127.0.0.1:$PORT
  allowedOrigins:
    - https://relying-party.test
    - http://127.0.0.1:9999

# Test-only configuration: exercise both optional grants. Never copy the
# legacy password setting into a recommended production configuration.
oauth:
  refreshTokensEnabled: true
  passwordGrantEnabled: true
  resources:
    - audience: https://api.e2e.example.test
      enabled: true
      scopes: [read, write]
    - audience: https://other.e2e.example.test
      enabled: true
      scopes: [read]
YAML

echo "==> Initializing admin and signing keys" >&2
printf '%s' "$ADMIN_PASSWORD" | "$BIN" init \
  --path "$WORKDIR" \
  --config "$WORKDIR/config.yaml" \
  --data-dir "$WORKDIR/data" \
  --admin-email "$ADMIN_EMAIL" \
  --admin-name "E2E Admin" \
  --password-stdin >&2

cat > "$TESTS_DIR/.env" <<ENV
E2E_BASE_URL=http://127.0.0.1:$PORT
E2E_ADMIN_EMAIL=$ADMIN_EMAIL
E2E_ADMIN_PASSWORD=$ADMIN_PASSWORD
ENV

cat >&2 <<EOF
==> Server starting on http://127.0.0.1:$PORT
==> Wrote tests/.env — in another terminal, just run:

    npm test

EOF

exec "$BIN" serve \
  --config "$WORKDIR/config.yaml" \
  --data-dir "$WORKDIR/data" \
  --port "$PORT"
