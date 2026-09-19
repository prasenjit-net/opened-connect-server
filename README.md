# OpenID Connect Server

OpenID Connect Server is a Go application with an embedded React administration console. The console includes cookie-based login, admin user management, profiles, password changes, appearance settings, and the Grove theme from Lizard.

Repository: https://github.com/prasenjit-net/opened-connect-server

## What You Get

- `serve`, `init`, `keys`, and `version` CLI commands
- `chi`-based API routing under `/api`
- User/admin roles enforced in the API and UI
- Argon2id passwords and expiring, revocable cookie sessions
- Local identity storage behind a transactional interface
- An OpenID Connect provider (authorization code + PKCE, discovery, JWKS, UserInfo) alongside the management API
- UI configuration at `/api/public/config` and a health check at `/api/public/health`
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
│   ├── oidc/
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
- Health: `http://localhost:8080/api/public/health`

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
- `internal/oidc/service.go`
- `ui/src/router.tsx`
- `ui/src/components/Layout.tsx`

## UI theme

The UI uses React 19, TanStack Router, and Tailwind CSS 4. Theme tokens and shared styles live in `ui/src/styles/index.css`. The responsive sidebar, components, and light/dark/system modes are copied from Lizard, with this app’s own branding and browser preference keys.

Routes: `/login`, `/` (dashboard), `/users`, `/users/new`, `/users/$userId` (admin only), `/profile`, `/components` (local style previews), `/settings`, and a catch-all 404 page. Application pages require login. `/dashboard` redirects to `/` for existing bookmarks. Direct navigation and refresh preserve the requested page.

Set `ui.defaultTheme` to `auto`, `light`, or `dark` and `ui.repoURL` in `config.yaml`. `app.name` and `app.description` supply the visible branding. The server injects the default theme before the first paint; a saved browser preference takes priority.

Unknown API routes return a JSON 404. The old `/api/example` and `/api/meta` endpoints have been removed. See `THIRD_PARTY_NOTICES.md` for theme attribution.

## Initial administrator

There are no default accounts or passwords. Initialize the first administrator before signing in:

```sh
./build/opened-connect-server init --admin-email admin@example.com --admin-name "Administrator"
./build/opened-connect-server serve
```

The command prompts for a password without echoing it, then asks for confirmation. Passwords must contain 12–128 characters. For automation, pass `--password-stdin` and supply the password through stdin from a secret manager. Passwords are never accepted as command-line flags or printed. `--path` selects the project directory; `--data-dir` overrides the storage location on both `init` and `serve`.

Initialization refuses to modify any existing user store, even with `--force`. The force flag only applies to generated configuration files. Use the Users screen for subsequent accounts. Searches run only when submitted, with role/status filters and 10 results per page. Clicking a user opens a detail screen for editing attributes, role changes, disabling, and confirmed deletion. Returning to search preserves the filters, current page, and results without another request. Add user opens a separate creation screen; saving opens the new user’s detail, and Back returns to search. The last active administrator cannot be demoted, disabled, or deleted.

## Authentication and authorization

- Users sign in with their email address and password. Email uniqueness is case-insensitive.
- `user` can use the application, view their profile, edit their standard profile claims and custom attributes, and change their own password after verifying the current password.
- `admin` additionally manages users. Role, email, and status changes revoke the affected user's sessions. Deletion also revokes sessions.
- Sessions expire after `auth.sessionTTL` (8 hours by default). Logout revokes the current session; password changes revoke all sessions, including the current one.
- The browser receives an opaque `HttpOnly`, `SameSite=Lax` session cookie. The server stores only its SHA-256 digest. Authentication tokens are never placed in browser local storage.
- Authenticated writes require `X-CSRF-Token`, obtained from the login/session response and held in browser memory. Writes accept JSON only and reject cross-site origins. Login attempts are throttled by remote IP and email, with bounded concurrent password checks.
- The UI checks the session before rendering protected pages, guards admin routes, and clears private cached data after sign-out or session rejection. The API independently enforces authorization.

| Endpoint | Access |
| --- | --- |
| `GET /api/public/config`, `GET /api/public/health`, `GET /livez` | Public bootstrap/health information |
| `POST /api/auth/login` | Public; JSON and same-origin checks; throttled |
| `GET /api/auth/session`, `POST /api/auth/logout` | Signed-in user |
| `GET /api/user/profile`, `PUT /api/user/profile` | Own profile; editable claims and custom attributes |
| `POST /api/user/profile/password` | Own account; current password required |
| `GET /api/admin/users`, `POST /api/admin/users` | Admin |
| `GET /api/admin/users/{id}`, `PUT /api/admin/users/{id}`, `DELETE /api/admin/users/{id}` | Admin |

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

Profiles support the [OpenID Connect standard claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims): name, given/family/middle names, nickname, preferred username, profile/picture/website URLs, email, gender, birthdate, time zone, locale, phone number, and the structured address. `sub` is derived from the immutable account ID; `updated_at` is a server-generated Unix timestamp. Existing accounts remain compatible.

Custom attributes are a separate `custom_attributes` JSON object supporting scalar, array, and object values (up to 50 names within the 16 KB request limit). They never grant application permissions or override standard claims. Supplying editable claims replaces that set; omitting them preserves existing values. Administrators manage email/phone verification flags. Self-service changes to email or phone clear the corresponding verification flag.

Regular users access only their own profile through `/api/user/profile`; the server derives the target from the session and rejects identity, role, status, and verification fields. All `/api/admin/users` endpoints require admin authorization. Admins retain all self-service capabilities. The Users navigation entry and management routes are hidden/guarded for regular users.

## Client management

Administrators manage OpenID Connect clients at `/clients`, `/clients/new`, and `/clients/$clientId`. Search runs only on submission, matches client name or ID, and returns 10 clients per page. Detail/create navigation preserves the search draft, results, and current page. Creating a client replaces the create history entry with detail, so browser Back returns to search. Regular users cannot see the Clients menu or access its pages/APIs.

| Endpoint | Operation |
| --- | --- |
| `GET /api/admin/clients?q=portal&page=1` | Search; fixed page size 10 |
| `POST /api/admin/clients` | Create a client |
| `GET /api/admin/clients/{id}` | Read client metadata |
| `PUT /api/admin/clients/{id}` | Replace editable metadata |
| `DELETE /api/admin/clients/{id}` | Delete a client |
| `POST /api/admin/clients/{id}/secret` | Rotate its secret; send `{}` |

All endpoints require an admin session; mutations also require the session CSRF token. Metadata uses the top-level names from [OpenID Connect Dynamic Client Registration 1.0, section 2](https://openid.net/specs/openid-connect-registration-1_0.html#ClientMetadata), including language-tagged display fields. The editor exposes application/redirect settings, response/grant types, contacts and display URLs, authentication method, subject settings, public JWKS, signing/encryption preferences, authentication-age defaults, ACR values, and request/login URIs. Unknown and server-managed input fields are rejected. PUT replaces metadata and reapplies specification defaults for omitted defaulted fields.

This is the administrative client registry. OAuth authorization/token processing and public dynamic registration are separate features; metadata does not enable those protocol endpoints. Referenced JWKS, sector-identifier documents, and request objects are stored as URLs without fetching them. Their runtime content and cryptographic checks belong to the protocol implementation. Web redirects require HTTPS, with HTTP loopback allowed for code flow; native redirects follow the registration specification's custom-scheme/HTTP-loopback rules. Insecure RSA1_5 encryption is not accepted.

The server generates immutable `client_id` and `client_id_issued_at`. A `client_secret`, when required by the authentication or symmetric cryptographic metadata, is returned only on creation, first issuance after a metadata change, or rotation. Read/search responses never include it. Secrets have `client_secret_expires_at: 0` (no automatic expiry). The UI keeps a newly issued secret only in memory until dismissal or leaving its detail page, outside the query cache and browser storage. Rotation immediately replaces the stored secret.

Clients share the transactional `identity.Store` interface and local `data/identity.json` store. Existing identity files without clients remain valid. Client secrets use AES-256-GCM encryption with client IDs as authenticated data. The encryption key is stored separately in `data/client-secrets.key` (mode 0600); back up both files together. Missing/invalid keys fail closed. Database adapters implement the client transaction methods and their own secret protection.

API routes are grouped by access: `/api/admin/*` requires an administrator, `/api/user/*` provides self-service access to both users and admins, `/api/auth/*` handles authentication (only login is public), and `/api/public/*` supplies public bootstrap/health data. The infrastructure liveness probe remains `/livez`. Former ungrouped API paths return 404; API consumers must use the grouped paths. Browser page URLs are unchanged.

## OpenID Connect provider

Set `oidc.enabled: true` in `config.yaml` (or `APP_OIDC_ENABLED=true`) to serve an authorization-code OpenID Provider alongside the administration console. `oidc.issuer` defaults to `app.url`; it must be an absolute URL with no path, and HTTPS outside `development`/`test`. Protocol endpoints are mounted at the issuer root, ahead of the SPA/dev-proxy fallback, and never share the management API's JSON/CSRF middleware:

| Endpoint | Purpose |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery document; public, cacheable, CORS-open |
| `GET /jwks` | Public signing keys only; never private material |
| `GET`/`POST /authorize` | Authorization-code requests, PKCE S256 required |
| `POST /token` | Code exchange; form-encoded, OAuth-shaped errors |
| `GET`/`POST /userinfo` | Bearer-token claims, scope-gated |

`./build/opened-connect-server init` provisions the RSA 3072-bit signing key and self-signed certificate under `data/signing-keys/` the first time OIDC is enabled, alongside the identity store; rerunning `init` (including `--force`) never replaces a valid existing key, and on an already-initialized install it now provisions only the missing signing material without touching users or passwords. `keys status` reports the active/retired keys and expiry (never private material); `keys rotate` generates and activates a new key while keeping the retired one published in `/jwks` for verification of still-unexpired tokens. `serve` fails closed at startup if OIDC is enabled and the signing material is missing, corrupt, mismatched, or expired — it never falls back to an ephemeral key.

Login/consent reuse the existing form-login flow: `/authorize` persists a short-lived transaction and a dedicated browser-binding cookie, then continues at `/oidc/continue` in the React app (a consent screen or an immediate redirect), independent of the admin console's session-authenticated pages. `prompt=none` requests never render UI — they redirect straight back to the relying party with a result or an `interaction_required`-style error. Consent is recorded per user/client/scope set at the client's current metadata revision; a metadata change invalidates prior consent.

The provider implements OpenID Connect authorization code with required PKCE S256, discovery, opaque access tokens, RS256 ID tokens, and scope-gated UserInfo. OpenID Connect sign-in requires compatible client metadata; unsupported signing, encryption, pairwise subjects, and implicit/hybrid response types are flagged in client detail. Dynamic client registration and OAuth token lifecycle endpoints are described below. RP-initiated logout, request objects, and WebFinger are not implemented. OAuth grants are controlled separately by explicit administrative permissions.

### Authorization-code security and browser clients

Set exact browser client origins for cross-origin `/token` and `/userinfo` calls:

```yaml
oidc:
  enabled: true
  issuer: https://identity.example.com
  allowedOrigins:
    - https://app.example.com
```

The default origin list is empty. Discovery and JWKS remain public; protocol CORS never allows credentials. Issuers are normalized once by removing a trailing slash; user information, query strings, fragments, and path prefixes are rejected.

Authorization requests and token forms are limited to 16 KiB. Duplicate parameters, malformed encoding, conflicting client credentials, and mixed POST query/body parameters are rejected. Each protocol endpoint allows up to 240 requests per peer IP per minute, with separate failed-client-credential limits of 30 per client/peer pair per 15 minutes. Successful authentication does not consume the failed-credential allowance. These in-process limits use the direct peer address; configure source limits at a trusted reverse proxy as well when deploying behind one.

Consent completion and token issuance commit atomically. Authorization-code replay requires correct client, redirect, and PKCE proof before revoking issued access tokens; consumed-code evidence is retained through the access-token lifetime. Forced login and `max_age` are enforced against stored session authentication timestamps. An existing browser binding is reused for additional tabs.

Password, email, role, and active-status changes revoke the user's browser sessions, pending codes/transactions, access tokens, and consent. Client updates, secret rotation, and deletion invalidate that client's protocol state. Updating a login email signs the user out and requires login with the new address. Self-contained ID tokens already delivered to relying parties remain verifiable until their expiry; access-token revocation does not retract those JWTs.

Signing checks certificate validity at issuance and rejects JWT lifetimes extending beyond it. Rotate keys before expiry. Clients requiring signed UserInfo or signed request objects are reported incompatible and cannot silently receive unsigned behavior. Unsupported request objects and response modes return protocol errors. Optional capabilities listed above remain unadvertised.

Regression coverage and the original findings are recorded in [OIDC_AUTHORIZATION_CODE_REVIEW.md](OIDC_AUTHORIZATION_CODE_REVIEW.md). Passing local tests is not OpenID conformance certification.

### Administrative activity monitoring

The admin sidebar has one **Activity** menu entry, with tabs for protocol activity and initial access tokens. Administrators can open `/activity/transactions`, `/activity/codes`, `/activity/tokens`, `/activity/refresh`, and `/activity/consents`. Each page shows retained records with user/client labels, scopes, lifecycle status, creation/expiry times, explicit search and status filters, 10-record pagination, manual refresh, and automatic refresh every 15 seconds. The admin dashboard summarizes these records and shows the 10 newest records plus user/client totals. Regular users receive a personal dashboard and cannot see or request administrative activity.

Monitoring endpoints use the existing admin browser session boundary:

- `GET /api/admin/activity/overview`
- `GET /api/admin/activity/{transactions|codes|tokens|refresh|consents}?q=...&status=...&grantType=...&audience=...&page=1`
- `POST /api/admin/activity/{kind}/{id}/revoke` with `{}` and the session CSRF header

The service rechecks admin authorization within the storage transaction. Responses are not cached, contain derived administrative record IDs, and exclude raw tokens, credential hashes, session/browser bindings, OAuth state/nonce, and PKCE material. List operations are part of the storage interface for future database adapters.

Only active items can be revoked. Consumed codes, completed transactions, expired records, and obsolete consents have no revocation action; the API rechecks eligibility atomically and returns HTTP 409 if an item is no longer active. Revoking an active transaction cancels it; revoking an unused code prevents exchange. Revoking an access token blocks further UserInfo use. Revoking consent cancels current transactions, codes, and tokens for that user/client only; subsequent authorization requires a new consent decision. These mutations are atomic with protocol issuance; retries on an already-revoked record are harmless. Consent revocation preserves consumed/completed/expired history while cancelling active grants. Already-delivered signed ID tokens cannot be recalled; newly issued tokens record the ID-token expiry for display in record details.

This is a view of retained protocol state, not a permanent audit log. Normal expiry cleanup and account/client security changes can remove records. Counts are current retained totals rather than lifetime traffic totals. Older records without creation or ID-token-expiry metadata display an unavailable timestamp.

### Dynamic client registration

Dynamic registration is disabled by default. Enable the provider and set
`oidc.registrationEnabled: true` in server configuration. Discovery then publishes
`registration_endpoint`. Use HTTPS; loopback HTTP is only for development/tests.

On the **Clients** list, admins can open **Issue initial access token** to create
an invitation in a modal. Monitor tokens under **Activity → Initial access tokens**,
with an automatically loaded first page, 15-second refresh, 10 results per page,
and revocation of unused capacity. Search filters apply when Search is clicked. An invitation
allows one registration and expires after 24 hours by default. Admins may choose
1–100 registrations and 1–720 hours. Tokens are displayed once and stored only as
hashes. No anonymous registration is supported.

Send `POST /register` with `Content-Type: application/json` and
`Authorization: Bearer <initial-access-token>`, for example this body:

```json
{
  "client_name": "Example application",
  "redirect_uris": ["https://app.example.com/callback"],
  "token_endpoint_auth_method": "none"
}
```

Use `none` for a public client using PKCE, or `client_secret_basic` (the default)
/ `client_secret_post` for a confidential client. The 201 response includes the
client ID, effective metadata, a secret when applicable, and a per-client
`registration_access_token` with its `registration_client_uri`. The registered
client can use the existing authorization-code flow immediately. Unknown
extension metadata is ignored; invalid or runtime-incompatible requirements are
rejected rather than silently weakened. Request objects, nonempty default ACR
values, sector-identifier validation, pairwise subjects, JWT client authentication,
and token encryption are not supported by dynamic registration.

Use `GET` on the returned configuration URI with the registration access token.
This read includes the current client secret when present: protect the registration
token as carefully as that secret. Configuration tokens do not expire automatically;
admins can replace or revoke them from client detail. Replacement does not change
the client secret or revoke user grants. Deleting a client invalidates its
configuration token and protocol grants. Initial-token revocation only stops
future registrations; it does not invalidate clients already created.

Client registration and configuration tokens cannot authorize user/admin APIs,
UserInfo, or token issuance. Browser sessions and ordinary OAuth access tokens
cannot authorize registration/configuration endpoints. Responses are `no-store`;
secrets are never included in admin inventory responses. CORS uses the existing
`oidc.allowedOrigins` allowlist without cookie credentials. Per-process limits are
240 registration/configuration requests per source and 120 per credential per
minute; apply additional edge limits for multi-instance deployments. Storage
transactions enforce initial-token quotas across processes sharing local data.

Disabling `oidc.registrationEnabled` stops new registrations and removes the
endpoint from discovery; existing configuration reads and login flows continue.
Disabling OIDC disables all protocol routes. A lost POST response may already
have consumed an invitation; inspect the client inventory and rotate/recover
credentials instead of blindly retrying registration.

Implemented: the OIDC registration and configuration-read profile described in
[DYNAMIC_CLIENT_REGISTRATION_PLAN.md](DYNAMIC_CLIENT_REGISTRATION_PLAN.md).
RFC 7592 self-service update/delete remains an optional later phase; those methods
return 405. Admins continue updating and deleting clients through `/api/admin/clients`.
This is not a claim of full OpenID conformance certification.


## OAuth token lifecycle and API access

With `oidc.enabled`, the provider also exposes `POST /introspect`, `POST /revoke`,
`grant_type=client_credentials` at `/token`, and
`/.well-known/oauth-authorization-server`. All token requests are bounded,
form-encoded POSTs. Protocol client authentication uses the registered
`client_secret_basic`, `client_secret_post`, or (where allowed) `none` method;
browser cookies, management roles, IATs, and RATs do not authorize these calls.

Example server configuration:

```yaml
oidc:
  enabled: true
  refreshMaxTTL: 720h
  refreshInactivityTTL: 168h
oauth:
  refreshTokensEnabled: true
  passwordGrantEnabled: false
  resources:
    - audience: https://api.example.com
      enabled: true
      scopes: [read, write]
```

Resources have exact HTTPS audience identifiers and non-OIDC scope names. They
are configured by the operator, not created by a token request or dynamic
registration. Restart after configuration changes. Disabling a resource or
removing its scopes makes affected tokens inactive during introspection.

Create an **OAuth API access** client without redirects for machine access.
Register `client_credentials`, then use **OAuth permissions** on client detail to
allow the grant, select resources, allowed/default scopes, and an optional default
resource. Without an approved default, each request must include `resource`.
Only one resource per request is supported. Machine tokens have subject
`client:<client_id>` and cannot access UserInfo or management APIs. They receive
neither ID tokens nor refresh tokens.

```sh
curl --user "$CLIENT_ID:$CLIENT_SECRET" "$ISSUER/token" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode resource=https://api.example.com \
  --data-urlencode scope=read
curl --user "$RESOURCE_CLIENT_ID:$RESOURCE_CLIENT_SECRET" "$ISSUER/introspect" \
  --data-urlencode "token=$ACCESS_TOKEN"
curl --user "$CLIENT_ID:$CLIENT_SECRET" "$ISSUER/revoke" \
  --data-urlencode "token=$ACCESS_TOKEN"
```

The examples use clients registered for `client_secret_basic`. Resource-server
clients need explicit introspection permission and allowed audiences; ownership
of a token alone does not grant inspection authority. Authorized callers may
inspect other clients' access tokens for permitted audiences. Invalid, expired,
revoked, unknown, or out-of-audience tokens return only `{"active":false}`.
Resource servers must enforce audience and scopes and consult introspection;
revocation cannot invalidate an independently cached positive result immediately.
Refresh inspection additionally requires explicit permission and the issuing
client's authentication. Token hints are advisory and never grant authority.

Revocation returns HTTP 200 with an empty body for unknown, already revoked, or
foreign-client tokens. Revoking an access token leaves its refresh family intact.
Revoking any refresh credential, including a consumed one, revokes its whole
family and associated access tokens. Eligible public clients send `client_id`
and their own token. `/introspect` is confidential-client-only.

### Rotating refresh tokens

Refresh is disabled by default. Enable it globally, register both
`authorization_code` and `refresh_token` on the client, and enable offline access
in its OAuth permissions. Request `scope=openid offline_access` (plus desired
profile scopes) and **`prompt=consent`** in the existing PKCE authorization flow.
The user must approve offline access. Ordinary code exchanges without that scope
still issue only access and ID tokens.

```sh
curl "$ISSUER/token" \
  --data-urlencode grant_type=refresh_token \
  --data-urlencode "client_id=$PUBLIC_CLIENT_ID" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN"
```

Confidential clients must also authenticate. Each successful refresh returns a
new access token and replacement refresh token, without an ID token or a new
browser session. Omitted scope retains the current scopes; explicit scope can
only narrow them, permanently. Resource cannot change. The original sign-in time
and absolute expiry never advance; rotation extends inactivity only up to the
absolute deadline.

Serialize refresh calls. Reuse of a consumed credential revokes the whole family,
including the winning token in a concurrent exchange. There is no grace window;
after an ambiguous lost response, sign in again instead of retrying the old
credential. Hashed replay evidence survives restart and is retained through the
family's maximum lifetime plus its possible access-token lifetime.

Logout ends the browser session but preserves approved offline grants. Account
security changes, client/policy changes, consent revocation, and explicit family
revocation invalidate them. Disabling global refresh blocks exchange but does not
revoke stored families; administrators can revoke them in **Activity → Refresh
tokens** to prevent reuse after re-enabling. Activity loads page 1 automatically,
uses 10 rows per page, and displays safe IDs, family, subject, grant, audience,
absolute/idle expiry, and lifecycle status. Consumed/expired items cannot be
revoked from the admin UI; the protocol revocation endpoint remains idempotent.

### Legacy password grant

`oauth.passwordGrantEnabled` defaults to false. This optional legacy grant is
prohibited by current OAuth security best practice (RFC 9700); prefer authorization
code with PKCE. It requires a confidential client registered for `password`,
explicit password/grant/resource permissions, and user resource entitlements in
**User detail → OAuth resource access**. An app admin role confers no OAuth scopes.
The username is the account email. The grant issues only a resource access token,
without an ID token, refresh token, session, or consent record. Verification uses
the existing password hash, generic failures, bounded concurrency, rate limits,
and an atomic account/policy recheck. MFA is not implemented; this grant must not
be used to bypass a future required interactive authentication policy.

Administrative settings APIs (admin session and CSRF for writes):

- `GET /api/admin/oauth`: configured resources and global grant flags.
- `GET/PUT /api/admin/clients/{id}/oauth-policy`: client permissions.
- `GET/PUT /api/admin/users/{id}/oauth-access`: user resource entitlements.

These permissions are separate from client registration metadata and user
profile claims. Dynamic clients receive none automatically. Saving permissions
invalidates existing affected grants. Data migrates to identity schema version 4;
legacy OIDC access tokens retain their UserInfo behavior and gain no refresh or
resource authority. Future storage adapters must preserve the serializable
issuance, rotation, revocation, and rollback contract in `identity.Store`.
