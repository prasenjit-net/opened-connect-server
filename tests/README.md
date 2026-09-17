# OIDC end-to-end tests (Playwright)

A browser-driven end-to-end suite for the OpenID Connect provider. **Manual only — never run by CI/CD.** It exercises real navigation through login, consent, redirect back to a (mocked) relying party, server-to-server code exchange, and `/userinfo`, plus admin-side dynamic registration and activity/revocation. The Go and Vitest suites already cover protocol edge cases and validation logic exhaustively at the unit/integration level; this suite is for the things only a real browser round-trip proves.

## This suite does not start a server

It targets whatever OpenID Connect server is **already running** at a URL you tell it about. Bring your own:

- Your normal dev instance (`make dev` / `opened-connect-server serve`), with `oidc.enabled: true` in its config, **or**
- A disposable, throwaway instance — a helper script is provided for this:

  ```sh
  cd tests
  bash scripts/run-server.sh
  ```

  This builds the binary if needed, wipes `tests/.server-workspace/`, provisions a fresh admin + signing keys with `oidc.enabled`, `oidc.registrationEnabled`, and `oidc.allowedOrigins` all on, runs `serve` in the foreground on port 8099 (override with `E2E_PORT`), and **writes `tests/.env`** with matching `E2E_BASE_URL`/`E2E_ADMIN_EMAIL`/`E2E_ADMIN_PASSWORD` for you. Leave it running in its own terminal.

## Running the suite

```sh
cd tests
npm install
npx playwright install chromium   # first time only

cp .env.example .env   # then edit .env — skip this if scripts/run-server.sh already wrote one for you

npm test              # headless
npm run test:headed   # watch it drive a real browser
npm run test:ui       # Playwright's interactive UI mode
npm run report         # open the HTML report from the last run
```

Configuration comes from `tests/.env` (never committed — `.env.example` is the tracked template), loaded automatically. A shell-exported `E2E_BASE_URL`/`E2E_ADMIN_EMAIL`/`E2E_ADMIN_PASSWORD` always takes precedence over `.env`, so `E2E_BASE_URL=... npm test` still works for a one-off override without touching the file.

## What's checked before anything else

`global-setup.ts` verifies `E2E_BASE_URL` is reachable and OIDC-enabled (a real discovery document, not the SPA's HTML), then logs in as `E2E_ADMIN_EMAIL`/`E2E_ADMIN_PASSWORD` and saves the session for every spec to reuse. A clear, actionable error is thrown immediately if either check fails — specs never run against a server they can't authenticate against.

## Isolation and safety

- Every spec provisions its **own** OIDC client(s), and usually its own end user, rather than sharing fixtures across spec files.
- User emails and client names include a per-run random suffix (`RUN_ID`), so re-running the suite against the same **persistent** server (not just a disposable one) never collides with a previous run's leftovers.
- Nothing here deletes or mutates data it didn't create itself, except where a spec is specifically testing revocation of a grant it just created.
- If you point this at a real, shared, non-disposable server, remember it **will** create real users and clients there (clearly named `... <RUN_ID>` / `...-<RUN_ID>@example.test`) — prefer a disposable instance via `scripts/run-server.sh` unless you have a reason not to.

## Relying party mocking

There's no real third-party relying party to redirect to. Most specs use `https://relying-party.test`, an origin that never resolves on the network; Playwright's `page.route()` intercepts every request to it and fulfills a minimal stub page locally (see `fixtures/relying-party.ts`) — this is enough to observe the real final redirect (`code`/`state`/`error` in the URL) exactly as a real RP's callback page would receive it. The actual code-for-tokens exchange is modeled as a confidential client's **backend** would do it — a direct HTTP call via Playwright's `request` fixture, not browser JS.

`public-client-cors.spec.ts` is the exception: it needs the browser to make a *real* outbound `fetch()` call, which a `page.route()`-mocked page cannot do (Chromium treats a fully synthetic response as having a restricted security context — confirmed empirically as "Failed to fetch"). That spec instead starts a real, minimal local HTTP server on a fixed loopback port (`fixtures/stub-callback-server.ts`) to serve its callback page, so the fetch is genuinely subject to the target server's CORS allowlist.

## Specs

| File | Covers |
| --- | --- |
| `discovery.spec.ts` | Discovery document and JWKS content; protocol routes never fall through to the SPA |
| `authorization-code-flow.spec.ts` | The golden path: login → consent → redirect → code exchange → **independently signature-verified** ID token → UserInfo |
| `consent-deny.spec.ts` | Denial still redirects the RP back with `error=access_denied` |
| `invalid-requests.spec.ts` | Unknown client / unregistered redirect_uri / duplicate params render an error page directly, never a redirect |
| `pkce-enforcement.spec.ts` | Missing/`plain`/empty `code_challenge_method` all rejected — S256 only |
| `code-replay.spec.ts` | A reused code fails and revokes the token from the original exchange; concurrent exchange of one code yields exactly one success |
| `dynamic-client-registration.spec.ts` | `POST /register` with an initial access token, `GET /register/{id}` with the resulting registration access token, server-owned-field rejection (skipped if `oidc.registrationEnabled` is off) |
| `admin-activity-revocation.spec.ts` | Admin revokes a live access token / consent via the activity API; revoked tokens immediately fail at `/userinfo`; consent revocation blocks a subsequent silent (`prompt=none`) sign-in |
| `public-client-cors.spec.ts` | A public-client SPA completes the flow via browser `fetch()`, gated by `oidc.allowedOrigins` (skipped if the mocked RP origin isn't allowlisted on the target server) |

## Troubleshooting

- **"No OIDC-enabled server responding at ..."** — nothing is listening at `E2E_BASE_URL`, or it's running with `oidc.enabled: false`.
- **"Admin login failed"** — `E2E_ADMIN_EMAIL`/`E2E_ADMIN_PASSWORD` don't match a real active administrator on that server.
- **Dynamic-registration or CORS specs report "skipped"** — the target server doesn't have `oidc.registrationEnabled` / a matching `oidc.allowedOrigins` entry; that's expected unless you specifically enabled them (`scripts/run-server.sh` enables both).
