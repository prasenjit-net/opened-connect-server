# Dynamic client registration implementation plan

Status: initial OIDC registration/read release implemented. Registration remains disabled by default. Delivery phases 1–4 are implemented; optional RFC 7592 management (phase 5) remains deferred, with PUT/DELETE returning 405.

Implementation evidence: transactional credential and migration tests, HTTP authorization/isolation tests, admin UI tests, and a real HTTP registration → login/consent → PKCE token exchange → ID-token verification integration test. Full conformance certification has not been performed.

## Scope and standards

Implement OpenID Connect Dynamic Client Registration 1.0 for this provider, using the existing clients and transactional storage. OIDC defines registration and authenticated configuration reads; update and delete management belong to the separate RFC 7592 extension. Unknown registration metadata must be ignored. Successful registration returns effective metadata, an assigned client ID, and any issued secret with its expiry. A configuration URI and registration access token are returned together or both omitted. Registration metadata failures use `invalid_client_metadata` or `invalid_redirect_uri`. See [OIDC Registration 1.0, sections 2–4](https://openid.net/specs/openid-connect-registration-1_0.html).

Use [RFC 7591](https://www.rfc-editor.org/rfc/rfc7591) as the OAuth registration reference and [RFC 7592](https://www.rfc-editor.org/rfc/rfc7592) for the optional management phase. Do not claim full OAuth registration extension support, software-statement support, or management support before their respective acceptance checks pass.

## Proposed product decisions

- Ship registration disabled by default. Enabling it requires an initial access token (IAT); anonymous registration is outside the initial release.
- Admins issue limited-use, expiring IATs through the management UI. Proposed defaults: one successful registration and a 24-hour lifetime; allow bounded admin overrides.
- Each new dynamic client receives its own opaque registration access token (RAT). It authorizes configuration access only for that client, never user data, token issuance, or administrative operations.
- Keep existing manual registration and client search/detail/new screens. Dynamic clients appear in the same inventory with origin and creation metadata.
- Initial release supports POST registration and GET configuration. PUT and DELETE are a separately gated follow-up; return protocol 405 responses until enabled.
- Dynamic registration accepts only runtime-compatible configurations. Existing administrative editing can continue storing unsupported metadata with its existing compatibility warning.
- Do not add support for new grant types, JWT client authentication, pairwise subjects, request objects, or encryption as a side effect of registration work.

## Existing implementation and integration points

| Component | Planned change |
| --- | --- |
| `internal/identity/clients.go` | Extract shared client creation and secret generation helpers without weakening admin principal checks. Add narrowly authorized registration services. |
| `internal/identity/client_metadata.go` | Reuse normalization, introduce a protocol input adapter and typed field errors. Preserve strict admin input handling. |
| `internal/oidc/capability` | Reuse the capability audit to reject registrations the provider cannot execute. |
| `internal/identity/store.go` | Extend transaction interfaces with registration credentials and lifecycle operations. |
| `internal/identity/file_store.go` | Persist new records in local data with compatible migration, atomic writes, and existing locking. |
| `internal/identity/client_secrets.go` | Retain encrypted client-secret persistence; avoid creating a second credential encryption mechanism. |
| `internal/oidc` | Add registration handlers, credential authentication, response projection, and discovery metadata. |
| `internal/server/server.go` | Mount protocol routes before SPA fallback, including disabled and unsupported-method responses. |
| `internal/api/router.go` | Add admin-only credential issuance, inventory, and revocation routes. |
| React client pages | Add registration provenance and contextual credential controls without exposing stored secrets. |

## Routes and authorization

| Route | Authentication and behavior |
| --- | --- |
| `POST /register` | Valid IAT in the Authorization Bearer header; create one client atomically. Return 201 JSON. |
| `GET /register/{clientID}` | RAT bound to the requested client; return 200 protocol configuration JSON. |
| `PUT /register/{clientID}` | Follow-up RFC 7592 phase; RAT, full replacement with explicit protected-field rules. |
| `DELETE /register/{clientID}` | Follow-up RFC 7592 phase; RAT, delete client and invalidate its grants and credentials. |
| `GET/POST /api/admin/registration-tokens` | Admin browser session; POST also requires existing CSRF/origin protection. |
| `POST /api/admin/registration-tokens/{id}/revoke` | Admin session plus CSRF; revoke future registration permission. |
| `POST /api/admin/clients/{id}/registration-token` | Admin session plus CSRF; explicitly issue/replace a client RAT and invalidate its predecessor. |
| `DELETE /api/admin/clients/{id}/registration-token` | Admin session plus CSRF; remove configuration access without deleting the client. |

Cookies, ordinary OAuth access tokens, ID tokens, client secrets, and IATs cannot substitute for a RAT. RATs cannot register additional clients. Regular users receive no registration administration entitlement; admins retain all normal user entitlements.

Discovery advertises `registration_endpoint` only when registration is enabled. Build absolute URLs from the validated issuer, never request Host headers. Existing discovery capability lists remain truthful.

## Credential and storage design

Introduce separate IAT and RAT records, not entries in the ordinary access-token collection. Use cryptographically random opaque values with distinct type prefixes and hashed lookup/storage. Retain only safe identifiers in admin responses and logs. Return newly issued credentials once to their intended caller.

IAT records contain ID, hash, label, issuer admin ID, issue/expiry times, maximum uses, successful uses, and revocation time. RAT records contain ID, hash, client ID, issue time, and revocation state. Proposed RAT policy: no automatic expiry in the initial release; explicit revocation or replacement ends access. Persist this policy in documentation and UI.

Check IAT validity and capacity, create the client and RAT, and increment usage in one storage transaction. Validation failures and failed commits consume no quota. Concurrent attempts cannot overspend an IAT. Recheck credential state within the transaction after expensive validation. Keep network I/O outside storage locks.

Store client provenance separately from protocol metadata. Existing clients migrate as manually registered and receive no RAT automatically. IAT revocation stops future registrations; it does not silently delete existing clients. Client deletion invalidates RATs and existing protocol state atomically. Client edits retain RAT access unless explicitly revoked; grant invalidation continues through the existing SaveClient contract. Replacing a RAT must not unnecessarily invoke SaveClient and revoke user grants.

A lost registration response may leave a committed client and consumed single-use IAT. Do not automatically retry POST as if it were idempotent. Let admins locate the resulting client, rotate credentials, or remove it through existing management controls.

## Validation and protocol responses

1. Require a bounded JSON object with the appropriate content type. Reject duplicate keys, trailing JSON, malformed types, excessive array lengths, oversized strings, and oversized bodies.
2. Classify known metadata, unknown extensions, and server-owned credential fields before normalization. Ignore unknown extensions; reject attempts to choose IDs, secrets, registration tokens, internal provenance, or admin flags.
3. Apply registration defaults, check cross-field constraints, and preserve language-tagged display metadata. Never rewrite redirect URI strings while claiming to have registered the supplied values.
4. Check redirect scheme/application-type rules against the selected OIDC profile. Require HTTPS web callbacks in production; retain documented native loopback/custom-scheme behavior. Audit runtime matching before accepting any native configuration.
5. Reject runtime-incompatible requests with a specific field-oriented explanation rather than silently downgrading requested security. Audit sector identifier requirements before claiming support; if supplied metadata needs unsupported remote validation, reject it explicitly.
6. Keep JWKS URI and inline JWKS mutually exclusive; accept public key material only. Do not fetch arbitrary branding or key URLs during registration. Any future required fetch needs an SSRF-safe client with destination validation, DNS/rebinding defenses, redirect controls, timeouts, and response bounds.
7. Use a dedicated protocol response builder. Exclude admin-only fields such as compatibility diagnostics and internal timestamps. Include effective defaults. Configuration reads may expose the current client secret to the correctly bound RAT holder; document that a RAT is therefore highly sensitive. Never expose it through admin list responses or logs.
8. Do not rotate RATs during GET. Omit the raw RAT from read responses rather than storing a recoverable copy just to echo it.
9. Return OAuth-style errors, Bearer challenges for authentication failures, `Cache-Control: no-store`, and safe descriptions. Missing, revoked, unknown, or mismatched RATs must not reveal another client's existence. Define and test the status/error matrix before handler implementation.

## Deployment protections

Use HTTPS outside explicit loopback development. Registration and configuration CORS use an explicit origin allowlist with no cookie credentials; preflight grants no access. Apply body limits, per-credential quotas, and bounded rate limiting before expensive processing. Trust proxy headers only under existing trusted-proxy policy. Redact authorization headers and credential-bearing responses from logs.

Disabling registration stops new POST requests while allowing existing clients to read their configuration; document this distinction. Add a separate emergency switch for configuration access if needed. Neither switch disables existing authorization-code clients.

## Admin UX

Issue initial access tokens from a modal on the Clients list. Place their inventory and revocation under Activity → Initial access tokens, sharing the existing Activity sidebar entry. Group by task:

- Issuance modal: enabled/disabled state, endpoint, limits, lifetime, and one-time credential display. Closing the modal preserves client search results and clears the displayed credential.
- Initial access token monitoring: automatic initial load and 15-second refresh, submitted search filters, page size 10, expiry, remaining uses, and revocation. The previous /clients/registration URL redirects here. Never display stored raw tokens.
- Client detail: provenance and a separate registration-access section with issue/replace/revoke actions and clear effects.
- One-time credential display: copy action, dismissal warning, and no query-cache, local-storage, or URL persistence.

Preserve existing client search results when returning from details. Confirm destructive credential replacement/revocation; disable actions on expired or already revoked credentials. Distinguish client-secret rotation from RAT replacement.

## Delivery sequence and acceptance

1. **Contract and storage:** document the exact supported metadata/status matrix; introduce credential records, migration, transaction helpers, and concurrency tests.
2. **Registration:** implement IAT authorization, POST, dedicated projections, limits, and conditional discovery. Verify a dynamically registered client completes the existing authorization-code + PKCE flow and receives a valid ID token.
3. **Configuration reads:** implement ownership checks, safe errors, current configuration projection, and admin RAT lifecycle operations.
4. **Admin experience:** add issuance, search, provenance, and one-time displays; preserve role guards and existing navigation behavior.
5. **Optional RFC 7592 management:** implement full-replacement update semantics, required client identity/secret checks, immutable credential fields, omitted-field handling, and authenticated deletion. Validate these separately against the RFC before enabling methods. Reuse atomic grant invalidation, and test concurrency against admin edits and credential revocation.

Required checks include missing/expired/revoked credentials; cross-client access; cookie/token confusion; regular-user denial; malformed JSON and metadata; defaults and unknown fields; public versus confidential clients; no secret leakage; restart persistence; older data migration; storage rollback; simultaneous final-use IAT requests; registration racing revocation; deletion racing reads; rate-limit behavior; CORS; disabled routes; unsupported methods returning no SPA HTML; and continued manual-client behavior.

Run relevant Go tests, race tests, vet, UI tests, production build, and lint. Complete a real HTTP registration-to-login-to-token round trip. Record tested capabilities and remaining optional extensions in README. No full-spec conformance claim until the applicable conformance suite has been evaluated and passed.


## Implemented response matrix

| Condition | Status / protocol error |
| --- | --- |
| Successful registration / read | 201 / 200 JSON, `no-store` |
| Missing, invalid, expired, consumed or revoked credential; wrong client | 401 `invalid_token`, Bearer challenge |
| Invalid metadata / redirect URI | 400 `invalid_client_metadata` / `invalid_redirect_uri` |
| Incorrect media type / oversized body | 415 `invalid_request` / 413 `invalid_client_metadata` |
| Rate limit | 429 `temporarily_unavailable`, `Retry-After: 60` |
| New registrations disabled | POST 404 `invalid_request`; authenticated reads remain enabled |
| Unsupported protocol method | 405 `invalid_request`, `Allow` header |
| Storage failure | 500 `server_error`; failed creation returns no credentials |

Admin errors retain the application's existing error envelope. Revoking an inactive invitation returns 409 `REGISTRATION_NOT_ACTIVE`. Client configuration reads do not rotate or echo the RAT. Runtime-incompatible metadata is rejected, including nonempty default ACR values and sector identifier URIs requiring unsupported validation. No outbound URL fetches occur during registration.
