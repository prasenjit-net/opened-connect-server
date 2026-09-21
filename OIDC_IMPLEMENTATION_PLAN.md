# OpenID Connect Core and Discovery implementation plan

Status: proposed implementation plan; no protocol endpoints are implemented by this document.

The detailed follow-on proposal for logout extensions and OP/app session activity is [Logout and session activity implementation plan](LOGOUT_IMPLEMENTATION_PLAN.md).

## 1. Objective and delivery scope

Turn this application into an OpenID Provider using the existing users, client registrations, form login, and transactional local storage. Expose protocol endpoints directly at the issuer root, including `/authorize` and `/token`. Preserve the existing management API groups and their role boundaries.

Deliver a usable authorization-code provider first, followed by additional Core capabilities. An initial code-flow release must not be described as implementing every optional Core feature or every registered client configuration. Each release must publish its actual capabilities through discovery and reject unsupported requests explicitly.

The proposed initial deployment is one issuer per application installation, at an HTTPS origin without an issuer path prefix. Local HTTP is permitted only through the existing explicit development/test configuration. Existing accounts and client IDs remain valid.

## 2. Existing implementation and gaps

| Existing component | Reuse and required change |
| --- | --- |
| `internal/server/server.go` | Mount protocol routes before the SPA and development-proxy fallback. Ensure protocol errors never return the SPA HTML. |
| `internal/api/router.go` | Preserve `/api/admin`, `/api/user`, `/api/auth`, and `/api/public` groups. Protocol endpoints have independent authentication and content-type handling. |
| `internal/identity/service.go` and `store.go` | Reuse users, password verification, account status, sessions, and transactional access. Extend the same transaction boundary for grants and tokens. |
| `internal/identity/clients.go` | Reuse IDs, metadata, and protected client secrets. Add a protocol-facing client lookup that returns a narrowly scoped runtime client configuration, without requiring an admin browser session. |
| `internal/identity/client_metadata.go` | Separate valid metadata syntax from implemented protocol capabilities. Existing acceptance of metadata does not imply runtime support. |
| `internal/identity/file_store.go` | Preserve existing data and implement versioned migrations for protocol state. Maintain cross-process locking and atomic writes. |
| React login and profile pages | Reuse form login and the theme. Add authorization transaction continuation, consent, and protocol error screens. |
| Current profile `sub` | Reuse the immutable account ID for public subjects. Pairwise subjects require a separate stable, issuer/sector-specific mapping. |

Current sessions have an expiry but no explicit authentication timestamp or authentication-method evidence. Add these before implementing `max_age`, `auth_time`, and forced reauthentication. Existing sessions without that evidence must reauthenticate when freshness is required.

## 3. Endpoint and authorization contract

All protocol paths below are outside `/api`. Names are implementation choices; discovery publishes their absolute URLs.

| Endpoint | Method | Authorization and behavior | Delivery |
| --- | --- | --- | --- |
| `/.well-known/openid-configuration` | GET | Public provider metadata, derived from configured issuer and enabled capabilities. | Initial |
| `/jwks` | GET | Public signing keys only; never private keys or client secrets. | Initial |
| `/authorize` | GET, POST | Validate registered client and authorization request first. Then require an active user's browser session and any necessary consent. Both users and admins may authorize clients. | Initial |
| `/token` | POST | Form-encoded requests; authenticate the client as registered. Public clients identify themselves and prove code possession with PKCE. Browser cookies never authorize token issuance. | Initial |
| `/userinfo` | GET, POST | Bearer access token issued for this resource with `openid`; enforce expiry, grant status, current account status, and claim permissions. Cookies and ID tokens are not credentials here. | Initial |
| `/revoke` | POST | Authenticate/identify the issuing client and verify token ownership; revoke only its grant/token according to policy. Use OAuth revocation response semantics. | Token lifecycle phase |
| `/introspect` | POST | Authenticated, explicitly entitled confidential client/resource server; deny arbitrary token inspection. Return inactive for tokens outside the caller's permitted audience/ownership. | Optional extension phase |
| `/logout` | GET, POST | RP-initiated logout extension with validated hints/registered return URLs, session binding, and confirmation where needed. | Optional extension phase |

Application interaction APIs remain grouped:

- `/api/auth/login`, `/api/auth/session`, `/api/auth/logout`: existing login/session behavior, extended to bind and resume an authorization transaction.
- `/api/user/authorization/{transactionId}`: proposed authenticated read of a transaction bound to this browser and user.
- `/api/user/authorization/{transactionId}/decision`: proposed authenticated consent decision; JSON, same-origin validation, and session CSRF token required.
- `/api/user/grants`: proposed own-grant listing/revocation for consent management.
- `/api/admin/*`: management remains admin-only, including any new client policy or signing-key management operations.
- `/api/public/*` and `/livez`: existing bootstrap and infrastructure endpoints remain available.

Protocol scopes never confer application admin privileges. An admin's ID/access token must not automatically contain their application role. Protocol bearer tokens cannot authenticate management or self-service APIs; those continue to use browser sessions and CSRF protection.

## 4. Provider architecture and dependency decision

Create `internal/oidc` for protocol services, HTTP handlers, capability definitions, claim projection, client authentication, and token lifecycle rules. Define a signing/key-store interface separately from the identity store. Keep wire-format handlers separate from domain/storage operations.

Before protocol implementation, run a bounded dependency spike: select a maintained Go provider/protocol library with authorization-code, PKCE, refresh rotation, storage adapters, and appropriate error handling. Verify its license, supported Go version, maintenance history, and fit with the existing login/consent flow. Use a maintained JOSE implementation for signing and verification; do not write cryptographic primitives or JWT verification from scratch. Record the selected dependencies and adapter design in this document before adding them.

Acceptance for the spike: an in-memory round trip using an existing-style client/user fixture, validated ID-token signature, and a demonstrated atomic code-consumption hook. If the provider library cannot preserve transactional guarantees, retain its validated primitives and implement the missing orchestration behind our interfaces; document the exact responsibility boundary.

A single capability registry must drive discovery, runtime validation, and management-screen compatibility messages. Avoid three independently maintained allowlists.

## 5. Issuer, keys, and discovery

Proposed configuration adds `oidc.enabled`, `oidc.issuer`, token/transaction TTLs, capability flags, and key rotation settings. Validate issuer consistency with the application's public URL and secure-cookie configuration. Never derive issuer URLs from request `Host` or untrusted forwarded headers. Reject unsupported path-prefixed issuers at startup until their routing and discovery behavior are implemented.

The `opened-connect-server init` command must provision the initial RSA private key and matching self-signed X.509 certificate for provider JWT signing. Use RS256 for the first delivery. The private key signs ID tokens and other provider-issued signed JWTs as those features are enabled; the certificate carries the corresponding public key. Initial access and refresh tokens remain opaque, as specified in section 7.

### Initial signing material and command behavior

- Generate an RSA 3072-bit key with a cryptographically secure random source. Create a self-signed certificate with a random positive serial number, digital-signature key usage, and `IsCA=false`. Proposed certificate validity is 365 days with a five-minute start-time allowance for clock skew. Record the certificate's expiry and key activation time.
- Store the pair under the configured local data directory, for example `data/signing-keys/<kid>/private.pem` (PKCS#8 PEM) and `certificate.pem` (X.509 PEM), with an active-key manifest. Directories use mode 0700; private material and the manifest use mode 0600. Keep this signing material separate from `client-secrets.key` and include it in backup/restore instructions.
- Derive a stable `kid` from the public key using the selected JOSE library's standard JWK thumbprint support. The certificate, JWT header, active-key manifest, and published JWK must identify the same key. `/jwks` exposes its public RSA parameters; private key material must never be returned. Relying parties establish trust through the configured issuer and its JWKS. HTTPS continues to use the deployment's TLS configuration.
- Fresh `init` provisions signing material alongside configuration and the first admin. Validate configuration and destination permissions first; validate that the certificate and private key match before activating them. Commit a complete staged key directory and active manifest atomically under a cross-process initialization/key-store lock.
- Make initialization recoverable: rerunning `init` preserves valid existing signing material and its `kid`, even with `--force`. For an installation with existing users, skip first-admin creation and provision missing signing material without changing any user or password. This intentionally extends the current command behavior, which rejects an already initialized user store. Partially completed initialization must be resumable without replacing valid keys or accounts.
- Missing material on an existing installation requires an explicit `init` run. Corrupt, mismatched, or expired existing material must produce an actionable error; `init --force` must not silently replace it. Provide an explicit signing-key rotation operation for intentional replacement. Report generated/reused paths, `kid`, and expiry, but never print the private key.
- With OIDC enabled, `serve` loads and validates the initialized pair and active manifest. It must fail startup on missing, invalid, mismatched, or unusable signing material rather than generating an ephemeral key. Restarts preserve issuer signing identity.

### Rotation and JWT use

Use the signing/key-store interface for every provider-issued signed JWT, including ID tokens, signed UserInfo, and future logout tokens. Keep per-token claim, audience, type, and algorithm validation separate even when sharing the active RSA key. Client-generated JWT assertions are verified against client credentials and never signed with the provider key.

Rotate before certificate expiry with enough overlap for the longest-lived signed artifact and clock tolerance. Do not issue an artifact whose verification lifetime would exceed the signing certificate's usable lifetime; if rotation has not completed, fail issuance with an operational error. Retain retired public keys and certificates for verification of unexpired artifacts while new JWTs use the new active `kid`. Certificate renewal/replacement belongs to explicit rotation, not ordinary initialization.

Discovery includes issuer, authorization/token/UserInfo/JWKS URLs, supported response and grant types, response modes, subject types, scopes/claims, signing algorithms, client authentication methods, and PKCE methods. Include optional flags explicitly where omission would imply unsupported default behavior. Initial request-object support flags are false; registration, logout, and introspection endpoints are omitted until delivered. Verify issuer equality across discovery and issued tokens. Use cache validators for public metadata/key responses and ensure key cache lifetimes permit rotation. [Discovery specification](https://openid.net/specs/openid-connect-discovery-1_0.html)

## 6. Authorization and browser interaction

Proposed initial flow:

1. Parse bounded GET query or form-encoded POST parameters. Reject duplicate security-critical parameters and conflicting input sources.
2. Load the registered client; require a supported `response_type=code`, registered authorization-code grant, `openid` scope, and valid redirect URI. Use exact matching, with only explicitly implemented native-loopback exceptions. Never redirect an invalid client or untrusted redirect URI.
3. Intersect requested scopes with provider capabilities and the client's allowed scope policy. Preserve `state`; validate PKCE input and store an optional `nonce` exactly as supplied.
4. Persist a short-lived authorization transaction containing validated inputs and an unpredictable browser-binding value. Do not put the complete request into a user-controlled login return URL. Bind the transaction across session rotation at login.
5. Resolve login/freshness requirements, then consent. Resume through a fixed same-origin continuation; never through an arbitrary submitted destination.
6. Atomically verify the transaction, account, client policy revision, and consent decision before generating a single-use code. Redirect only to the validated URI with the protocol response and original `state`.

Initial interaction semantics include normal login, `prompt=login`, `prompt=consent`, and `prompt=none`. Implement `max_age` and the client's authentication-age default using verified authentication timestamps. A noninteractive request must return the appropriate interaction-required error instead of rendering login or consent. Reject invalid prompt combinations. Account-selection behavior must either offer a real account switch or be declared unsupported; never silently ignore it. Treat login hints as hints, not proof of identity.

Authorization POSTs may arrive without a SameSite=Lax cookie. Store the validated request and use a same-origin GET continuation to establish the browser session rather than weakening cookie policy globally. Consent decisions remain protected against CSRF, transaction replay, and approval from another browser/account. Use `Cache-Control: no-store` and `Referrer-Policy: no-referrer` on interaction pages.

These tasks implement the selected authorization-code profile of Core; additional response types and optional features are tracked in section 11. [Core specification](https://openid.net/specs/openid-connect-core-1_0.html)

## 7. Token issuance and lifecycle

Proposed defaults: authorization transaction 10 minutes, authorization code 60 seconds, access token 10 minutes, ID token 5 minutes, and refresh family maximum 30 days with a 7-day inactivity limit. Make lifetimes configurable and validated; use an injected clock in tests.

Require PKCE S256 for all code clients in the initial release. Persist challenge/method with the code and enforce verifier syntax and binding. Do not allow downgrade to plain or missing PKCE. The management UI must make this provider policy visible. [PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)

Initial client authentication supports `client_secret_basic`, `client_secret_post`, and `none`. Enforce the registered method, reject multiple simultaneous authentication methods, compare secrets safely, and rate-limit failures. Token requests validate client binding, grant type, code expiry, redirect binding, and PKCE before issuance. Consume the code and persist tokens in one transaction; concurrent exchange must produce at most one success. Reuse detection revokes artifacts linked to the consumed code where applicable.

Use opaque, high-entropy access and refresh tokens initially; persist only token hashes. Store access-token audience/resource, client, user, granted scopes, expiry, and revocation linkage. The first resource is `/userinfo`; avoid promising general API access tokens until audience/resource policy exists.

Refresh tokens are bound to the original client, user, and grant. Rotate atomically, retain consumed-token tombstones, and revoke the family on replay. Scope may stay the same or narrow, never expand. Offline access requires explicit consent and an allowed client grant; preserve original authentication time when refreshing. Define refresh ID-token behavior and subject/nonce continuity explicitly in the chosen provider adapter.

Do not send tokens in URLs or logs. Token endpoints return OAuth errors, not the management API's error envelope. Credential-bearing responses use no-store. Client authentication failures use the appropriate HTTP status and authentication challenge. Password grant and implicit token delivery are excluded from the initial security profile. [OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html)

## 8. Claims, subjects, and consent policy

Build a dedicated claims projector; never serialize an entire stored user as an ID token or UserInfo response.

- ID tokens include issuer, audience, subject, issuance/expiry, and applicable nonce/authentication-time fields. Add other protocol claims only when required by the implemented flow. Use an explicit signing algorithm policy and correct `kid`.
- Map `profile`, `email`, `address`, and `phone` scopes to the corresponding existing profile attributes. Include verification flags only from their protected stored values.
- Keep standard profile disclosure primarily in UserInfo for the initial code flow. Consent and per-client policy control any additional ID-token claims.
- Custom attributes require explicit per-client claim allowlists and user consent. Prevent reserved-name collisions. Self-editable custom attributes cannot be treated as trusted roles, group membership, or authorization evidence.
- Public subjects reuse immutable account IDs. Add pairwise subject support as a separate delivery with durable per-sector mappings; never substitute public subjects for a client registered as pairwise.
- Do not assert MFA, assurance levels, or authentication methods that the application has not actually performed. Requests for unsupported essential assurance must fail appropriately.

Add server-controlled client policy alongside registration metadata: allowed scopes, allowed custom claims, consent behavior, protocol enabled/disabled state, and a policy/security revision. This is administrative policy, not a user-editable profile claim. The default permits supported standard scopes, requires consent, and exposes no custom attributes.

Consent records bind issuer, user, client, scopes/claims, and relevant policy revision. New permissions require a new decision. A returning user may reuse an applicable stored consent except when interaction parameters require otherwise.

## 9. Persistence, revocation, and migration

Extend the existing storage transaction interface with these conceptual records:

| Record | Essential state |
| --- | --- |
| Authorization transaction | Validated request, browser binding, expiry, login/consent progress, consumption state |
| Authorization code | Hash, client/user/grant, redirect, PKCE, nonce, auth time, expiry, consumption/reuse linkage |
| Access token | Hash, audience, client/user/grant, scopes, expiry, revocation state |
| Refresh token/family | Hash, family and parent, client/user/grant, scope, expiry, rotation/reuse state |
| Consent/grant | User/client, approved disclosure, policy revision, timestamps, revocation |
| Client assertion replay marker | Client, assertion identifier, expiry; needed for JWT client authentication |
| Pairwise subject mapping | Issuer, sector, immutable user ID, stable subject; added with pairwise support |

Use one atomic transaction boundary for identity checks and protocol mutations. Avoid separate JSON files with independently committed code consumption and token issuance. Keep signing-key storage separate because its lifecycle differs from grant state. Version the identity document and provide tested migration/backup behavior for existing installations.

Extend current security-change behavior: user deletion/disabling, password changes, security-relevant account changes, client deletion/disabling, and client security-policy changes invalidate relevant outstanding grants/tokens. Secret rotation revokes the client's outstanding protocol grants under the proposed conservative initial policy. Check current user/client eligibility on every token exchange and UserInfo access. Ordinary name/address edits do not require revocation.

Browser logout terminates its session and pending transactions. Explicitly consented offline grants persist until their own expiry or revocation; account security events still invalidate them. Users can revoke grants through self-service. Opaque tokens permit immediate enforcement at UserInfo; already-issued ID tokens remain valid to relying parties until expiry, which must be documented.

Add expiry cleanup, tombstone retention sufficient for replay detection, store-size limits, and restart/concurrent-process tests. A future database adapter must provide equivalent isolation and conditional-consumption semantics.

## 10. Transport and integration safeguards

- Keep management JSON/CSRF middleware separate from OAuth form-encoded endpoints. Do not use the session-expired SPA behavior for protocol errors.
- Discovery and public JWKS can allow noncredentialed cross-origin reads. Configure narrowly scoped, noncredentialed CORS for browser public-client token/UserInfo use; never enable wildcard credentialed access or global management API CORS. CORS is not authentication.
- Match registered redirect URIs independently from any CORS origin policy. Register trusted public-client origins explicitly when browser exchanges are enabled.
- Use request size limits, timeouts, endpoint-specific rate limits, redacted audit events, and bounded cleanup jobs. Log event/outcome identifiers, not codes, tokens, secrets, assertions, or authorization query strings.
- Remote client JWKS, sector documents, and request objects need a dedicated fetcher before their use: HTTPS, DNS/IP checks including redirects, private/link-local/metadata-address blocking, response size/time limits, and bounded caching. Do not dereference token-supplied key URLs.
- Register protocol methods and method-not-allowed/error responses ahead of the production SPA and Vite proxy. Test both hosting modes and malformed/trailing-path requests.

## 11. Capability delivery matrix

| Capability | Initial code-flow release | Subsequent work |
| --- | --- | --- |
| Discovery, public JWKS, RS256 ID tokens | Included | Rotation administration and additional vetted algorithms |
| Authorization code + S256 PKCE | Included | Interoperability refinements |
| Standard scopes and JSON UserInfo | Included | Individual `claims` requests, localized claim projection, signed/encrypted UserInfo |
| Secret basic/post and public clients | Included | `private_key_jwt` and `client_secret_jwt`, strict audience/algorithm checks and assertion replay prevention |
| Refresh/offline access | Required before enabling offline-access advertisement | Revocation endpoint and self-service grants complete the lifecycle milestone |
| Public subjects | Included | Pairwise identifiers and validated sector documents |
| Request objects / `request_uri` | Explicitly unsupported | Signed/encrypted request validation and safe remote retrieval |
| ID-token encryption | Explicitly unsupported | Per-client algorithms, key use, and key derivation validation |
| Implicit/hybrid response types | Rejected | Separate compatibility decision and security/conformance work; not promised by the initial profile |
| WebFinger issuer discovery | Not required for configured-issuer clients | Implement separately if account-based issuer discovery is needed |
| Dynamic client registration | Existing admin registration only | Separate registration-token API and policy design if requested |
| RP logout and introspection | Not advertised | Separate extensions with their own authorization/metadata rules |

Before enabling protocol service, audit existing client metadata and present compatibility failures on client detail. A client requiring pairwise subjects, JWT authentication, encryption, or unsupported response types must not silently fall back to different security settings. Permit code flow for a client only when its mandatory settings and the requested flow are supported. Updating management validation must preserve stored metadata and make migration decisions visible.

## 12. Ordered implementation milestones and acceptance gates

1. **Provider foundation and dependency spike.** Choose the protocol/JOSE libraries; document adapters, capability registry, issuer configuration, and runtime client policy. Gate: a repeatable in-memory exchange and compatibility report for existing client fixtures.
2. **Storage, initialization, and keys.** Extend `init` to generate and safely reuse the RSA key/self-signed certificate, including upgrade behavior for existing users. Add migrations, protocol records, atomic operations, explicit key rotation, and discovery/JWKS handlers. Gate: fresh/repeated/concurrent initialization, interrupted-init recovery, certificate/key matching, file permissions, restart stability, public-only JWKS, atomic replay tests, and unchanged existing data/API authorization tests.
3. **Authorization interactions.** Add validated authorization transactions, form-login continuation, reauthentication, consent, and safe callback handling. Gate: active user and admin can authorize; invalid redirects never receive callbacks; silent requests never render UI; cross-browser consent replay fails.
4. **Code exchange and UserInfo.** Add client authentication, S256 checks, code consumption, opaque access tokens, signed ID tokens, and scoped claims. Gate: an independent relying-party client completes discovery → login/consent → code exchange → signature validation → UserInfo.
5. **Lifecycle completion.** Add refresh rotation/replay handling, grant revocation UI, `/revoke`, policy revisions, account/client invalidation hooks, and cleanup. Gate: race/restart tests and evidence that security changes invalidate the intended tokens. Only now enable offline-access discovery.
6. **Additional Core capabilities.** Deliver JWT client authentication, pairwise subjects, claims requests, request objects, and signed/encrypted responses in separately tested increments. Gate: each implemented capability is reflected accurately in metadata and discovery.
7. **Interoperability and release.** Run the relevant OpenID Foundation conformance profiles plus browser integration tests. Document the tested profile and exclusions; do not claim certification without completing the certification process. Gate: no advertised feature lacks passing coverage.

## 13. Verification checklist

- Existing admin/user API authorization, client management, profile editing, and SPA navigation still pass.
- Discovery URLs are consistent with the configured issuer, including behind a proxy; attacker-controlled headers cannot change them.
- Unregistered redirects, wrong clients, absent/wrong PKCE, expired/reused codes, and unsupported mandatory metadata fail safely.
- Two concurrent exchanges of one code yield at most one success; refresh reuse revokes the family even after restart.
- A browser cookie alone cannot call token/UserInfo/introspection successfully; access and ID tokens cannot unlock `/api/admin`.
- Consent cannot be submitted for another user/browser, altered to add scopes, or replayed after consumption.
- `prompt`, `max_age`, nonce, authentication time, and account disabling behave correctly through login/session rotation.
- ID-token audience/issuer/signature/expiry and UserInfo subject consistency are validated by an independent client.
- Custom attributes, password hashes, client secrets, storage identifiers, and admin roles are not accidentally disclosed.
- Fresh `init` creates a matching self-signed RSA certificate and private key; an ID token signed with that key verifies with the certificate's public key and published JWK.
- Repeated `init`, `init --force`, and server restarts preserve existing valid keys and users. Existing-user upgrades add only missing signing material; interrupted/concurrent initialization never activates an incomplete pair.
- Missing, corrupted, mismatched, or expired active material fails startup when OIDC is enabled. Certificate-expiry and rotation-boundary tests use an injected clock.
- Signing-key rotation preserves verification of unexpired artifacts; private material never appears in JWKS, CLI output, logs, or API responses.
- New protocol endpoints return correct protocol errors/content types, including in development proxy mode.

This document is the first deliverable. Application implementation begins with milestone 1 after the plan is reviewed; this planning task does not change application behavior.

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OAuth 2.0 Security Best Current Practice — RFC 9700](https://www.rfc-editor.org/rfc/rfc9700.html)
- [Proof Key for Code Exchange — RFC 7636](https://www.rfc-editor.org/rfc/rfc7636.html)
