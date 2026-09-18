# OAuth 2.0 endpoints and grants implementation plan

Implementation status (2026-09-17): implemented. Operator configuration, client/user permissions, protocol examples, refresh rotation semantics, and the opt-in legacy password exception are documented in README.md under “OAuth token lifecycle and API access.” Refresh and password grants remain disabled by default. This document retains the design and verification requirements; implementation does not claim certification or full OAuth/OIDC conformance.

The following sections preserve the approved design and its pre-implementation findings.

## 1. Scope and standards

Add `POST /introspect`, `POST /revoke`, and a grant dispatcher at the existing `POST /token`. Deliver client credentials as the supported machine-to-machine grant and rotating refresh tokens for eligible authorization-code sessions. Include a separately gated resource owner password credentials (ROPC) compatibility phase as requested. Preserve authorization code + PKCE, OIDC login, dynamic registration, and existing admin/user API boundaries.

Standards baseline:

- [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html): authenticated introspection with a mandatory `active` result. Invalid/inactive tokens return `active: false`; hints must not prevent lookup of supported token types.
- [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009.html): form-based token revocation, client ownership checks, and HTTP 200 for successful revocation or an invalid token. Unknown hints are ignored.
- [RFC 6749 sections 4.3 and 4.4](https://www.rfc-editor.org/rfc/rfc6749.html): password and client-credentials request/response formats. Client credentials requires a confidential client; refresh tokens should not be included in its response.
- [RFC 9700 section 2.4](https://www.rfc-editor.org/rfc/rfc9700.html#section-2.4): ROPC **MUST NOT be used** under current OAuth security best practice. Enabling a legacy implementation is an explicit departure from that guidance; allowlisting and rate limiting do not make it compliant. Authorization code + PKCE remains the recommended user flow.
- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707.html): resource indicators to identify the intended API. This project will initially accept one resource per token and reject unsupported or ambiguous targets.
- [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414.html): OAuth authorization-server metadata, including introspection/revocation endpoints and their authentication methods.

Initial scope includes refresh-token issuance, rotation, and family revocation. It excludes JWT access tokens, token exchange, device authorization, JWT client authentication, and resource-server implementation. Do not describe this release as supporting those extensions or as fully certified OAuth/OIDC conformance.

Additional refresh references: [RFC 6749 section 6](https://www.rfc-editor.org/rfc/rfc6749.html#section-6) for refresh requests and scope restrictions; [RFC 9700 section 4.14](https://www.rfc-editor.org/rfc/rfc9700.html#section-4.14) for replay protection; [OIDC Core sections 11–12](https://openid.net/specs/openid-connect-core-1_0.html#OfflineAccess) for offline consent and OIDC refresh behavior. This project chooses rotation for both public and confidential clients.

## 2. Existing implementation and required refactoring

Refresh-flow review, 2026-09-17: **not implemented**. `internal/oidc/token.go` rejects grants other than authorization_code and its response has no refresh_token field. `internal/oidc/capability/capability.go` advertises authorization_code only. `internal/identity/oidc_records.go` and Store have no refresh-token records or operations. `internal/config/config.go` explicitly reserves RefreshMaxTTL (30 days) and RefreshInactivityTTL (7 days) for future implementation. Accepting refresh_token as client registration metadata does not provide runtime support.

| Current behavior | Required change |
| --- | --- |
| `internal/oidc/token.go` handles only authorization code and always returns an ID token. | Dispatch by grant after common parsing/authentication. Make ID-token serialization optional. Keep code redemption and replay revocation atomic. |
| `AccessToken` has a required-by-convention user, `Audience: "userinfo"`, and optional code link. | Add explicit grant type and subject kind, supporting machine tokens without a user or code. Keep opaque tokens and hashed persistence. |
| Client validation requires redirect URIs and OIDC response types for all clients. | Add OAuth-only client profiles, with redirect/response requirements applied only to browser grants. |
| Client authentication rejects anything incompatible with the complete OIDC profile. | Separate credential authentication from endpoint/grant eligibility. A valid OAuth-only client must not need OIDC signing or redirect settings. |
| UserInfo performs its own token, client, and account checks. | Introduce a shared token-activity evaluator; add UserInfo-specific user/audience/openid checks afterward. |
| Local storage provides atomic reads/writes and grant invalidation. | Extend the existing Store/Tx interfaces and migrate token/policy records; keep filesystem details inside the adapter. |
| Reserved refresh lifetimes have no enforcement or backing records. | Add refresh families, hashed rotating credentials, atomic exchanges, and validated absolute/inactivity expiry. |
| Activity assumes tokens normally have a user and ID-token expiry. | Display machine subjects, grant type, audience, and absent ID tokens accurately. |

Refactor before adding grants so no new branch bypasses existing client-secret checks, PKCE, consumed-code handling, or account invalidation.

## 3. Authorization model and resources

Introduce a trusted resource registry in server configuration for the first release. Each resource has an exact audience URI, enabled flag, and supported scopes. Resource identifiers are names, not URLs the server fetches. Do not accept arbitrary audiences or infer an API audience from an untrusted Host header.

Add a separate, admin-managed OAuth policy to client records:

- Allowed grants and per-resource allowed/default scopes.
- Optional single default resource; otherwise require an explicit `resource` on machine/password token requests.
- Introspection enabled flag plus permitted resource audiences.
- Explicit refresh issuance permission; registration of the refresh_token grant alone is insufficient.
- Explicit legacy-password permission, separate from ordinary client-credentials access.

Store policy outside user-controlled registration metadata. Expose it through `/api/admin/clients/{id}/oauth-policy` with existing session, admin, CSRF, and origin checks. Policy changes invalidate affected client tokens atomically. Resource disablement or scope removal also makes existing tokens inactive through live policy evaluation, including after restart.

For the legacy password phase, add admin-managed per-user resource entitlements through `/api/admin/users/{id}/oauth-access`. A user's permitted scopes are the intersection of their entitlement, the client's policy, and the resource's supported scopes. No entitlement means no API access. Profile claims and custom attributes cannot grant entitlements. Application `admin` and `user` roles are not automatically OAuth scopes or API resource permissions.

Dynamically registered clients receive no machine-grant, password-grant, refresh-issuance, or introspection privilege automatically. Reject attempts to set these admin-owned policy fields through registration/configuration APIs. Keep OIDC `/register` semantics and required redirect metadata; create OAuth-only clients through admin management in this release. Supporting general OAuth dynamic registration is a separate extension.

## 4. Protocol routes and credentials

| Route | Caller authorization | Proposed behavior |
| --- | --- | --- |
| `POST /token`, `grant_type=authorization_code` | Existing registered client method and PKCE | Preserve current OIDC behavior. |
| `POST /token`, `grant_type=refresh_token` | Original client binding, registered authentication, permitted refresh grant, and active refresh family | Rotate refresh credential and issue a new access token. |
| `POST /token`, `grant_type=client_credentials` | Confidential client, registered method, explicit grant/resource permission | Issue a machine access token. |
| `POST /token`, `grant_type=password` | Legacy feature flag plus explicitly approved confidential client and valid entitled user | Issue a user API access token; disabled by default. |
| `POST /introspect` | Confidential client explicitly entitled as an introspection caller | Return token state only within its permitted audience boundary. |
| `POST /revoke` | Confidential client authentication, or a public client's ID plus possession of its own opaque token | Revoke only a token issued to that client. |

Initially support the existing `client_secret_basic` and `client_secret_post` methods for confidential callers. Public clients cannot introspect or use client_credentials/password. They may refresh their own eligible PKCE-originated grant using client_id and the refresh credential; no browser session or repeated code_verifier is required. A public client ID alone grants no ability to find or enumerate tokens; revocation also requires the full bearer token and an exact client ownership match.

Cookies, ID tokens, IATs, RATs, and ordinary API access tokens are not endpoint authentication credentials here. Existing `/api/admin`, `/api/user`, and `/api/auth` APIs retain session-based authorization. Resource-server authorization is a distinct permission from token ownership: an introspection caller can inspect an audience it serves even when another client obtained that token.

Use bounded form parsing, reject duplicate security parameters and conflicting credentials, require HTTPS outside explicit loopback development, and reserve routes ahead of SPA fallback. Introspection is server-to-server with no browser CORS. Revocation may use the configured exact-origin, noncredentialed CORS policy for public browser clients. Password requests have no browser CORS support. All sensitive responses use `no-store`; logs exclude passwords, secrets, tokens, and request bodies.

## 5. Token model and lifecycle

Extend stored access tokens with:

- `grantType`: authorization_code, client_credentials, password, or refresh_token; retain the original grant type separately for refreshed tokens.
- Optional refresh family ID linking original and refreshed access tokens to one revocable grant.
- `subjectKind`: user or client; immutable subject identifier and optional UserID.
- Existing single audience, approved scopes, issue/expiry timestamps, client ID, and revocation state.
- Policy revision evidence if needed in addition to live permission checks. Preserve original CodeHash links for code-derived tokens, including refreshed descendants. Record IDTokenExpiresAt only when an ID token was actually issued.

Migrate existing tokens as user/authorization-code tokens with their current UserInfo audience. Never infer a machine principal solely from an empty UserID; malformed or ambiguous legacy records fail closed. Machine subjects use a distinct namespace such as `client:<clientID>` and can never resolve to a user account.

A shared activity evaluator checks existence, expiry, revocation, current client eligibility, current resource policy, and current user state/entitlements when applicable. The existing UserInfo audience has its existing OIDC scope rules; it must not become inactive merely because no custom-resource entitlement exists. Infrastructure/storage failures return errors rather than fabricating an authoritative inactive result.

Issuance commits a token only after current client/policy/account checks in the same transaction. Return the raw token only after commit. Default new-grant lifetime: the existing access-token TTL. Neither client_credentials nor password issues refresh tokens or ID tokens in this release. Eligible authorization-code exchanges may issue refresh tokens under section 10. Reject OIDC scopes (`openid`, `profile`, `email`, `address`, `phone`) for these API-only grants. UserInfo rejects machine/password API tokens, regardless of client or user role.

## 6. Introspection design

Request: required `token`, optional `token_type_hint`. Token lookup covers opaque access tokens and refresh tokens; hints are advisory. Do not interpret an arbitrary JWT as an access token.

After authenticating and authorizing the caller, evaluate the token in one consistent read snapshot. For a valid token, return a minimal projection: `active`, `client_id`, `token_type`, scope string, audience, issuer, issue/expiry times, and correctly typed subject. Omit email, username, custom profile attributes, token hashes, and credentials by default.

Unknown, expired, revoked, deleted-client/user, and out-of-audience tokens all return only `{"active":false}`. An otherwise authenticated client with no introspection entitlement receives a generic 403, independent of the submitted token. Failed authentication receives 401 with the applicable challenge. Never let all confidential clients introspect every token.

Refresh-token introspection requires an additional explicit refresh-inspection permission and ownership by the authenticated issuing client; ordinary resource introspection permission is insufficient. Consumed refresh credentials return active false. Resource servers must never accept a refresh credential as authorization to their APIs.

Initially do not cache positive results at the provider. Document that a resource server caching introspection results introduces revocation delay and must bound its cache by token expiry. Resource servers still enforce audience and required scopes on every protected action.

## 7. Revocation design

Request: required `token`, optional advisory `token_type_hint`. Authenticate/identify the client before processing token ownership. Revoke the matching owned access token or refresh-token family atomically. Repeated, unknown, expired, or another client's tokens return the same empty HTTP 200 response; another client's state never changes.

Do not reuse the admin monitoring API's 409 rule for expired/consumed records: protocol revocation is deliberately idempotent. Admin monitoring continues to disable actions on inactive items.

Revoking an access token affects that access token only. Revoking a refresh token revokes its entire family and all associated access tokens, including the initial access token. Neither action revokes unrelated families or consent. Existing admin consent revocation keeps its broader cascade. ID tokens cannot be recalled and IAT/RAT management remains separate. Ignore unknown hints and search supported token records even if the hint is wrong. Unknown values, including credentials outside this token store, follow the invalid-token no-op behavior; reserve `unsupported_token_type` for a positively recognized OAuth token type that cannot be revoked. Retain consumed refresh hashes long enough to identify and revoke their still-live family when a consumed credential is submitted to /revoke.

## 8. Client credentials grant

Accept `grant_type=client_credentials`, optional scope, and the selected resource. Authenticate the client and require explicit grant permission. If scope is omitted, use that resource's configured client defaults; fail closed if no usable defaults exist. Reject scopes outside the intersection of client and resource permissions rather than silently expanding or substituting them.

Require one permitted resource, or the client's explicit default. Reject multiple resource values in this initial single-audience implementation with `invalid_target`; retain the common parser's rejection of other duplicate security parameters. No redirects, user password, user session, consent transaction, or authorization code is involved. Return access token, Bearer type, expires_in, and granted scope; omit id_token and refresh_token entirely.

## 9. Legacy password compatibility phase

Include the requested wire format (`grant_type=password`, username, password, scope, resource), but keep `oauth.passwordGrantEnabled=false` by default. If enabled, require both client grant registration and a separate admin approval. Do not expose an enablement toggle to dynamically registered clients or regular users. Discovery advertises this grant only when the legacy feature is actually enabled; documentation must retain the RFC 9700 incompatibility notice.

Use the account's existing normalized email as username. Extract a password verification operation from `identity.Service.Login`; do not call Login, create cookies/sessions, or mint CSRF tokens. Preserve dummy-hash checks for unknown users and generic credential errors. Verify passwords outside the storage write lock, then recheck the password hash, identity, active status, client revision, and entitlements inside the issuance transaction.

Apply bounded verification concurrency and rate limits across peer, client, account, and aggregate traffic, so changing client IDs or source addresses cannot trivially bypass protection. Do not trim, log, persist, or echo passwords. A correct password for a disabled or ineligible account still fails. Do not manufacture consent records or claim that password possession completes an interactive/MFA authentication policy. If MFA or another required interaction is introduced, those accounts must be rejected by this grant.

This phase is compatibility-only; enabling it remains inconsistent with current OAuth security best practice. Keep authorization code + PKCE as the supported migration path.

## 10. Refresh-token flow

### Issuance and consent

Add `oauth.refreshTokensEnabled`, disabled by default until explicitly configured, plus per-client refresh issuance permission. Issue a refresh token only when the client registers authorization_code and refresh_token, the user completes the existing PKCE flow, and refresh/offline consent is recorded. This release deliberately limits refresh issuance to OIDC authorization-code flows; password and client_credentials remain access-token-only.

Support `offline_access` in authorization scope validation, discovery, the consent screen, and stored consent. For this project's initial policy, require an explicit offline-access consent decision with `prompt=consent`; do not let existing ordinary consent or `prompt=none` silently authorize offline access. Requests that omit offline_access continue issuing access/ID tokens without refresh tokens. Unsupported offline access must not be advertised or silently approved. Offline access is an authorization condition, not an additional UserInfo profile claim.

Commit initial refresh-family creation, refresh credential, access token, and authorization-code consumption together. Existing code replay detection must also revoke the associated refresh family and descendants, not just the original access token.

### Exchange and rotation

Accept form-encoded `grant_type=refresh_token`, required refresh_token, optional scope, and optional resource. Authenticate confidential clients with their registered method; public clients present client_id and the bound credential. Check the registered grant and current refresh policy before exchange. Token possession cannot change the issuing client, subject, or target resource.

If scope is omitted, reuse the credential's approved scopes. Explicit scope must be a subset; reject expansion with invalid_scope. This implementation narrows both the newly issued access token and successor refresh credential permanently. An omitted resource retains the original audience; a different resource is rejected with invalid_target. OAuth API audiences and UserInfo remain distinct.

Each successful exchange consumes the presented credential, issues a new refresh credential and access token, and updates family activity in one transaction. Concurrent exchanges can yield at most one success. A second use of a consumed credential, after confirming its client binding, revokes the family and associated access tokens; commit that revocation before returning invalid_grant. Wrong-client submissions must fail without revoking the owner's family. No grace window or retry replay is planned: clients must serialize refresh calls and reauthenticate after an ambiguous lost response rather than repeatedly retrying the old credential.

For the initial implementation, refresh responses omit id_token, which OIDC permits. Return access_token, token_type, expires_in, scope, and the replacement refresh_token. Refresh is not a new login: never advance the original auth_time or create a browser session. If ID-token renewal is added later, implement and test the OIDC section 12.2 claim rules separately.

### Persistence and expiry

Add RefreshFamily and RefreshToken records behind Store/ReadTx/Tx. Family data includes ID, client/user binding, original grant and authorization-code link, audience, original approved scopes, offline consent/policy evidence, original authentication time, creation time, absolute deadline, inactivity deadline, and revocation state. Credential records include only a random token hash, family ID, approved scopes, issue time, consumption time/state, and optional successor ID. Link every family-issued access token to the family.

Activate the existing oidc.refreshMaxTTL and oidc.refreshInactivityTTL settings. Validate positive bounded values and inactivity TTL no greater than maximum TTL. Default to the existing 30-day absolute and 7-day inactivity limits. Rotation may extend inactivity only up to the original absolute deadline; it never resets maximum lifetime. Consumed hashes must remain as replay evidence until their family and relevant access-token lifetime have ended. Existing authorization-code pruning must not remove the only evidence linking a live refresh family to a replayed code.

Preserve existing data through a versioned migration; old access tokens gain no refresh authority retroactively. Return no credentials if persistence fails. After restart, expiry, rotation history, and revocation remain effective.

### Lifecycle and monitoring

Password/email/role/security changes, account disablement/deletion, client deletion or security-policy changes, consent revocation, and removal of refresh permission invalidate affected families atomically or through the shared current-policy check. Replacing/revoking an IAT or RAT must not invalidate user refresh grants. Ordinary browser logout ends the browser session only; approved offline grants survive until explicitly revoked, expired, or invalidated by a security event. Turning off global refresh support blocks exchange; expiry clocks continue running. Administrators must revoke existing families if they should not resume after re-enablement.

Add a Refresh tokens category under the existing Activity menu with automatic page-1 loading, 10-per-page pagination, periodic refresh, family/client/user filters, and creation/absolute/inactivity expiry details. Show active/consumed/expired/revoked states and safe IDs only. Active-family revocation includes all descendant access tokens; inactive credentials have no redundant revoke action. Keep protocol /revoke idempotent even for consumed credentials, independently of admin UI restrictions.

## 11. Metadata, UI, and error contract

Publish `/.well-known/oauth-authorization-server` and extend OIDC discovery with enabled endpoint URLs, per-endpoint authentication methods, and accurate grant lists. Advertise refresh_token and offline_access only when implemented and enabled; update the shared capability audit and client grant controls at the same time. Both documents derive from one capability source. Keep OIDC authorization response types limited to what `/authorize` supports; adding machine grants must not imply implicit/hybrid support.

In client create/edit, group client purpose and grants first, then API resources/scopes, followed by advanced introspection permissions. OAuth-only clients do not require irrelevant redirects or ID-token fields. Mark password controls as legacy and unavailable while globally disabled. User detail gains a separate admin-only API entitlements section, not editable profile attributes.

Extend existing Activity token monitoring and dashboard summaries with grant and audience filters and a machine/user subject label. Machine tokens show no ID-token expiry or waiting-for-login placeholder. Do not add another sidebar group or leak raw tokens into monitoring.

| Failure | Contract |
| --- | --- |
| Malformed/missing request parameters | 400 invalid_request |
| Unknown or globally disabled grant | 400 unsupported_grant_type |
| Authenticated client lacks requested grant | 400 unauthorized_client |
| Invalid, expired, revoked, wrong-client, or replayed refresh credential | 400 invalid_grant; bound replay also revokes its family |
| Invalid user credentials or failed legacy account checks | 400 invalid_grant |
| Unsupported/disallowed scopes | 400 invalid_scope |
| Unusable, unauthorized, or ambiguous resource | 400 invalid_target |
| Client authentication failure | invalid_client, with status/challenge matching authentication mechanism and OAuth rules |
| Authenticated caller lacks introspection permission | 403 generic denial |
| Inactive/out-of-audience token during authorized introspection | 200, active false only |
| Validly submitted unknown/repeated revocation | 200, empty body |
| Throttle / storage outage | 429 with Retry-After / 503 server failure; never report successful revocation when a write failed |

## 12. Delivery and verification

1. **Domain foundation:** resource registry, admin policy/entitlement storage, migration, grant-aware metadata validation, authentication separation, and shared token evaluation. All new privileges default to denied.
2. **Lifecycle endpoints:** introspection and revocation for current authorization-code tokens, route reservation, error matrix, discovery, and resource-caller authorization tests.
3. **Machine tokens:** client credentials, API audiences/scopes, OAuth-only client UI, and monitoring projections.
4. **Refresh tokens:** offline consent, family storage, initial issuance, rotating exchange, replay detection, expiry enforcement, lifecycle endpoint integration, and Activity monitoring.
5. **Legacy compatibility:** password verifier extraction, dual enablement, account entitlements, throttling, and atomic rechecks. Keep disabled in the recommended configuration.
6. **Release checks:** documentation, examples, full regression/race/build checks, and independent HTTP integration tests.

Required verification:

- Existing authorization-code/PKCE/login/consent and DCR flows still work; grant refactoring cannot bypass registered grant permission.
- Code + PKCE + explicit offline consent → initial refresh token → rotation → refreshed UserInfo access. Confirm that refresh responses omit ID tokens and no new session is created.
- Concurrent refresh, replay after restart, wrong-client attempts, scope narrowing, audience changes, idle/absolute expiry, failed commits, and lost-response handling behave as specified.
- Revoking a refresh family invalidates its initial and descendant access tokens. Revoking one access token does not cancel refresh; consent revocation and code replay do. Consumed refresh tokens remain usable only as family-revocation evidence, never for exchange or API access.
- Machine token → authorized resource introspection → revoke → inactive; UserInfo and admin/user APIs reject that token.
- Introspection across two resource audiences and two issuing clients: permitted cross-client resource checks work; foreign audiences reveal no metadata.
- Public clients cannot introspect or use machine/password grants; eligible public clients can use bound rotating refresh tokens; they can revoke only a possessed token bound to their own client ID.
- Cookie, IAT, RAT, ID-token, access-token, and client-secret substitution fails at inappropriate endpoints.
- Password grant disabled by default; wrong/unknown/disabled users, absent entitlements, disallowed clients/scopes/resources, and MFA-required accounts fail safely.
- Concurrent password change, account disablement, client policy change, token revocation, and deletion cannot produce a usable token after the invalidating transaction commits.
- Failed commits return no tokens, repeated revocations remain indistinguishable, hints cannot bypass lookup/ownership, and infrastructure failures do not masquerade as inactive tokens or successful writes.
- Migration preserves existing valid OIDC tokens, resource policy changes take effect after restart, and future DB adapters honor the same transaction contracts.
- UI admin guards, logical field groups, machine subject display, automatic paginated activity loading, revocation controls, and secret-free query caches remain correct.

Run Go tests and race checks, vet, UI tests, lint, production build, and real HTTP end-to-end flows. Publish exact implemented capabilities and the legacy exception; do not claim full conformance until applicable conformance testing is completed.
