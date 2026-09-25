# Logout and session activity implementation plan

Status: implemented on `feature/logout-session-activity`. The sections below preserve the design proposal; the shipped API and operational defaults are documented in README.md.

Implementation decisions: delivery concurrency is one request per process; retry (24 hours), history (30 days), and creation limits are fixed in this release. Native custom-scheme logout return URLs are excluded. Session-management actions create durable operation summaries; protocol/legacy logout is represented by per-session and per-app delivery events. The completion page uses an explicit Continue link after attempting notifications, so it works without JavaScript. Migration assigns stable opaque IDs to legacy provider sessions without inventing historical app associations.

## 1. Scope and intended behavior

Implement RP-initiated, OP-initiated, front-channel, and back-channel logout, with self-service and administrator session management. Cover current-session logout, another device, all devices, individual app sessions, administrative/security revocation, and provider-session expiry.

An OP session is a browser login to this provider. An app session is this provider's recorded association between that OP session and a relying party (RP). The actual app cookie and local session belong to the RP. The OP cannot observe app-only logout, every app request, or whether an app UI has refreshed. Activity pages must make that boundary explicit.

Local logout inside an external app remains that app's responsibility. Provide integration documentation and two test RPs demonstrating local logout and shared logout. Do not add an inbound back-channel endpoint to this OP: it sends notifications; registered RPs receive them. Upstream identity federation and OIDC Session Management's `check_session_iframe` are separate features.

### Logout scope and policy

| Trigger/action | OP scope | App scope and notification | Grants |
| --- | --- | --- | --- |
| External app local sign-out | None | That app only; OP has no standard notification of this event | App's own policy |
| RP-initiated `/logout` | Current, verified OP session after confirmation | All linked app sessions, including initiating RP | Ordinary logout policy below |
| Provider's Sign out | Current OP session | All linked app sessions | Ordinary logout policy |
| End selected app session | None | Selected association only | Revoke its session-bound artifacts |
| Sign out another device | Selected OP session | All associations for that session; back-channel remotely | Ordinary logout policy |
| Sign out all devices | All user's OP sessions | All linked associations | Preserve offline access unless explicitly revoked |
| Password/account security change or disable/delete user | All affected user's sessions | Notify affected RPs | Revoke all affected grants, including offline access |
| Disable/delete client or client security policy change | Preserve unrelated OP sessions | End affected client associations | Existing client revocation policy remains effective |
| OP session expiry | Expired session | End linked associations; enqueue back-channel | Ordinary logout policy |
| Revoke app access/consent | Preserve OP sessions | End that user's associations for that client | Revoke client-specific consent and grants, including offline access |

Ordinary logout revokes linked pending authorization transactions, unused codes, and online access/refresh artifacts. Explicitly consented offline grants survive, matching the existing documented policy. Offer a separate, clearly described “Revoke offline access too” choice on self-service bulk actions. Consent itself survives ordinary logout. Client-credentials grants have no browser session and are unaffected by browser logout. Already-issued signed ID tokens cannot be recalled.

Ending one app association leaves provider SSO available, so a later authorization request can sign that app in again. Explain this in the action confirmation. Ending sessions and revoking future app access are distinct actions.

## 2. Current code and changes needed

| Current implementation | Planned change |
| --- | --- |
| `internal/identity/store.go`: `Session` has credential hash, CSRF secret, user, expiry, authentication time | Add public opaque session ID, lifecycle and display metadata; never expose credential hashes or CSRF values in activity |
| `internal/identity/service.go`: `Logout` deletes one session; `Login` rotates the cookie | Route real session termination through one transactional operation; distinguish cookie rotation from logout |
| `internal/identity/file_store.go`: schema version 4; pruning deletes expired sessions | Migrate schema, retain bounded session history, enqueue expiry notifications before cleanup |
| `oidc_records.go`, `oauth_store.go`, authorization/code/refresh services | Persist OP/app linkage throughout issuance and enforce termination during exchange and refresh |
| `internal/identity/monitor.go`, `internal/api/monitor.go` | Extend admin monitoring with session and logout projections; add owner-scoped services |
| `ui/src/pages/Activity.tsx`, `ActivityTable.tsx`, `ActivityNavigation.tsx` | Reuse filtering/detail/confirmation patterns; add session-specific tables and delivery details |
| Client metadata, runtime compatibility, dynamic registration, discovery | Add validated logout metadata and capability advertisement together |
| `internal/server/server.go`, `internal/api/router.go` | Mount logout protocol routes ahead of SPA fallback; keep browser API authorization separate |

The existing activity categories cover transactions, codes, tokens, consent, refresh tokens, and initial access tokens. They are retained operational records, not a complete audit history. Add explicit session history and logout events without relabeling existing token rows as app sessions.

## 3. Session and delivery data model

Extend the identity store transaction interface and file schema with:

| Record | Required fields and invariants |
| --- | --- |
| OP session | Random public ID distinct from cookie/hash; user; authentication/creation/last-seen/expiry times; ended time/reason; safe browser/device description; optional minimized network metadata |
| App session association | Random ID and protocol `sid`; OP session ID; client; actual issued subject; created/last-provider-interaction times; ended time/reason; logout metadata revision |
| Logout operation | Random ID; initiating actor/source; target scope; reason; created/committed times; aggregate local and delivery outcome |
| Logout delivery | Operation and association IDs; channel; validated endpoint snapshot/revision; status; attempts; next attempt; lease; last HTTP outcome; bounded error code |
| Logout interaction | Short-lived browser binding, validated RP request/return URI/state, target IDs, confirmation/completion state, expiry |
| Audit event | Actor, action, target IDs, time, outcome, correlation ID; no cookies, tokens, hashes, or raw request parameters |

Use a separate random `sid` per OP-session/client association. Reuse it for repeated login exchanges in that live association; issue a new value after termination. Include it in supported clients' ID tokens and subsequent refresh ID tokens while preserving original authentication context. Never use a user ID, cookie value, or credential hash as `sid`.

Record participation atomically with successful code exchange/ID-token issuance. Bind the pending authorization request and code to the OP session earlier so logout can stop an exchange in flight. Persist app-session IDs on online token/family records. A refresh from a surviving offline grant must not resurrect an ended association or create a new browser session; any historical `sid` retains its original identity and cannot target a later session.

Cookie rotation for the same authenticated browser/user preserves the logical OP session and associations; account switching ends the previous logical session and creates another. Test `prompt=login`, failed reauthentication, and account switches explicitly.

Migrate existing OP sessions with new opaque IDs and unknown display metadata. Do not infer historical app associations from user/client token coincidences. Mark existing unlinked grants as legacy; preserve their documented lifetime/revocation behavior, and disclose that selective session revocation only covers linked artifacts. Account-wide security revocation still covers legacy grants. New logins and code exchanges establish complete linkage.

## 4. One transactional termination operation

Add identity-domain operations for ending one OP session, one app association, a user's sessions, and user/client access. Every entry point uses these operations, including password changes, disable/delete, client policy mutations, and expiry processing.

Within one serializable write: authorize the actor, resolve targets, mark lifecycle state, invalidate applicable credentials/grants, append audit data, and create durable delivery intents. Repeated termination is idempotent. Network delivery and JWT signing happen outside the store lock. Failure to reach an RP never restores a terminated OP session.

Recheck session/association eligibility inside code and refresh issuance transactions. Concurrent logout cannot produce a newly usable online credential after termination commits. Snapshot notification targets before deleting users/clients; otherwise existing delete cascades can lose the information needed for logout.

Enforce expiry on every authentication check; a bounded background sweep also materializes expiration and delivery intents without requiring user traffic. Cleanup retains records needed for delivery, recent ID-token hints, and replay detection. Proposed configurable defaults: 30 days of ended-session/event history, 24 hours of delivery retry, and seven days of bounded recent-session hint association history. Set total record and queue limits and surface saturation; never silently drop required delivery intents.

## 5. RP-initiated and provider browser logout

Implement `GET` and form-encoded `POST /logout`; publish `end_session_endpoint` only when enabled. Accept the standard parameters: `id_token_hint`, `client_id`, `post_logout_redirect_uri`, `state`, `logout_hint`, and `ui_locales`.

Validate provider-issued hints with known signing keys, issuer, client/audience, subject and session association. A bounded recent-session match can accept an expired hint; it is never a general bearer credential. Verify `client_id` consistency. Exact-match return URIs against `post_logout_redirect_uris`; invalid requests render a local error without an untrusted redirect. Treat `logout_hint` as a hint only; initially it adds no authority. Unsupported locales fall back to English.

Use a confirmation page by default, and always when the hint is absent or mismatches the current browser session. Never terminate another account merely because a supplied hint names it. Bind confirmation to a short-lived interaction and browser nonce; protect the decision POST against CSRF and replay. A missing cookie or old hint must not silently become account-wide logout. Cancellation leaves the OP session intact and shows a local cancellation result.

On confirmation, commit termination, attempt notifications to all linked RPs including the initiator, render applicable front-channel frames, then use the validated return URI with the original `state`. Use a bounded initial delivery wait; durable back-channel retries continue after browser completion. Clearly report pending/failed app notifications.

Keep `POST /api/auth/logout` as a compatible current-provider-session action with its existing response contract, extending it to enqueue back-channel notifications. Add a prepare/complete interaction API for the first-party Sign out UI so it can run front-channel completion after clearing authentication. Completion access uses a short-lived, narrowly scoped browser-bound capability, not the deleted login session. Confirmation/completion pages sit outside `AuthGuard`, as the existing OIDC continuation page does.

Normative reference: [RP-Initiated Logout 1.0](https://openid.net/specs/openid-connect-rpinitiated-1_0.html). The additional retention, confirmation-by-default, and lifecycle policies above are implementation decisions.

## 6. Back-channel delivery

Register `backchannel_logout_uri` and `backchannel_logout_session_required`; advertise provider support and session support only after delivery is operational. Send form-encoded `logout_token` to the RP by HTTP POST.

Use the existing signing-key service with a dedicated Logout Token claim builder and explicit token type. Include `iss`, client-specific `aud`, `iat`, `exp`, unique `jti`, the back-channel logout `events` member, and the stored `sid`/subject as appropriate; exclude `nonce`. Prefer `sid`-scoped notifications to avoid terminating unrelated devices. Use the RP's actual subject value, not an assumed global subject.

A durable worker leases jobs transactionally, sends outside locks, and records results. Proposed policy: five-second request timeout, bounded concurrency, exponential backoff with jitter up to 24 hours, retry network/429/5xx outcomes, cap Retry-After, and expose terminal failures. Treat HTTP 200 as acknowledged; classify other responses under protocol rules. Generate a fresh short-lived signed token for a retried logical notification and require idempotent RP session termination. Retain public signing keys through verification windows. Recover expired leases after crashes and support multiple server processes without concurrent job ownership.

Protect this outbound fetch surface: HTTPS in production, no redirects, bounded body/time, DNS and resolved-address checks at connection time, block loopback/private/link-local/metadata destinations by default, and prevent DNS rebinding. Explicit development or administrator-controlled private-network allowlists support internal RPs. Apply checks to admin and dynamically registered URLs. Endpoint changes require safe reconciliation: do not silently retarget old jobs to a new URL; cancel invalidated destinations and surface undelivered logout.

Normative reference: [Back-Channel Logout 1.0 with errata set 1](https://openid.net/specs/openid-connect-backchannel-1_0.html). Retry, network policy, and queue design are provider implementation choices.

## 7. Front-channel delivery

Support `frontchannel_logout_uri` and `frontchannel_logout_session_required`, with matching discovery flags. Validate absolute URLs, no fragments, and the required origin relationship to a registered login redirect. Render escaped iframe URLs preserving registered query parameters; include both `iss` and `sid` when either is sent.

Build a minimal completion page with no third-party assets, no-store and no-referrer headers, and CSP limited to the intended RP frame origins. Keep the provider session cookie policy intact. RP documentation must explain iframe-compatible CSP/frame headers and browser cookie/storage restrictions.

Allow both registered channels: back-channel invalidates server sessions and front-channel can clear local browser state. Dispatch is idempotent. An iframe load event is not proof that logout succeeded; record “browser request attempted; unconfirmed,” timeout, or browser unavailable. Never label front-channel loading as acknowledged app logout.

For remote-device, administrator, scheduled-expiry, and security-event logout, the affected browser is generally unavailable. Do not load another device's logout URL in the administrator's browser. Deliver back-channel where supported and mark front-channel-only associations unconfirmed. A short-lived browser-bound completion interaction may run if that same browser returns, but cannot be required for enforcement.

Normative reference: [Front-Channel Logout 1.0](https://openid.net/specs/openid-connect-frontchannel-1_0.html).

## 8. Activity pages and actions

### Administrator activity

Add `/activity/op-sessions`, `/activity/app-sessions`, and `/activity/logout-events` to existing navigation and dashboard counts. Add deep links from user and client detail pages with filters preserved.

| Page | Table and detail data | Actions |
| --- | --- | --- |
| OP sessions | User, browser/device label, current session badge, creation/authentication/last-provider-seen/expiry times, active/ended/expired state, reason, linked app count | End selected session; inspect apps; end user's sessions |
| App sessions | App, user, linked OP session, creation and last provider interaction, provider association state, logout delivery summary | End association; inspect OP session and grant links; view delivery attempts |
| Logout events | Time, actor/source, reason, scope, local outcome, counts of acknowledged/pending/failed/unconfirmed/unsupported deliveries | Inspect attempts; retry eligible back-channel failures |

Show lifecycle and delivery state separately: “Ended at provider; app notification pending” is valid. Use “Known app sessions” and explain that active means no termination is recorded at the OP, not verified activity inside the app. Avoid a misleading total “devices online” count. Last seen means provider-observed activity; device labels are inferred, not verified identities.

### User self-service

Add `/sessions` (“Your sessions”) for both users and administrators viewing their own account. Group apps under provider sessions; show current device, dates, expiry and known app associations. Include “Sign out this session,” “Sign out other sessions,” “Sign out all sessions,” and “Sign out of this app.” Add a separate connected-app access action for revoking consent/offline grants, with explicit consequences.

Confirm scope before destructive account-wide actions and require recent password authentication for all-device/offline-access revocation. Explain which apps cannot confirm remote logout. Clear auth/query caches and navigate to the completion page when the current session ends; use the existing unauthorized response handling when another device/admin ends it.

Reuse current pagination, filtering, loading/empty/error states, 15-second refresh pattern, themes, and accessible dialogs. Pause polling during confirmation; keep focus restoration and mobile layouts. Ordinary users see only their own records and redacted outcomes, never another user's sessions or detailed outbound endpoint diagnostics.

### API contract

| API | Authorization / result |
| --- | --- |
| `GET /api/user/sessions`, `GET /api/user/app-sessions` | Owner-scoped paginated projections |
| `POST /api/user/sessions/{id}/logout` | End own selected OP session |
| `POST /api/user/sessions/logout` | Explicit `other` or `all` scope; optional separately confirmed offline revocation |
| `POST /api/user/app-sessions/{id}/logout` | End own selected app association |
| `POST /api/user/clients/{id}/revoke-access` | Revoke own client consent/grants and end its associations |
| `POST /api/auth/logout/prepare` | Prepare current-browser provider logout interaction |
| `GET/POST /logout/interaction/{id}` | Browser-bound status/decision/completion; no general session-list access |
| `GET /api/admin/activity/{kind}` | Add `op-sessions`, `app-sessions`, `logout-events` kinds |
| `POST /api/admin/sessions/{id}/logout` | End selected OP session |
| `POST /api/admin/users/{id}/sessions/logout` | End user's sessions with explicit scope/reason |
| `POST /api/admin/app-sessions/{id}/logout` | End selected association |
| `GET /api/admin/logout-operations/{id}` | Redacted delivery details |
| `POST /api/admin/logout-deliveries/{id}/retry` | Authorized, bounded retry of eligible failed delivery |

New mutation APIs return an operation ID and local outcome, with asynchronous delivery status; they must not return blanket “all apps logged out.” Preserve the existing logout endpoint's 204 contract. Apply same-origin/CSRF protection, owner checks inside storage transactions, body limits, rate limits, and no-store responses. UI opacity is not authorization. Return non-enumerating errors for foreign session IDs. Protocol bearer tokens cannot call these management APIs.

## 9. Implementation milestones and acceptance gates

1. **Session foundation.** Migrate storage; create OP IDs and app associations; wire `sid`, issuance linkage, logical-session rotation and history. Gate: two browsers and two RPs have correct independent associations; refresh preserves linkage; legacy data loads without invented associations.
2. **Central termination and outbox.** Implement scopes, security/delete hooks, expiry sweep, online/offline policy, audit projections and durable jobs. Gate: atomic race/restart tests; no lost jobs on deletion; all existing security revocation behavior remains effective.
3. **Back-channel and metadata.** Add safe sender, signed Logout Tokens, retries, endpoint controls, client editor/dynamic registration validation and discovery. Gate: independent RP validates tokens; unreachable/hostile endpoints are bounded; restarted workers resume jobs.
4. **Browser logout protocols.** Add RP-initiated validation, confirmation, front-channel page, provider Sign out integration and safe completion redirects. Gate: App A initiates shared logout, App B loses server access, and unrelated device sessions remain active; cancellation and partial delivery are truthful.
5. **Activity and self-service.** Deliver all pages/APIs, user/client deep links, recent-auth confirmations and retry diagnostics. Gate: users cannot enumerate or mutate foreign records; current-session termination navigates correctly; active/ended versus delivery status stays distinct.
6. **Expiry/security integration and release.** Exercise every trigger end-to-end, document RP integration and operational configuration, reconcile README and older implementation-plan logout status. Enable only tested capabilities. Gate: two-RP multi-browser interoperability and failure matrix below passes.

## 10. Verification and release criteria

- Run focused Go identity/OIDC/API/server tests during implementation, then `go test ./...` and relevant race tests. Run UI tests, lint and build from `ui`. Run the Playwright suite against disposable test services following `tests/README.md`; maintain its manual-only execution convention.
- Cover local App A logout (B remains active), RP shared logout (A and B ended), provider sign-out, selected app/device, other/all devices, password change, disable/delete, consent/offline revocation, client changes, and scheduled expiry.
- Test two users, two devices per user, and two real test RPs using distinct origins. Front-only, back-only, both-channel, and no-logout-support clients must have accurate status. Verify App B's next protected request, not merely a logout-page screenshot.
- Test missing/invalid/expired hints, old signing keys, mismatched user/client/session, forged/duplicate parameters, unregistered return URIs, state handling, cancellation, CSRF/replay, missing cookies, and interactions after the OP cookie has been cleared.
- Validate Logout Token signature/type/claims, expiration, audience, absence of nonce and replay-safe RP processing with an independent verifier. Confirm `sid` never terminates another device or a newly created session.
- Exercise browser frame/storage blocking, closing the page mid-logout, remote front-only sessions, redirect timeouts, RP 429/500 responses, permanent failures, duplicate delivery, crashes before/after HTTP success, lease expiry and concurrent workers.
- Test SSRF through direct URLs, DNS rebinding, redirects, endpoint metadata updates and dynamic registration. Verify tokens/credentials, sensitive URLs and unredacted response bodies never enter activity APIs/logs.
- Race logout with code exchange, refresh, login rotation, security mutation, expiry cleanup and deletion. Verify surviving offline grants do not recreate browser associations and selected-app logout cannot affect sibling apps.
- Test migration/restart/cleanup retention and bounded file-store growth. Retain pending delivery dependencies until terminal resolution; document backups, queue recovery and signing-key overlap.
- Verify keyboard/mobile/dark-mode pages, polling and filter behavior, recent-auth flows, foreign-record authorization, current-session cache clearing, and honest partial-failure copy.

Release documentation must state that RP delivery acknowledgment is not evidence that an open UI refreshed, front-channel delivery is best effort, and external app-only logout is not observable by this provider. This completes the logout extensions described here without claiming OpenID certification.
