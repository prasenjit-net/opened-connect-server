# Multiple response types and form-post implementation plan

Status: proposed; this document does not implement protocol changes.

## Objective

Extend the existing authorization-code provider with a common authorization-response encoder, `fragment` and `form_post` delivery, and explicitly enabled implicit/hybrid flows. Preserve existing code + PKCE behavior, administrator-owned OAuth permissions, session tracking, logout, and revocation.

Deliver form-post for code flow first. Additional response types require issuance and lifecycle changes, not just alternate URL encoding. Keep browser access-token issuance disabled by default, with explicit operator enablement and client registration. Do not advertise unfinished or disabled capabilities.

## Standards and scope

- [Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html): unordered response-type combinations, default modes, and `none` semantics.
- [Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html): browser form submission to the registered callback.
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html): implicit/hybrid issuance, nonce, claims, and hash validation.

The target encoding matrix is:

| Response type | Returned credentials | Default mode | Allowed explicit modes |
| --- | --- | --- | --- |
| `code` | Code | query | query, fragment, form_post |
| `none` | None | query | query, fragment, form_post |
| `id_token` | ID token | fragment | fragment, form_post |
| `token` | Access token | fragment | fragment, form_post |
| `id_token token` | ID token and access token | fragment | fragment, form_post |
| `code id_token` | Code and ID token | fragment | fragment, form_post |
| `code token` | Code and access token | fragment | fragment, form_post |
| `code id_token token` | Code, ID token, and access token | fragment | fragment, form_post |

Use one mode for all parameters in a response, including errors and echoed state. `none` cannot be combined with another type. Query delivery cannot carry front-channel ID/access tokens. These rules come from the response-type specification above; allowing code with explicit fragment is an implementation policy supported by the shared encoder.

`token` alone is an OAuth flow, not an OIDC authentication flow. Implement it as a separate API-resource phase with its own consent and permissions; reject `scope=openid` for that profile. OIDC profiles continue requiring `openid` and target UserInfo. Do not silently reinterpret machine-client permissions as browser-grant permission.

Out of scope: JARM, request objects/PAR, new signing algorithms, encrypted tokens, pairwise subjects, and password-grant changes.

## Existing code and required changes

| Location | Current behavior | Planned change |
| --- | --- | --- |
| `internal/oidc/capability` | Only `code` is supported | Shared response-type parser, mode matrix, enabled-flow registry |
| `internal/oidc/authorize.go` | Exact `code` and query-only checks | Validate the registered combination and select a safe response mode |
| `internal/oidc/errors.go` | Errors always use query | Encode success and errors through the same delivery abstraction |
| `internal/oidc/interaction.go` | `mintCode` returns a redirect URL | Return typed response data; separate issuance from HTTP delivery |
| `internal/identity/oidc_records.go` | Transaction omits response type/mode | Persist canonical type, effective mode, and state presence |
| `internal/oidc/claims.go`, `token.go` | ID token primarily issued at code exchange | Add front-channel signing inputs and hash claims without altering default code flow |
| `internal/identity/token_state.go`, sessions and monitoring | Existing grant/lifecycle assumptions | Recognize implicit/hybrid artifacts and link them to OP/app sessions |
| `ui/src/pages/OIDCContinue.tsx` | Navigates to `redirectTo` | Navigate to a same-origin response-completion endpoint |
| `example-rp` | GET code callback | POST callback and fragment receiver, per-flow validation |

## 1. Capability and registration model

Create a single canonical response-type representation used by registration, runtime checks, discovery, and compatibility messages. Treat space-separated order as immaterial; reject duplicate tokens, unknown members, illegal combinations, and malformed separators. Define handling of empty values explicitly. Validate each complete registered combination rather than checking whether its individual words occur in separate entries.

Require `authorization_code` for code-bearing combinations, `implicit` for front-channel token/ID-token combinations, and both for hybrid. For `none`, require explicit response-type registration and a browser-capable client with a registered callback; it grants no token-issuance capability by itself. Preserve the existing default `response_types=[code]` and machine-client empty response types. Update dynamic registration to allow enabled browser profiles without allowing callers to set administrator-owned permissions.

Proposed configuration: an allowlist of enabled authorization response types, defaulting to `code`. Modes can expand to query/fragment/form_post once delivery is complete. Store these settings in the existing configuration system and expose only active capabilities in discovery. Metadata that requests a disabled flow remains clearly marked incompatible, as today; do not silently downgrade it.

## 2. Shared validation and response delivery

Introduce an authorization response value containing the validated callback, effective mode, and parameter map. No encoder accepts an arbitrary callback from consent submissions or completion requests.

Validation order: parse bounded request; resolve client; exactly validate callback; parse response type and mode; enforce registration and enabled-flow policy; validate scope, nonce, PKCE, prompt, and session requirements. Persist the result before login/consent. Recheck client revision, active account, session, and permissions at final issuance.

Define an error matrix before coding: invalid client/callback and ambiguous request parsing render a local error page. Once the callback and response type are trustworthy, errors use the selected valid mode. An invalid/prohibited mode produces `invalid_request` using the response type's safe default; unknown or ambiguous response types use a local error page rather than guessing a delivery channel. Never put credentials in an error response.

Preserve registered callback query parameters. Encode protocol parameters exactly once, preserve empty-but-present state, and reject collisions with reserved protocol fields in registered callback queries to avoid ambiguous RP parsing. Cover encoded spaces, plus signs, Unicode, ampersands, and malicious HTML in tests.

## 3. Form-post delivery and consent continuation

Serve a small HTML document whose form posts URL-encoded parameters to the validated callback. Add a normal submit button as a fallback when automatic submission is unavailable. Both success and authorization errors use this renderer. Per the form-post specification, responses must not be cached or reused.

Implementation controls: Go `html/template`, UTF-8, `Cache-Control: no-store`, `Pragma: no-cache`, `Referrer-Policy: no-referrer`, frame protection, and CSP with `default-src 'none'`, `base-uri 'none'`, an exact permitted form destination, and a nonce/hash-authorized submit script. Avoid third-party assets and do not interpolate protocol data into JavaScript. Test callback URLs that already contain query parameters and CSP-sensitive characters. No bearer credentials in page titles, logs, analytics, or same-origin completion URLs.

The existing JSON consent API cannot deliver a browser navigation by returning HTML to fetch. Change its successful/denied result to an opaque same-origin completion URL. After approval, navigate the browser there; the completion handler finalizes the response and renders a form or sends the appropriate redirect. The direct existing-consent path uses the same issuer/encoder without an unnecessary SPA round trip.

Completion records contain validated request/decision state rather than raw newly issued credentials. They are short lived, browser-bound, and consumed atomically with issuance. Revalidate session and client policy at completion; never mint on repeated fetches, browser back, or refresh. A lost response after consumption requires a fresh authorization request. No raw access tokens, codes, or ID tokens are persisted simply to replay a completion page.

## 4. Implicit/hybrid issuance and ID tokens

Refactor `mintCodeTx` into a small transactional issuance coordinator that generates exactly the requested artifacts. Prepare random values and signatures safely, commit all persistent records together, and release no credentials on signing or storage failure. Concurrent completion must have one winner.

Require S256 PKCE whenever a code is issued. Require nonce for OIDC implicit/hybrid requests and echo it in the ID token. Compute `c_hash` when a front-channel ID token accompanies a code and `at_hash` when it accompanies an access token, using the ID-token signing algorithm. Keep backend-issued and front-channel token claim rules distinct. For ID-token-only flow, include scope-authorized identity claims needed when no UserInfo token is returned. Implement these details against Core sections 3.2/3.3, with independently verified fixtures.

Create the RP/app session association at front-channel issuance, including ID-token-only flow, so `sid` and logout work before any code exchange. Hybrid code redemption must reuse that association and authenticated subject. Front-channel access tokens remain opaque, hashed at rest, and subject to normal expiry, introspection, UserInfo, logout, and consent revocation. Link hybrid front-channel tokens to the code so replay revocation reaches all associated artifacts.

Refresh tokens are issued only at the token endpoint after code redemption and existing offline-access approval. Reject offline access on code-free flows; no refresh tokens in fragments or forms. `none` issues no credentials or fake access-token activity rows; it may record the approved consent, while honoring prompt/login requirements.

Version persisted changes when needed. Legacy in-flight transactions default to code/query; new response modes survive restart. Verify cleanup, retention, and rollback with both old and new records.

## 5. OAuth token-only phase

Extend browser authorization with an explicitly enabled API-resource profile. Require an exact registered resource, allowed scopes, and user consent. Add a distinct admin-managed browser-implicit permission and resource policy; existing `client_credentials` approval does not qualify. Decide and document user resource entitlements consistently with the existing access model before enabling this phase.

Keep this profile separate from UserInfo and machine tokens in issuance, introspection, and activity views. No ID token or refresh token is returned. Discovery advertises standalone `token` only after these authorization and revocation paths pass tests.

## 6. Example RP and UI

Add response-type/mode selectors driven by discovery, a POST callback, and a minimal fragment-receiving page. The fragment page submits parsed values to its own backend and promptly clears the fragment; it does not load third-party scripts or expose tokens to arbitrary endpoints.

Bind each authorization attempt to state, issuer, expected type/mode, nonce, PKCE verifier, callback, and browser. Validate duplicate parameters, unexpected credentials, ID-token signature/claims and applicable hashes before establishing a session. For hybrid, compare front-channel and token-endpoint identity/session claims and consume state once.

Cross-site POST can omit an RP's SameSite=Lax cookie. Use a dedicated short-lived Secure, HttpOnly, SameSite=None correlation cookie for HTTPS form-post attempts, with explicit local-development handling. Do not relax the provider's management/session cookie globally. Test separate sites over HTTPS so localhost's same-site behavior cannot hide a broken callback binding.

Update client editor choices and compatibility messages. Activity views distinguish implicit, hybrid, and code artifacts and preserve OP/app session links. Inspector logging should redact credentials by default while retaining flow, mode, errors, and verification outcomes.

## Delivery order

1. Canonical parser, capability matrix, registration validation, migration design, and mode-aware error tests.
2. Shared response model and completion handler; code + query/fragment/form_post end to end.
3. `none`, including consent/prompt behavior and no-credential assertions.
4. OIDC implicit/hybrid issuance, claim hashes, session associations, token-state/revocation support.
5. OAuth token-only resource authorization and consent policy.
6. Example-RP coverage, UI/discovery documentation, full regression and Sonar checks; enable additional profiles only after their acceptance tests pass.

Each phase is independently reviewable. Keep code/query working throughout and do not claim full matrix support after only phase 2.

## Test and acceptance matrix

- Table-driven tests for every response-type/mode pair, order permutations, invalid combinations, duplicate fields, and registration/grant mismatches.
- Success, denial, prompt=none, expired interaction, changed client policy, switched user, invalid callback, missing nonce, and PKCE failures in each applicable mode.
- Known hash vectors plus independent JOSE verification; scope-limited ID-token-only claims; hybrid subject/sid consistency; no unrequested credentials.
- Atomic rollback, simultaneous completion, code replay, browser retry/back, restart/migration, and token expiry.
- Front/back-channel logout, local/app/provider logout distinctions, revocation, UserInfo and introspection for all new artifact types.
- Browser tests for real cross-site POST, SameSite correlation, automatic and manual submission, fragment callbacks, CSP, HTML escaping, state binding, and replay rejection.
- Regression for dynamic machine registration, OAuth permissions, refresh families, existing consent UI, and all existing authorization-code tests.
- Run server `go test ./...`, focused race tests, example-RP tests, UI tests/lint/build, browser-test typecheck and Playwright suite. Confirm build and Sonar results on the final PR commit. Record unavailable checks explicitly.

Completion means every enabled and advertised combination works through login, consent, callback validation, session activity, and revocation, with errors delivered safely and existing clients unchanged by default.
