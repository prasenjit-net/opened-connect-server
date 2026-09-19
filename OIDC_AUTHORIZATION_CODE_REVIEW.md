# Authorization-code flow review and corrections

## Correction status — 2026-09-16

The 11 numbered implementation defects below are corrected, along with the listed request-size, traffic-limit, malformed-query, CORS, protocol-routing, and browser-binding hardening items. The original review is preserved below as historical evidence, not a description of current behavior.

| Finding | Correction |
| --- | --- |
| 1. Replay revocation | Correctly bound replays commit revocation before returning `invalid_grant`; consumed-code tombstones survive until issued access tokens expire. |
| 2. Concurrent consent | Binding, current session/user/client, consent, code creation, and transaction consumption share one atomic write. |
| 3. Reauthentication | Persisted authentication boundary checked against the live server session; zero default age retained; age comparison avoids duration overflow. |
| 4. Issuance atomicity | Random generation, signing, code consumption, and access-token persistence share one transaction; failed signing/commit leaves the code usable. |
| 5. Security lifecycle | Account security changes and client updates/deletion invalidate protocol state atomically; client timestamps advance monotonically at nanosecond resolution; UserInfo rechecks client eligibility. |
| 6. Client signing policy | Required signed UserInfo and request-object signing are explicitly incompatible until implemented. |
| 7. Unsupported parameters | Request/request-URI modes and unsupported response modes receive explicit errors. |
| 8. Token parsing | Bounded, strictly decoded, single-source forms; duplicate parameters and authentication conflicts rejected; Basic credentials OAuth form-decoded. |
| 9. Throttling | Failed authentication is client/peer scoped; valid authentication is excluded; separate bounded endpoint traffic limits. |
| 10. Issuer | One normalized issuer used for discovery and tokens; forbidden URL components rejected. |
| 11. Certificate | Signing checks current certificate validity and proposed JWT validity boundaries. |

Additional tests cover retry after failed commits/signing, expired unused codes, replay after original code expiry, incorrect-proof replay, concurrent consent, security mutation invalidation, fresh/stale login, default/large `max_age`, parsing, authentication source isolation, issuer/certificate boundaries, explicit CORS origins, traffic limits, multi-tab binding reuse, protocol paths ahead of both SPA and dev proxy, and email-change sign-out.

Optional extensions from the broader plan—refresh/offline access, JWT client authentication, pairwise subjects, request objects, individual claims, encryption, revocation/introspection/logout endpoints, own-grant management, custom-claim policy, and native loopback exceptions—remain separate future capabilities. They are not advertised as implemented. This correction closes the supported authorization-code path's findings; it does not claim full plan completion or conformance certification. Independent relying-party and OpenID conformance testing remain outstanding.

Operational details, including `oidc.allowedOrigins` and the request limits, are documented in README.md. Existing client consent revisions are conservatively invalidated by the stronger revision comparison. Already-delivered self-contained ID tokens remain verifiable until expiration.

### Verification after corrections

- `GOCACHE=/tmp/opened-connect-go-cache go test ./...` passed.
- Race-enabled tests passed for `internal/oidc/...`, `internal/identity`, `internal/api`, `internal/server`, and `internal/config`; OIDC/config race tests were rerun after the final changes.
- `go vet ./...` and `git diff --check` passed.
- UI: all 61 tests passed; TypeScript/Vite production build passed; ESLint passed with six existing Fast Refresh warnings in unchanged context modules. Existing OIDC UI tests still print React `act` warnings.
- Regression tests are retained in `internal/oidc/security_regression_test.go`, alongside configuration, server-routing, API, and profile UI checks.

## Original review (before corrections)

Reviewed: 2026-09-16. Scope: current Go provider, identity transactions, API wiring, continuation UI, discovery, and existing tests. No production code was modified.

**Conclusion: the basic authorization-code flow exists, but it is not complete or ready for a security-sensitive production deployment.** Several safeguards in the supported code-flow path are ineffective. Optional protocol capabilities should be tracked separately from those defects.

## Findings, highest priority first

### 1. P1 — Code-replay revocation is rolled back

Location: [internal/oidc/token.go](internal/oidc/token.go), consumed-code branch around lines 83–88; [internal/identity/file_store.go](internal/identity/file_store.go), callback error handling around line 123.

The replay branch marks associated access tokens revoked and then returns `errInvalidGrant` from the storage callback. The file store rolls back callbacks returning errors, so the revocation never persists. A replay receives HTTP 400 while the original bearer token continues to receive HTTP 200 from UserInfo. This was reproduced with the real file store.

Commit revocation successfully, then return the OAuth error outside the transaction. Check client/code ownership and proof before applying replay consequences. Keep consumed-code evidence for the relevant token lifetime; current pruning removes it at code expiry even if access tokens remain live. The OAuth specification recommends revoking already-issued tokens when code reuse is detected. [RFC 6749 §4.1.2](https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2)

### 2. P1 — A consent transaction can issue multiple authorization codes

Location: [internal/oidc/interaction.go](internal/oidc/interaction.go), `Status`, `Decide`, and `consumeTransaction`, especially lines 220–245.

Transaction loading, consent persistence, code creation, and transaction consumption are separate transactions. Two requests can both read the same unconsumed transaction and each mint a different code. A controlled concurrent test reproduced two distinct codes from one consent transaction. Automatic completion through `Status` has the same structure. Consumption errors are discarded.

Use one transaction to recheck browser/user binding, expiry, consumption, consent, and client eligibility; then record consent, consume the authorization transaction, and create exactly one code. Do not mint a code first and attempt consumption afterward.

### 3. P1 — Forced reauthentication is enforced only by clearing a browser cookie

Location: [internal/oidc/authorize.go](internal/oidc/authorize.go), login redirect branch; [internal/oidc/interaction.go](internal/oidc/interaction.go), `bindUser` around line 93.

`prompt=login` and stale-session handling clear the response cookie, but the old server session remains valid. Continuation accepts an existing principal without checking that authentication occurred after this transaction's reauthentication requirement. A targeted test completed `prompt=login` using the preexisting session, without another password check. The same missing continuation check affects `max_age`.

Persist the required reauthentication boundary and enforce it against authenticated session evidence during continuation and issuance. Also preserve the distinction between absent `default_max_age` and zero: the current `> 0` condition ignores a client's valid zero default. Bound `max_age` before converting seconds to `time.Duration` to prevent overflow. [OIDC authentication request rules](https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest)

### 4. P1 — Token issuance is not atomic with code consumption

Location: [internal/oidc/token.go](internal/oidc/token.go), lines 78–138.

The first write consumes the code. A second write stores the access token. ID-token signing happens afterward. A storage/signing failure burns the code without returning a complete response. Account/client changes or replay processing can occur between writes; issuance does not recheck eligibility in the access-token write. The existing concurrency test proves at most one successful exchange, but not atomic issuance or failure recovery.

Prepare fallible signing/random generation safely, then validate and persist the complete issuance with code consumption under one transaction. No credential response should escape before commit. Test injected storage/signing failures and concurrent security changes.

### 5. P1 — Client deletion and account security changes do not invalidate protocol grants

Location: [internal/oidc/userinfo.go](internal/oidc/userinfo.go), lines 43–50; [internal/identity/file_store.go](internal/identity/file_store.go), `DeleteClient` and `DeleteUserSessions`; [internal/identity/service.go](internal/identity/service.go), password/security-change paths.

UserInfo checks user activity but does not check whether the client still exists or remains eligible. Deleting a client leaves its access tokens usable: reproduced HTTP 200 after deletion. Password and role/email changes currently delete browser sessions without connecting to protocol revocation helpers. Existing authorization codes also lack an account security revision.

Wire security mutations to revoke outstanding codes, transactions, tokens, and affected consent/grants atomically. Verify current client eligibility in UserInfo. Replace second-resolution client timestamps with a reliable revision: two metadata/secret changes in one second are currently indistinguishable to outstanding code/consent checks.

### 6. P1 — Required client signing settings can be silently ignored

Location: [internal/identity/protocol_audit.go](internal/identity/protocol_audit.go), `auditMetadata`; [internal/oidc/userinfo.go](internal/oidc/userinfo.go), response serialization.

Compatibility auditing does not consider `userinfo_signed_response_alg` or `request_object_signing_alg`. A client requesting signed UserInfo is marked compatible, while the handler always returns unsigned JSON. The compatibility failure was reproduced. A registered request-object signing requirement is likewise not enforced.

Until those capabilities are implemented, reject incompatible client configurations at runtime and report the exact incompatibility in management. Do not silently substitute weaker response/request behavior. [OIDC UserInfo response rules](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse)

### 7. P2 — Unsupported authorization parameters are silently ignored

Location: [internal/oidc/authorize.go](internal/oidc/authorize.go).

Adding an unsupported `request` JWT to an otherwise valid request still proceeds to continuation; reproduced. Discovery advertises request-object support as false, but the authorization endpoint must return `request_not_supported` when it is supplied. The corresponding handling is also absent for `request_uri`. An unsupported `response_mode` is ignored and a query response is generated regardless of the requested mode.

Validate supported protocol parameters explicitly and use the specified errors for unsupported request-object modes. Optional support may be absent; silently continuing as if those parameters were absent is a separate defect. [OIDC request objects](https://openid.net/specs/openid-connect-core-1_0.html#RequestObject)

### 8. P2 — Duplicate token parameters are accepted

Location: [internal/oidc/token.go](internal/oidc/token.go), form parsing; [internal/oidc/clientauth.go](internal/oidc/clientauth.go), credential extraction.

The token endpoint takes the first value returned by `form.Get`. A request containing a valid `code` followed by a second conflicting `code` received HTTP 200 in a targeted reproduction. Similar ambiguity applies to grant, redirect, verifier, and client credentials. Basic credentials are not OAuth form-decoded, and a conflicting form `client_id` alongside Basic is not checked.

Reject duplicated critical parameters and conflicting authentication sources. Parse malformed authorization headers explicitly. Use OAuth-compatible Basic credential decoding, with tests for reserved characters and percent encoding. [RFC 6749 token errors](https://www.rfc-editor.org/rfc/rfc6749.html#section-5.2)

### 9. P2 — Authentication rate limiting locks out normal client traffic

Location: [internal/oidc/clientauth.go](internal/oidc/clientauth.go), `authenticateClient` and `clientAuthLimiter.allow`.

Every client authentication attempt, including successful ones, consumes the same 30-attempt/15-minute allowance. The 31st valid authentication fails; reproduced without any bad credentials. Any caller who knows a public client ID can exhaust that client's allowance.

Separate bounded traffic limits from failed-credential throttling. Successful client activity must not accumulate into a client-wide authentication lockout. Include source-aware limits and avoid allowing one attacker to exhaust an entire relying party's capacity.

### 10. P2 — Discovery and ID-token issuer can differ

Location: [internal/config/config.go](internal/config/config.go), issuer validation; [internal/oidc/discovery.go](internal/oidc/discovery.go), `discoveryDocument`; [internal/oidc/claims.go](internal/oidc/claims.go), `signIDToken`.

Configuration permits an issuer ending in `/`. Discovery trims that slash; ID tokens use the original configured value. Strict relying parties then reject issuer validation. Issuer validation also does not reject userinfo, query, or fragment components.

Validate and resolve one issuer string at configuration time, then use it unchanged everywhere. Add tests for trailing slashes and forbidden URL components. [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata)

### 11. P2 — Running processes do not enforce signing-certificate lifetime

Location: [internal/oidc/keystore.go](internal/oidc/keystore.go), `Sign` around line 294; [internal/oidc/claims.go](internal/oidc/claims.go).

Key expiry is checked on load, but signing checks only that an active key exists. A continuously running process can issue JWTs after certificate expiry or with JWT expiry beyond certificate validity, contrary to the plan's lifecycle policy.

Check certificate usability and the proposed JWT validity interval during signing. Test with an injected clock across expiry and rotation boundaries.

## Implemented surface and limitations

| Area | Current status |
| --- | --- |
| Root discovery, JWKS, `/authorize`, `/token`, `/userinfo` | Present |
| Registered client lookup, exact redirect matching, code response type | Present |
| PKCE S256 challenge/verifier syntax and comparison | Present |
| Form login, cookie/session authentication, browser-binding cookie | Present; reauthentication and concurrent continuation need fixes |
| Consent approval/denial and scope narrowing | Present; transaction consumption is not atomic |
| State and nonce propagation | Present on the basic path |
| Code expiry and client/redirect/PKCE binding | Implemented; security revisions and replay consequences incomplete |
| Public clients, Basic/post secret authentication | Implemented; parsing/throttling defects noted above |
| RS256 ID tokens and scoped JSON UserInfo | Present; registered signing requirements and lifecycle checks incomplete |
| User/admin management authorization | Remains separate from protocol bearer-token use |
| Refresh tokens / offline access | Not implemented and not advertised |
| JWT client authentication, pairwise subjects, request objects, individual claims requests, encryption | Not implemented; these are optional/configuration-dependent, not all mandatory for a minimal code-flow profile |
| Revocation endpoint, own-grant management, introspection, RP logout | Not implemented; broader plan/extensions remain outstanding |
| Per-client scope/custom-claim policy | Not implemented; custom attributes are currently omitted from protocol responses |
| Native loopback port exception | Not implemented; matching is strictly literal |
| Multi-tab authorization | A single binding cookie is overwritten by a new authorization request, invalidating an earlier in-flight flow |

Additional hardening gaps: dedicated authorization/body size and rate limits, explicit rejection of malformed query encoding, narrow configured browser-client origins rather than reflecting any Origin, and protocol method/error handling ahead of SPA fallbacks. These require further tests; reflecting noncredentialed CORS by itself is not a cookie-authentication bypass.

## Verification and test coverage

Eight temporary targeted tests reproduced findings 1, 2, 3, 5, 6, 7, 8, and 9 using existing fixtures and the real file-backed store. Their failures were expected assertions of the missing behavior. The concurrency probe synchronizes two initial transaction reads to expose the race deterministically.

Temporary probes were removed from the application tree after review and retained at `/tmp/oidc-authorization-review-probes_test.go`. No fixes were applied. The checked-in Go tests for `internal/oidc/...`, `internal/api`, and `internal/identity` passed; all 60 UI tests passed with React act warnings. These were run separately from the probes. Passing existing tests does not cover these defects or establish OIDC conformance. In particular, the current reuse test checks the second exchange's error but never checks whether the first access token was revoked. The test named `TestTokenRejectsExpiredOrReusedCode` exercises reuse without advancing the clock to test expiry.

An independent relying-party integration and the applicable OpenID conformance suite are still needed after the defects are corrected. The current end-to-end test verifies signatures with the provider's own test fixtures/library; it is useful but not conformance certification.

## Recommended correction order

1. Make consent/code/token mutations atomic, with durable replay revocation and reliable revisions.
2. Enforce reauthentication server-side and wire account/client lifecycle revocation.
3. Fail closed for unsupported mandatory client settings; correct protocol parameter validation and authentication throttling.
4. Fix issuer/key-lifetime consistency and add the missing negative, concurrency, and failure-injection tests.
5. Complete refresh/grant lifecycle and other explicitly selected plan milestones; advertise only passing capabilities.
