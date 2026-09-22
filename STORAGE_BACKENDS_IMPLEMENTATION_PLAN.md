# Configurable JSON, PostgreSQL, and MongoDB storage backends

Status: proposed.

## Objective

Keep the JSON `FileStore` as the default for local and single-instance deployments. Add PostgreSQL and MongoDB implementations of `identity.Store`, selectable through validated configuration, without changing HTTP, OIDC, OAuth, logout, activity, or UI behavior.

Every backend must preserve the existing store contract: read snapshots are immutable to callers; writes are atomic and serializable; a callback error rolls back every change; client/account changes revoke the associated grants; and concurrent code/refresh/transaction consumption has exactly one winner.

## Current architecture and constraints

`internal/identity/store.go` is the domain boundary used by the identity, API, and OIDC packages. The JSON implementation loads a versioned `fileState`, takes a cross-process file lock, applies the whole callback to its maps, then atomically replaces `identity.json`. It also contains important domain side effects in methods such as `SaveClient`, `SaveUser`, `DeleteUserSessions`, `RevokeRefreshFamily`, and the logout/session cleanup routines.

The database adapters must not weaken those semantics by mapping each interface method to independent writes. They must move shared state-transition logic out of `fileState` or implement it through a common transactional domain layer, then persist that layer atomically.

## Configuration and backend selection

Extend `storage` with an explicit backend selector. The default remains `json`.

```yaml
storage:
  backend: json # json, postgres, or mongodb
  dataDir: data # required by json and signing-key storage

  postgres:
    dsn: ${APP_STORAGE_POSTGRES_DSN}
    maxOpenConns: 20
    maxIdleConns: 5
    connMaxLifetime: 30m
    connectTimeout: 5s
    statementTimeout: 10s
    sslMode: verify-full

  mongodb:
    uri: ${APP_STORAGE_MONGODB_URI}
    database: opened_connect_server
    connectTimeout: 5s
    serverSelectionTimeout: 5s
    transactionTimeout: 10s
```

Configuration rules:

- `json` accepts `dataDir` and rejects database-only settings when they are explicitly supplied.
- `postgres` requires a PostgreSQL URI/DSN, TLS outside development/test, sane pool and timeout limits, and no embedded password in logs or validation errors.
- `mongodb` requires a MongoDB URI, database name, TLS outside development/test, and deployment support for multi-document transactions. A standalone server is rejected because it cannot satisfy the store write contract.
- Environment variables remain the preferred place for DSNs and credentials. Configuration output, diagnostics, activity logs, and errors redact user-info, passwords, tokens, query credentials, and private certificate paths.
- `storage.dataDir` remains available for JSON data and OIDC signing keys. Add a separate explicit signing-key location only if deployments require database-only application storage; do not silently move private signing keys into either database.
- Startup selects one backend through a `identity.OpenStore(ctx, config.Storage)` factory, pings it with bounded timeouts, verifies schema/index version, and fails closed before serving traffic.

Update `init` with `--storage-backend`, `--postgres-dsn`, `--mongodb-uri`, and `--mongodb-database` only after the configuration factory exists. Secret-bearing flags should be avoided or clearly documented as development-only; prefer environment variables and generated config references.

## Domain-layer refactor

1. Define an internal persistence-neutral `stateTx` implementation of `ReadTx`/`Tx` and move lifecycle invalidation, clone behavior, timestamp normalization, pruning, and capacity checks from `fileState` into it.
2. Give that layer a narrow record gateway for loading, saving, deleting, and listing typed aggregates. It must not expose backend query objects to identity/OIDC callers.
3. Retain the existing `Store` callback API. PostgreSQL and MongoDB invoke the callback once per committed transaction; retries happen around a fresh callback transaction only when the callback is proven safe to repeat. Where retrying a callback could regenerate random credentials, return a typed contention error and let the service retry before minting values.
4. Keep all secure values hashed as today. Client-secret encryption currently depends on local key material; introduce a `SecretProtector` interface with the existing file-backed protector as default and an explicit key-management design before a database backend stores encrypted client secrets.
5. Add backend capability/health reporting that names only the selected backend, schema version, connection state, and safe pool metrics.

## PostgreSQL design

Use `pgx` with `SERIALIZABLE` transactions for writes, read-only repeatable-read transactions for consistent activity views, context-bound statement timeouts, and a small bounded retry policy for SQLSTATE `40001`/deadlock errors.

Create migrations managed by a checked-in migration tool and a `schema_migrations` table. Use UUID/text IDs compatible with existing records and `timestamptz` for all times. Store protocol metadata/claims that are not queried as `jsonb`; use typed columns for security joins, uniqueness, expiry, and activity filtering.

Core tables include:

- `users`, `sessions`, `app_sessions`, and session/logout audit fields;
- `clients`, encrypted client secret material, client metadata JSON, initial tokens, and registration access tokens;
- `authz_transactions`, `authorization_codes`, `access_tokens`, `refresh_families`, `refresh_tokens`, consents, OAuth policies, and user OAuth access;
- logout interactions, operations, and delivery records.

Required constraints and indexes include case-insensitive unique user email, unique client ID, unique credential hashes, consent `(user_id, client_id)`, active/expiry lookup indexes, transaction/code/refresh replay indexes, app session client/OP-session indexes, activity sorting indexes, and foreign keys or transactional deletion rules that mirror current invalidation behavior.

Use row locking or conditional updates for single-use codes, refresh-token rotation, transaction completion, session capacity, and logout leasing. Test every state transition under serialization failure and concurrent writers.

## MongoDB design

Use the official MongoDB Go driver and require a replica set or sharded cluster with transactions enabled. Configure majority write concern and snapshot read concern for write transactions; bound transaction lifetime and retry only MongoDB-labeled transient transaction errors through the same callback-safety policy as PostgreSQL.

Use focused collections rather than one unbounded document: `users`, `sessions`, `clients`, `oauth_policies`, `oauth_access`, `authz_transactions`, `authorization_codes`, `access_tokens`, `refresh_families`, `refresh_tokens`, `consents`, `app_sessions`, `logout_interactions`, `logout_operations`, `logout_deliveries`, `initial_access_tokens`, and `registration_access_tokens`.

Create unique indexes for identity and hashed credentials; compound indexes for expiry/pruning, client/user revocation, app/OP sessions, activity filters, and worker leasing. TTL indexes may reduce stale data but cannot replace transactional `Prune*` behavior, because security decisions must treat an expired record as inactive before background deletion occurs. Use explicit conditional filters for consumed/revoked state and verify matched-count invariants.

Do not support standalone MongoDB, best-effort multi-document writes, or distributed transactions across clusters. They cannot uphold authorization-code, refresh-token, logout, and client-change atomicity.

## Migration and operational workflow

1. Add `opened-connect-server storage status` to report selected backend and safe schema/migration status.
2. Add an offline `storage export --backend json|postgres|mongodb` command that emits a versioned, encrypted-at-rest or operator-protected snapshot without raw passwords, tokens, client secrets, or signing keys in terminal output.
3. Add `storage import` with preflight validation, target-empty checks, record counts/checksums, explicit `--replace-empty-target`, and a resumable migration journal. Do not perform dual writes or transparent live migration in the first release.
4. Stop writers for the cutover, create a JSON backup, export, import into a fresh target, verify counts and representative state, change `storage.backend`, run a read-only health check, and start one instance. Roll back by restoring the JSON configuration and backup before accepting new writes.
5. Document PostgreSQL backup/restore and MongoDB replica-set backup requirements, connection pooling, TLS/certificate rotation, schema upgrades, monitoring, and disaster recovery.

## Delivery phases

1. **Store contract suite.** Extract a reusable backend compliance suite from the current JSON store tests: snapshots, rollback, concurrency, client/user invalidation, codes, refresh families, consent, registration, sessions, logout, pruning, and activity.
2. **Configuration and factory.** Add backend config validation, redaction, factory selection, startup health checks, JSON default regression coverage, and operator documentation. No database backend is selectable yet.
3. **Shared transaction layer.** Move lifecycle behavior out of `fileState`, maintain JSON behavior byte/semantics compatible where practical, and run the contract suite against JSON.
4. **PostgreSQL.** Add migrations, adapter, pool lifecycle, retries/locking, integration tests in disposable PostgreSQL, and migration/export/import tooling. Make it selectable after the compliance suite passes.
5. **MongoDB.** Add transaction-capable deployment checks, collections/indexes, adapter, integration tests in a replica set, and import/export support. Make it selectable after the same compliance suite passes.
6. **Operations rollout.** Add CI service containers, load/concurrency tests, metrics, alerting guidance, runbooks, and staged production rollout.

## Test and acceptance matrix

- Run every existing identity, API, OIDC, OAuth, session, logout, registration, activity, and security regression test against JSON, PostgreSQL, and MongoDB.
- Test callback rollback, cancellation, timeout, process restart, driver disconnect, serialization/deadlock retry, Mongo transient transaction retry, and transaction-size/time limits.
- Race authorization-code redemption, refresh rotation, consent/client mutations, last-admin operations, session limits, logout delivery leasing, and concurrent app instances against each backend.
- Verify all unique constraints and case-insensitive email behavior; test expiry before physical pruning and TTL deletion.
- Test JSON-to-database and database-to-JSON export/import with old file versions, encrypted client secrets, corrupt snapshots, count mismatches, interrupted import, and rollback.
- Assert logs, metrics, errors, diagnostics, CLI help, and crash reports never disclose DSNs, database credentials, raw tokens, password hashes, client secrets, or private signing material.
- Benchmark realistic login, authorize, token, UserInfo, refresh, logout, registration, and activity workloads. Publish tested limits and recommend JSON only for single-instance low-volume deployments.

Completion means `storage.backend: json`, `postgres`, and `mongodb` produce identical externally observable security and protocol behavior, with JSON still selected when `storage.backend` is omitted.
