-- Normalized schema for the PostgreSQL identity store. One table per
-- fileState map. See internal/identity/store.go for the domain contract
-- these tables must uphold (cascades, revision-pinning, replay retention).

CREATE TABLE users (
    id             text PRIMARY KEY,
    email          text NOT NULL,
    email_verified boolean NOT NULL DEFAULT false,
    name           text NOT NULL DEFAULT '',
    role           text NOT NULL,
    active         boolean NOT NULL DEFAULT true,
    password_hash  text NOT NULL DEFAULT '',
    profile        jsonb NOT NULL DEFAULT '{}'::jsonb, -- Claims + Address + custom attributes
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL
);
-- Case-insensitive uniqueness matches strings.EqualFold usage in SaveUser/
-- UserByEmail; email is also stored pre-lowercased by the service layer.
CREATE UNIQUE INDEX users_email_lower_idx ON users (lower(email));
CREATE INDEX users_role_active_idx ON users (role, active);

-- Sessions are keyed by hash (the credential lookup) but referenced
-- everywhere else by id, which survives credential rotation.
CREATE TABLE sessions (
    hash         text PRIMARY KEY,
    id           text NOT NULL,
    user_id      text NOT NULL,
    device       text NOT NULL DEFAULT '',
    csrf         text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    auth_time    timestamptz,
    expires_at   timestamptz NOT NULL,
    ended_at     timestamptz,
    end_reason   text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX sessions_id_idx ON sessions (id);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
CREATE INDEX sessions_expiry_idx ON sessions (expires_at) WHERE ended_at IS NULL;
CREATE INDEX sessions_ended_at_idx ON sessions (ended_at) WHERE ended_at IS NOT NULL;

CREATE TABLE app_sessions (
    id            text PRIMARY KEY,
    op_session_id text NOT NULL,
    client_id     text NOT NULL,
    user_id       text NOT NULL,
    subject       text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    ended_at      timestamptz,
    end_reason    text NOT NULL DEFAULT ''
);
-- Implicit invariant token.go relies on: at most one *active* app session
-- per (op_session_id, client_id) pair.
CREATE UNIQUE INDEX app_sessions_active_pair_idx ON app_sessions (op_session_id, client_id) WHERE ended_at IS NULL;
CREATE INDEX app_sessions_op_session_idx ON app_sessions (op_session_id);
CREATE INDEX app_sessions_client_idx ON app_sessions (client_id);
CREATE INDEX app_sessions_user_idx ON app_sessions (user_id);
CREATE INDEX app_sessions_ended_at_idx ON app_sessions (ended_at) WHERE ended_at IS NOT NULL;

CREATE TABLE clients (
    id              text PRIMARY KEY,
    origin          text NOT NULL DEFAULT '',
    initial_token_id text NOT NULL DEFAULT '',
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    secret          text NOT NULL DEFAULT '', -- ciphertext; sidecar key, unchanged from today
    issued_at       bigint NOT NULL DEFAULT 0, -- unix seconds
    updated_at      timestamptz NOT NULL,
    -- Nanosecond policy revision. Compared with exact equality across
    -- RefreshFamily.ClientRevision, Consent.PolicyRevision, and
    -- AuthzTransaction/AuthorizationCode.ClientUpdatedAt. timestamptz
    -- truncates to microseconds, so this must be a separate bigint.
    updated_at_ns   bigint NOT NULL
);

CREATE TABLE oauth_policies (
    client_id                text PRIMARY KEY,
    grants                   text[] NOT NULL DEFAULT '{}',
    resources                jsonb NOT NULL DEFAULT '{}'::jsonb, -- audience -> {allowed, default}
    default_resource         text NOT NULL DEFAULT '',
    introspection_enabled    boolean NOT NULL DEFAULT false,
    introspection_audiences  text[] NOT NULL DEFAULT '{}',
    refresh_inspection       boolean NOT NULL DEFAULT false,
    refresh_enabled          boolean NOT NULL DEFAULT false,
    password_enabled         boolean NOT NULL DEFAULT false
);

CREATE TABLE oauth_access (
    user_id  text NOT NULL,
    audience text NOT NULL,
    scopes   text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (user_id, audience)
);

CREATE TABLE refresh_families (
    id               text PRIMARY KEY,
    app_session_id   text NOT NULL DEFAULT '',
    op_session_id    text NOT NULL DEFAULT '',
    client_id        text NOT NULL,
    user_id          text NOT NULL,
    code_hash        text NOT NULL DEFAULT '',
    audience         text NOT NULL DEFAULT '',
    scopes           text[] NOT NULL DEFAULT '{}',
    auth_time        bigint NOT NULL DEFAULT 0, -- unix seconds
    client_revision  bigint NOT NULL,           -- pinned ClientRecord.updated_at_ns
    created_at       timestamptz NOT NULL,
    absolute_expiry  timestamptz NOT NULL,
    idle_expiry      timestamptz NOT NULL,
    retain_until     timestamptz NOT NULL,
    revoked          boolean NOT NULL DEFAULT false
);
CREATE INDEX refresh_families_client_idx ON refresh_families (client_id);
CREATE INDEX refresh_families_user_idx ON refresh_families (user_id);
CREATE INDEX refresh_families_code_hash_idx ON refresh_families (code_hash);
CREATE INDEX refresh_families_app_session_idx ON refresh_families (app_session_id);
CREATE INDEX refresh_families_op_session_idx ON refresh_families (op_session_id);
-- Pruning keys off retain_until, not revoked (revoked families are kept as
-- replay-detection evidence until retain_until).
CREATE INDEX refresh_families_retain_until_idx ON refresh_families (retain_until);

CREATE TABLE refresh_tokens (
    hash      text PRIMARY KEY,
    family_id text NOT NULL REFERENCES refresh_families (id) ON DELETE CASCADE,
    scopes    text[] NOT NULL DEFAULT '{}',
    issued_at timestamptz NOT NULL,
    consumed  boolean NOT NULL DEFAULT false
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);

CREATE TABLE initial_access_tokens (
    hash       text PRIMARY KEY,
    id         text NOT NULL,
    label      text NOT NULL DEFAULT '',
    issued_by  text NOT NULL DEFAULT '',
    issued_at  timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    max_uses   integer NOT NULL DEFAULT 1,
    uses       integer NOT NULL DEFAULT 0,
    revoked    boolean NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX initial_access_tokens_id_idx ON initial_access_tokens (id);

CREATE TABLE registration_access_tokens (
    client_id text PRIMARY KEY,
    hash      text NOT NULL,
    issued_at timestamptz NOT NULL
);
CREATE UNIQUE INDEX registration_access_tokens_hash_idx ON registration_access_tokens (hash);

CREATE TABLE authz_transactions (
    id                    text PRIMARY KEY,
    client_id             text NOT NULL,
    redirect_uri          text NOT NULL DEFAULT '',
    scopes                text[] NOT NULL DEFAULT '{}',
    state                 text NOT NULL DEFAULT '',
    response_mode         text NOT NULL DEFAULT '',
    nonce                 text NOT NULL DEFAULT '',
    code_challenge        text NOT NULL DEFAULT '',
    code_challenge_method text NOT NULL DEFAULT '',
    prompt                text[] NOT NULL DEFAULT '{}',
    max_age               bigint,
    login_hint            text NOT NULL DEFAULT '',
    browser_binding_hash  text NOT NULL DEFAULT '',
    op_session_id         text NOT NULL DEFAULT '',
    app_session_id        text NOT NULL DEFAULT '',
    user_id               text NOT NULL DEFAULT '',
    auth_time             bigint NOT NULL DEFAULT 0,
    client_updated_at_ns  bigint NOT NULL,
    reauthenticate_after  timestamptz,
    consent_granted       boolean NOT NULL DEFAULT false,
    revoked               boolean NOT NULL DEFAULT false,
    consumed              boolean NOT NULL DEFAULT false,
    expires_at            timestamptz NOT NULL,
    created_at            timestamptz NOT NULL
);
CREATE INDEX authz_transactions_client_idx ON authz_transactions (client_id);
CREATE INDEX authz_transactions_user_idx ON authz_transactions (user_id);
CREATE INDEX authz_transactions_op_session_idx ON authz_transactions (op_session_id);
CREATE INDEX authz_transactions_expires_at_idx ON authz_transactions (expires_at);

CREATE TABLE authorization_codes (
    hash                  text PRIMARY KEY,
    transaction_id        text NOT NULL DEFAULT '',
    client_id             text NOT NULL,
    user_id               text NOT NULL,
    redirect_uri          text NOT NULL DEFAULT '',
    scopes                text[] NOT NULL DEFAULT '{}',
    nonce                 text NOT NULL DEFAULT '',
    auth_time             bigint NOT NULL DEFAULT 0,
    code_challenge        text NOT NULL DEFAULT '',
    code_challenge_method text NOT NULL DEFAULT '',
    client_updated_at_ns  bigint NOT NULL,
    op_session_id         text NOT NULL DEFAULT '',
    app_session_id        text NOT NULL DEFAULT '',
    revoked               boolean NOT NULL DEFAULT false,
    consumed              boolean NOT NULL DEFAULT false,
    created_at            timestamptz,
    expires_at            timestamptz NOT NULL,
    -- Zero until consumed; then set to now+AccessTokenTTL (or the refresh
    -- family's retain_until for offline_access). Pruning requires BOTH
    -- expires_at and retain_until to have passed - this is the replay
    -- evidence retention window.
    retain_until          timestamptz
);
CREATE INDEX authorization_codes_client_idx ON authorization_codes (client_id);
CREATE INDEX authorization_codes_user_idx ON authorization_codes (user_id);
CREATE INDEX authorization_codes_transaction_idx ON authorization_codes (transaction_id);
CREATE INDEX authorization_codes_op_session_idx ON authorization_codes (op_session_id);
CREATE INDEX authorization_codes_app_session_client_idx ON authorization_codes (op_session_id, client_id);
CREATE INDEX authorization_codes_prune_idx ON authorization_codes (expires_at, retain_until);

CREATE TABLE access_tokens (
    hash                text PRIMARY KEY,
    client_id           text NOT NULL,
    user_id             text NOT NULL DEFAULT '',
    audience            text NOT NULL DEFAULT '',
    scopes              text[] NOT NULL DEFAULT '{}',
    grant_type          text NOT NULL DEFAULT '',
    subject_kind        text NOT NULL DEFAULT '',
    family_id           text NOT NULL DEFAULT '',
    original_grant      text NOT NULL DEFAULT '',
    code_hash           text NOT NULL DEFAULT '',
    op_session_id       text NOT NULL DEFAULT '',
    app_session_id      text NOT NULL DEFAULT '',
    id_token_expires_at timestamptz,
    issued_at           timestamptz NOT NULL,
    expires_at          timestamptz NOT NULL,
    revoked             boolean NOT NULL DEFAULT false
);
CREATE INDEX access_tokens_client_idx ON access_tokens (client_id);
CREATE INDEX access_tokens_user_idx ON access_tokens (user_id);
CREATE INDEX access_tokens_family_idx ON access_tokens (family_id);
CREATE INDEX access_tokens_code_hash_idx ON access_tokens (code_hash);
CREATE INDEX access_tokens_app_session_idx ON access_tokens (app_session_id);
-- Pruned unconditionally on expiry regardless of revoked state.
CREATE INDEX access_tokens_expires_at_idx ON access_tokens (expires_at);

CREATE TABLE consents (
    user_id         text NOT NULL,
    client_id       text NOT NULL,
    scopes          text[] NOT NULL DEFAULT '{}',
    policy_revision bigint NOT NULL,
    granted_at      timestamptz NOT NULL,
    revoked         boolean NOT NULL DEFAULT false,
    PRIMARY KEY (user_id, client_id)
);
CREATE INDEX consents_client_idx ON consents (client_id);

CREATE TABLE logout_operations (
    id         text PRIMARY KEY,
    actor      text NOT NULL DEFAULT '',
    kind       text NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX logout_operations_created_at_idx ON logout_operations (created_at);

-- Targets is polymorphic (Session.ID or AppSession.ID depending on Kind);
-- no FK is possible.
CREATE TABLE logout_operation_targets (
    operation_id text NOT NULL REFERENCES logout_operations (id) ON DELETE CASCADE,
    target_id    text NOT NULL
);
CREATE INDEX logout_operation_targets_operation_idx ON logout_operation_targets (operation_id);
CREATE INDEX logout_operation_targets_target_idx ON logout_operation_targets (target_id);

CREATE TABLE logout_deliveries (
    -- Deterministic derived id ("op-"+sessionID, appSessionID+"-backchannel",
    -- etc): re-ending the same session/app-session is idempotent by
    -- construction via ON CONFLICT (id) DO UPDATE.
    id             text PRIMARY KEY,
    op_session_id  text NOT NULL DEFAULT '',
    app_session_id text NOT NULL DEFAULT '',
    client_id      text NOT NULL DEFAULT '',
    user_id        text NOT NULL DEFAULT '',
    subject        text NOT NULL DEFAULT '',
    actor          text NOT NULL DEFAULT '',
    reason         text NOT NULL DEFAULT '',
    channel        text NOT NULL,
    status         text NOT NULL,
    -- Deliberate snapshot, never joined to clients.endpoint - a deleted
    -- client still has a trusted destination for pending deliveries.
    endpoint       text NOT NULL DEFAULT '',
    history        jsonb NOT NULL DEFAULT '[]'::jsonb, -- capped at 50 entries in application code
    created_at     timestamptz NOT NULL,
    updated_at     timestamptz NOT NULL,
    next_attempt   timestamptz NOT NULL,
    lease_until    timestamptz,
    lease_id       text NOT NULL DEFAULT '',
    attempts       integer NOT NULL DEFAULT 0,
    http_status    integer,
    error_code     text NOT NULL DEFAULT ''
);
CREATE INDEX logout_deliveries_op_session_idx ON logout_deliveries (op_session_id);
CREATE INDEX logout_deliveries_app_session_idx ON logout_deliveries (app_session_id);
CREATE INDEX logout_deliveries_created_at_idx ON logout_deliveries (created_at);
-- Worker claim predicate: backchannel + pending/delivering + due, ordered
-- by next_attempt. FOR UPDATE SKIP LOCKED is applied at query time.
CREATE INDEX logout_deliveries_claim_idx ON logout_deliveries (channel, status, next_attempt);

CREATE TABLE logout_interactions (
    id             text PRIMARY KEY,
    client_id      text NOT NULL DEFAULT '',
    app_session_id text NOT NULL DEFAULT '',
    binding_hash   text NOT NULL DEFAULT '',
    csrf           text NOT NULL DEFAULT '',
    op_session_id  text NOT NULL DEFAULT '',
    user_id        text NOT NULL DEFAULT '',
    redirect_uri   text NOT NULL DEFAULT '',
    state          text NOT NULL DEFAULT '',
    expires_at     timestamptz NOT NULL,
    completed      boolean NOT NULL DEFAULT false
);
CREATE INDEX logout_interactions_expires_at_idx ON logout_interactions (expires_at);
