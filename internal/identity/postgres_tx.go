package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// postgresTx implements both ReadTx and Tx against one Postgres
// transaction. Every Save*/Delete*/Revoke* method (the Tx-only surface)
// executes its statement immediately and records any failure on err; since
// none of those methods can return an error per the Store interface, a
// failure "poisons" the transaction so the eventual Store.Write caller
// still observes it and the transaction still rolls back (see
// postgres_store.go's runOnce).
type postgresTx struct {
	ctx     context.Context
	tx      pgx.Tx
	secrets *FileStore
	now     func() time.Time
	err     error
}

// fail records the first error seen so subsequent calls short-circuit;
// once poisoned, read methods return the zero value / ErrNotFound rather
// than issuing more statements against a transaction that will roll back
// anyway.
func (p *postgresTx) fail(err error) {
	if p.err == nil && err != nil {
		p.err = err
	}
}

func (p *postgresTx) poisoned() bool { return p.err != nil }

// nzs ("non-nil strings") guards every text[] NOT NULL column write: pgx
// sends a nil []string as SQL NULL rather than an empty array, which
// violates the NOT NULL constraint these columns carry (matching
// fileState's map/slice fields, which are never actually nil once past
// JSON decoding, but domain structs constructed directly in Go - as
// AuthorizationCode/AuthzTransaction/etc. are throughout internal/oidc -
// commonly leave an unset []string as nil).
func nzs(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---- Users ----

func encodeUserProfile(u User) ([]byte, error) {
	return json.Marshal(struct {
		GivenName         string                     `json:"given_name,omitempty"`
		FamilyName        string                     `json:"family_name,omitempty"`
		MiddleName        string                     `json:"middle_name,omitempty"`
		Nickname          string                     `json:"nickname,omitempty"`
		PreferredUsername string                     `json:"preferred_username,omitempty"`
		ProfileURL        string                     `json:"profile,omitempty"`
		Picture           string                     `json:"picture,omitempty"`
		Website           string                     `json:"website,omitempty"`
		Gender            string                     `json:"gender,omitempty"`
		Birthdate         string                     `json:"birthdate,omitempty"`
		Zoneinfo          string                     `json:"zoneinfo,omitempty"`
		Locale            string                     `json:"locale,omitempty"`
		PhoneNumber       string                     `json:"phone_number,omitempty"`
		PhoneVerified     bool                       `json:"phone_number_verified,omitempty"`
		Address           Address                    `json:"address"`
		CustomAttributes  map[string]json.RawMessage `json:"custom_attributes,omitempty"`
	}{
		GivenName: u.GivenName, FamilyName: u.FamilyName, MiddleName: u.MiddleName,
		Nickname: u.Nickname, PreferredUsername: u.PreferredUsername, ProfileURL: u.ProfileURL,
		Picture: u.Picture, Website: u.Website, Gender: u.Gender, Birthdate: u.Birthdate,
		Zoneinfo: u.Zoneinfo, Locale: u.Locale, PhoneNumber: u.PhoneNumber,
		PhoneVerified: u.PhoneNumberVerified, Address: u.Address, CustomAttributes: u.CustomAttributes,
	})
}

func decodeUserProfile(raw []byte, u *User) error {
	var p struct {
		GivenName         string                     `json:"given_name,omitempty"`
		FamilyName        string                     `json:"family_name,omitempty"`
		MiddleName        string                     `json:"middle_name,omitempty"`
		Nickname          string                     `json:"nickname,omitempty"`
		PreferredUsername string                     `json:"preferred_username,omitempty"`
		ProfileURL        string                     `json:"profile,omitempty"`
		Picture           string                     `json:"picture,omitempty"`
		Website           string                     `json:"website,omitempty"`
		Gender            string                     `json:"gender,omitempty"`
		Birthdate         string                     `json:"birthdate,omitempty"`
		Zoneinfo          string                     `json:"zoneinfo,omitempty"`
		Locale            string                     `json:"locale,omitempty"`
		PhoneNumber       string                     `json:"phone_number,omitempty"`
		PhoneVerified     bool                       `json:"phone_number_verified,omitempty"`
		Address           Address                    `json:"address"`
		CustomAttributes  map[string]json.RawMessage `json:"custom_attributes,omitempty"`
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &p); err != nil {
			return err
		}
	}
	u.GivenName, u.FamilyName, u.MiddleName = p.GivenName, p.FamilyName, p.MiddleName
	u.Nickname, u.PreferredUsername, u.ProfileURL = p.Nickname, p.PreferredUsername, p.ProfileURL
	u.Picture, u.Website, u.Gender, u.Birthdate = p.Picture, p.Website, p.Gender, p.Birthdate
	u.Zoneinfo, u.Locale, u.PhoneNumber = p.Zoneinfo, p.Locale, p.PhoneNumber
	u.PhoneNumberVerified = p.PhoneVerified
	u.Address, u.CustomAttributes = p.Address, p.CustomAttributes
	return nil
}

const userColumns = `id, email, email_verified, name, role, active, password_hash, profile, created_at, updated_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	var profile []byte
	if err := row.Scan(&u.ID, &u.Email, &u.EmailVerified, &u.Name, &u.Role, &u.Active, &u.PasswordHash, &profile, &u.CreatedAt, &u.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrNotFound
		}
		return User{}, err
	}
	if err := decodeUserProfile(profile, &u); err != nil {
		return User{}, err
	}
	u.Sub = u.ID
	u.ClaimUpdatedAt = u.UpdatedAt.Unix()
	return u, nil
}

func (p *postgresTx) User(id string) (User, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, id)
	return scanUser(row)
}

func (p *postgresTx) UserByEmail(email string) (User, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+userColumns+` FROM users WHERE lower(email) = lower($1)`, email)
	return scanUser(row)
}

func (p *postgresTx) Users() []User {
	rows, err := p.tx.Query(p.ctx, `SELECT `+userColumns+` FROM users ORDER BY created_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

// SaveUser is the only fallible Tx mutator in the interface. Case-
// insensitive email uniqueness is enforced by the users_email_lower_idx
// unique index; a violation there is translated to ErrConflict, matching
// fileState.SaveUser's explicit EqualFold scan. A change to
// passwordHash/email/role/active cascades into DeleteUserSessions, exactly
// as fileState.SaveUser does.
func (p *postgresTx) SaveUser(user User) error {
	if p.poisoned() {
		return p.err
	}
	oldRow := p.tx.QueryRow(p.ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, user.ID)
	existing, err := scanUser(oldRow)
	hadOld := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}

	profile, err := encodeUserProfile(user)
	if err != nil {
		return err
	}
	_, err = p.tx.Exec(p.ctx, `
		INSERT INTO users (id, email, email_verified, name, role, active, password_hash, profile, created_at, updated_at)
		VALUES ($1, lower($2), $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (id) DO UPDATE SET
			email = lower($2), email_verified = $3, name = $4, role = $5, active = $6,
			password_hash = $7, profile = $8, updated_at = $10`,
		user.ID, user.Email, user.EmailVerified, user.Name, user.Role, user.Active,
		user.PasswordHash, profile, user.CreatedAt, user.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}

	if hadOld && (existing.PasswordHash != user.PasswordHash || existing.Email != user.Email ||
		existing.Role != user.Role || existing.Active != user.Active) {
		p.DeleteUserSessions(user.ID)
	}
	return p.err
}

func (p *postgresTx) DeleteUser(id string) {
	if p.poisoned() {
		return
	}
	if _, err := p.tx.Exec(p.ctx, `DELETE FROM oauth_access WHERE user_id = $1`, id); err != nil {
		p.fail(err)
		return
	}
	p.DeleteUserSessions(id)
	if _, err := p.tx.Exec(p.ctx, `DELETE FROM users WHERE id = $1`, id); err != nil {
		p.fail(err)
	}
}

// DeleteUserSessions is the security cascade: revoke all access grants for
// the user, hard-delete codes/transactions/consents, and end (not delete)
// every session. Order matches fileState.DeleteUserSessions.
func (p *postgresTx) DeleteUserSessions(userID string) {
	if p.poisoned() {
		return
	}
	p.RevokeAccessTokensForUser(userID)
	if _, err := p.tx.Exec(p.ctx, `DELETE FROM authorization_codes WHERE user_id = $1`, userID); err != nil {
		p.fail(err)
		return
	}
	if _, err := p.tx.Exec(p.ctx, `DELETE FROM authz_transactions WHERE user_id = $1`, userID); err != nil {
		p.fail(err)
		return
	}
	if _, err := p.tx.Exec(p.ctx, `DELETE FROM consents WHERE user_id = $1`, userID); err != nil {
		p.fail(err)
		return
	}
	rows, err := p.tx.Query(p.ctx, `SELECT id FROM sessions WHERE user_id = $1 AND ended_at IS NULL`, userID)
	if err != nil {
		p.fail(err)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			p.fail(err)
			return
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		p.fail(err)
		return
	}
	now := p.now()
	for _, id := range ids {
		p.EndSession(id, "security", "account_security_change", now)
	}
}

func isUniqueViolation(err error) bool {
	var pgErr interface{ SQLState() string }
	if errors.As(err, &pgErr) {
		return pgErr.SQLState() == "23505"
	}
	return false
}

// ---- Sessions ----

const sessionColumns = `hash, id, user_id, device, csrf, created_at, last_seen_at, auth_time, expires_at, ended_at, end_reason`

func scanSession(row pgx.Row) (Session, error) {
	var s Session
	var authTime, endedAt *time.Time
	if err := row.Scan(&s.Hash, &s.ID, &s.UserID, &s.Device, &s.CSRF, &s.CreatedAt, &s.LastSeenAt, &authTime, &s.ExpiresAt, &endedAt, &s.EndReason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrNotFound
		}
		return Session{}, err
	}
	if authTime != nil {
		s.AuthTime = *authTime
	}
	if endedAt != nil {
		s.EndedAt = *endedAt
	}
	return s, nil
}

// Session returns ErrNotFound for an ended session, matching
// fileState.Session - callers separately check ExpiresAt themselves.
func (p *postgresTx) Session(hash string) (Session, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+sessionColumns+` FROM sessions WHERE hash = $1 AND ended_at IS NULL`, hash)
	return scanSession(row)
}

// SessionByID is not part of the ReadTx interface but is used internally
// by cascades below that must locate a session by its stable ID.
func (p *postgresTx) sessionByID(id string) (Session, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = $1 ORDER BY ended_at IS NULL DESC LIMIT 1`, id)
	return scanSession(row)
}

func (p *postgresTx) ListSessions() []Session {
	rows, err := p.tx.Query(p.ctx, `SELECT `+sessionColumns+` FROM sessions ORDER BY created_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

func (p *postgresTx) SaveSession(session Session) {
	if p.poisoned() {
		return
	}
	var authTime, endedAt *time.Time
	if !session.AuthTime.IsZero() {
		authTime = &session.AuthTime
	}
	if !session.EndedAt.IsZero() {
		endedAt = &session.EndedAt
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO sessions (hash, id, user_id, device, csrf, created_at, last_seen_at, auth_time, expires_at, ended_at, end_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (hash) DO UPDATE SET
			id = $2, user_id = $3, device = $4, csrf = $5, last_seen_at = $7,
			auth_time = $8, expires_at = $9, ended_at = $10, end_reason = $11`,
		session.Hash, session.ID, session.UserID, session.Device, session.CSRF,
		session.CreatedAt, session.LastSeenAt, authTime, session.ExpiresAt, endedAt, session.EndReason,
	)
	p.fail(err)
}

// RemoveSessionCredential hard-deletes a session row without ending it -
// used only for credential rotation at login, where the same logical
// session (by ID) continues under a new hash.
func (p *postgresTx) RemoveSessionCredential(hash string) {
	if p.poisoned() {
		return
	}
	_, err := p.tx.Exec(p.ctx, `DELETE FROM sessions WHERE hash = $1`, hash)
	p.fail(err)
}

// DeleteSession is not a delete: it ends the session with reason
// "sign_out", matching fileState.DeleteSession.
func (p *postgresTx) DeleteSession(hash string) {
	if p.poisoned() {
		return
	}
	sess, err := p.Session(hash)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			p.fail(err)
		}
		return
	}
	p.EndSession(sess.ID, "user", "sign_out", p.now())
}

func (p *postgresTx) CheckSessionCapacity(kind string) error {
	var table string
	var limit int
	switch kind {
	case "op":
		table, limit = "sessions", 10000
	case "app":
		table, limit = "app_sessions", 50000
	case "interaction":
		table, limit = "logout_interactions", 10000
	default:
		return nil
	}
	var count int
	if err := p.tx.QueryRow(p.ctx, `SELECT count(*) FROM `+table).Scan(&count); err != nil {
		return err
	}
	if count >= limit {
		return fmt.Errorf("%s capacity exceeded", kind)
	}
	return nil
}

// EndSession ends every (there should be at most one live) session row
// with the given logical ID, cascading exactly as fileState.EndSession:
// emit a local logout delivery, end every app session tied to it, and
// revoke (not delete) transactions/codes tied to it.
func (p *postgresTx) EndSession(id, actor, reason string, now time.Time) {
	if p.poisoned() {
		return
	}
	rows, err := p.tx.Query(p.ctx, `SELECT hash, user_id FROM sessions WHERE id = $1 AND ended_at IS NULL`, id)
	if err != nil {
		p.fail(err)
		return
	}
	type liveSession struct{ hash, userID string }
	var live []liveSession
	for rows.Next() {
		var l liveSession
		if err := rows.Scan(&l.hash, &l.userID); err != nil {
			rows.Close()
			p.fail(err)
			return
		}
		live = append(live, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		p.fail(err)
		return
	}
	for _, l := range live {
		if _, err := p.tx.Exec(p.ctx, `UPDATE sessions SET ended_at = $1, end_reason = $2, csrf = '' WHERE hash = $3`, now, reason, l.hash); err != nil {
			p.fail(err)
			return
		}
		p.SaveLogoutDelivery(LogoutDelivery{ID: "op-" + id, OPSessionID: id, UserID: l.userID, Actor: actor, Reason: reason, Channel: "local", Status: "ended", CreatedAt: now, UpdatedAt: now})

		appRows, err := p.tx.Query(p.ctx, `SELECT id FROM app_sessions WHERE op_session_id = $1 AND ended_at IS NULL`, id)
		if err != nil {
			p.fail(err)
			return
		}
		var appIDs []string
		for appRows.Next() {
			var appID string
			if err := appRows.Scan(&appID); err != nil {
				appRows.Close()
				p.fail(err)
				return
			}
			appIDs = append(appIDs, appID)
		}
		appRows.Close()
		if err := appRows.Err(); err != nil {
			p.fail(err)
			return
		}
		for _, appID := range appIDs {
			p.EndAppSession(appID, actor, reason, now)
		}

		if _, err := p.tx.Exec(p.ctx, `UPDATE authz_transactions SET revoked = true WHERE op_session_id = $1`, id); err != nil {
			p.fail(err)
			return
		}
		if _, err := p.tx.Exec(p.ctx, `UPDATE authorization_codes SET revoked = true WHERE op_session_id = $1`, id); err != nil {
			p.fail(err)
			return
		}
	}
}

// ---- AppSessions ----

const appSessionColumns = `id, op_session_id, client_id, user_id, subject, created_at, last_seen_at, ended_at, end_reason`

func scanAppSession(row pgx.Row) (AppSession, error) {
	var a AppSession
	var endedAt *time.Time
	if err := row.Scan(&a.ID, &a.OPSessionID, &a.ClientID, &a.UserID, &a.Subject, &a.CreatedAt, &a.LastSeenAt, &endedAt, &a.EndReason); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AppSession{}, ErrNotFound
		}
		return AppSession{}, err
	}
	if endedAt != nil {
		a.EndedAt = *endedAt
	}
	return a, nil
}

func (p *postgresTx) AppSession(id string) (AppSession, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+appSessionColumns+` FROM app_sessions WHERE id = $1`, id)
	return scanAppSession(row)
}

func (p *postgresTx) ListAppSessions() []AppSession {
	rows, err := p.tx.Query(p.ctx, `SELECT `+appSessionColumns+` FROM app_sessions ORDER BY created_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []AppSession
	for rows.Next() {
		a, err := scanAppSession(rows)
		if err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

func (p *postgresTx) SaveAppSession(a AppSession) {
	if p.poisoned() {
		return
	}
	var endedAt *time.Time
	if !a.EndedAt.IsZero() {
		endedAt = &a.EndedAt
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO app_sessions (id, op_session_id, client_id, user_id, subject, created_at, last_seen_at, ended_at, end_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			op_session_id = $2, client_id = $3, user_id = $4, subject = $5,
			last_seen_at = $7, ended_at = $8, end_reason = $9`,
		a.ID, a.OPSessionID, a.ClientID, a.UserID, a.Subject, a.CreatedAt, a.LastSeenAt, endedAt, a.EndReason,
	)
	p.fail(err)
}

// EndAppSession cascades exactly as fileState.EndAppSession: revoke
// non-family-backed access tokens, revoke (not delete) transactions/codes
// matched by the (op_session_id, client_id) pair, and emit logout
// deliveries derived from the client's current front/back-channel logout
// URIs (a no-op, matching the in-memory version, if the app session is
// absent or already ended).
func (p *postgresTx) EndAppSession(id, actor, reason string, now time.Time) {
	if p.poisoned() {
		return
	}
	a, err := p.AppSession(id)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			p.fail(err)
		}
		return
	}
	if !a.EndedAt.IsZero() {
		return
	}
	if _, err := p.tx.Exec(p.ctx, `UPDATE app_sessions SET ended_at = $1, end_reason = $2 WHERE id = $3`, now, reason, id); err != nil {
		p.fail(err)
		return
	}
	if _, err := p.tx.Exec(p.ctx, `UPDATE access_tokens SET revoked = true WHERE app_session_id = $1 AND family_id = ''`, id); err != nil {
		p.fail(err)
		return
	}
	if _, err := p.tx.Exec(p.ctx, `UPDATE authorization_codes SET revoked = true WHERE op_session_id = $1 AND client_id = $2`, a.OPSessionID, a.ClientID); err != nil {
		p.fail(err)
		return
	}
	if _, err := p.tx.Exec(p.ctx, `UPDATE authz_transactions SET revoked = true WHERE op_session_id = $1 AND client_id = $2`, a.OPSessionID, a.ClientID); err != nil {
		p.fail(err)
		return
	}

	var backchannel, frontchannel *string
	err = p.tx.QueryRow(p.ctx, `
		SELECT NULLIF(metadata->>'backchannel_logout_uri', ''), NULLIF(metadata->>'frontchannel_logout_uri', '')
		FROM clients WHERE id = $1`, a.ClientID).Scan(&backchannel, &frontchannel)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		p.fail(err)
		return
	}

	supported := false
	if backchannel != nil {
		supported = true
		p.SaveLogoutDelivery(LogoutDelivery{ID: id + "-backchannel", OPSessionID: a.OPSessionID, AppSessionID: id, ClientID: a.ClientID, UserID: a.UserID, Subject: a.Subject, Actor: actor, Reason: reason, Channel: "backchannel", Status: "pending", Endpoint: *backchannel, CreatedAt: now, UpdatedAt: now, NextAttempt: now})
	}
	if frontchannel != nil {
		supported = true
		p.SaveLogoutDelivery(LogoutDelivery{ID: id + "-frontchannel", OPSessionID: a.OPSessionID, AppSessionID: id, ClientID: a.ClientID, UserID: a.UserID, Subject: a.Subject, Actor: actor, Reason: reason, Channel: "frontchannel", Status: "browser_unavailable", Endpoint: *frontchannel, CreatedAt: now, UpdatedAt: now, NextAttempt: now})
	}
	if !supported {
		p.SaveLogoutDelivery(LogoutDelivery{ID: id + "-unsupported", OPSessionID: a.OPSessionID, AppSessionID: id, ClientID: a.ClientID, UserID: a.UserID, Actor: actor, Reason: reason, Channel: "none", Status: "unsupported", CreatedAt: now, UpdatedAt: now})
	}
}

// ---- LogoutOperations ----

func (p *postgresTx) LogoutOperation(id string) (LogoutOperation, error) {
	var op LogoutOperation
	err := p.tx.QueryRow(p.ctx, `SELECT id, actor, kind, created_at FROM logout_operations WHERE id = $1`, id).
		Scan(&op.ID, &op.Actor, &op.Kind, &op.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LogoutOperation{}, ErrNotFound
		}
		return LogoutOperation{}, err
	}
	targetRows, err := p.tx.Query(p.ctx, `SELECT target_id FROM logout_operation_targets WHERE operation_id = $1`, id)
	if err != nil {
		return LogoutOperation{}, err
	}
	defer targetRows.Close()
	for targetRows.Next() {
		var target string
		if err := targetRows.Scan(&target); err != nil {
			return LogoutOperation{}, err
		}
		op.Targets = append(op.Targets, target)
	}
	return op, targetRows.Err()
}

// SaveLogoutOperation bounds operational history at 10000 rows, evicting
// the oldest by created_at before inserting - matching fileState's O(n)
// eviction, expressed here as a single SQL statement.
func (p *postgresTx) SaveLogoutOperation(op LogoutOperation) {
	if p.poisoned() {
		return
	}
	var count int
	if err := p.tx.QueryRow(p.ctx, `SELECT count(*) FROM logout_operations`).Scan(&count); err != nil {
		p.fail(err)
		return
	}
	if count >= 10000 {
		if _, err := p.tx.Exec(p.ctx, `DELETE FROM logout_operations WHERE id = (SELECT id FROM logout_operations ORDER BY created_at ASC LIMIT 1)`); err != nil {
			p.fail(err)
			return
		}
	}
	if _, err := p.tx.Exec(p.ctx, `
		INSERT INTO logout_operations (id, actor, kind, created_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET actor = $2, kind = $3, created_at = $4`,
		op.ID, op.Actor, op.Kind, op.CreatedAt,
	); err != nil {
		p.fail(err)
		return
	}
	if _, err := p.tx.Exec(p.ctx, `DELETE FROM logout_operation_targets WHERE operation_id = $1`, op.ID); err != nil {
		p.fail(err)
		return
	}
	for _, target := range op.Targets {
		if _, err := p.tx.Exec(p.ctx, `INSERT INTO logout_operation_targets (operation_id, target_id) VALUES ($1, $2)`, op.ID, target); err != nil {
			p.fail(err)
			return
		}
	}
}

// ---- LogoutDeliveries ----

const logoutDeliveryColumns = `id, op_session_id, app_session_id, client_id, user_id, subject, actor, reason, channel, status, endpoint, history, created_at, updated_at, next_attempt, lease_until, lease_id, attempts, http_status, error_code`

func scanLogoutDelivery(row pgx.Row) (LogoutDelivery, error) {
	var d LogoutDelivery
	var history []byte
	var leaseUntil *time.Time
	var httpStatus *int
	if err := row.Scan(&d.ID, &d.OPSessionID, &d.AppSessionID, &d.ClientID, &d.UserID, &d.Subject, &d.Actor, &d.Reason,
		&d.Channel, &d.Status, &d.Endpoint, &history, &d.CreatedAt, &d.UpdatedAt, &d.NextAttempt, &leaseUntil, &d.LeaseID,
		&d.Attempts, &httpStatus, &d.ErrorCode); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LogoutDelivery{}, ErrNotFound
		}
		return LogoutDelivery{}, err
	}
	if len(history) > 0 {
		if err := json.Unmarshal(history, &d.History); err != nil {
			return LogoutDelivery{}, err
		}
	}
	if leaseUntil != nil {
		d.LeaseUntil = *leaseUntil
	}
	if httpStatus != nil {
		d.HTTPStatus = *httpStatus
	}
	return d, nil
}

func (p *postgresTx) ListLogoutDeliveries() []LogoutDelivery {
	rows, err := p.tx.Query(p.ctx, `SELECT `+logoutDeliveryColumns+` FROM logout_deliveries ORDER BY created_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []LogoutDelivery
	for rows.Next() {
		d, err := scanLogoutDelivery(rows)
		if err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

// SaveLogoutDelivery relies on the caller (EndSession/EndAppSession) to
// have built a deterministic id, so ON CONFLICT DO UPDATE reproduces the
// idempotent-overwrite semantics fileState gets for free from map[id]=v.
func (p *postgresTx) SaveLogoutDelivery(d LogoutDelivery) {
	if p.poisoned() {
		return
	}
	history, err := json.Marshal(d.History)
	if err != nil {
		p.fail(err)
		return
	}
	var leaseUntil *time.Time
	if !d.LeaseUntil.IsZero() {
		leaseUntil = &d.LeaseUntil
	}
	var httpStatus *int
	if d.HTTPStatus != 0 {
		httpStatus = &d.HTTPStatus
	}
	_, err = p.tx.Exec(p.ctx, `
		INSERT INTO logout_deliveries (id, op_session_id, app_session_id, client_id, user_id, subject, actor, reason,
			channel, status, endpoint, history, created_at, updated_at, next_attempt, lease_until, lease_id, attempts, http_status, error_code)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
		ON CONFLICT (id) DO UPDATE SET
			op_session_id=$2, app_session_id=$3, client_id=$4, user_id=$5, subject=$6, actor=$7, reason=$8,
			channel=$9, status=$10, endpoint=$11, history=$12, updated_at=$14, next_attempt=$15,
			lease_until=$16, lease_id=$17, attempts=$18, http_status=$19, error_code=$20`,
		d.ID, d.OPSessionID, d.AppSessionID, d.ClientID, d.UserID, d.Subject, d.Actor, d.Reason,
		d.Channel, d.Status, d.Endpoint, history, d.CreatedAt, d.UpdatedAt, d.NextAttempt, leaseUntil, d.LeaseID, d.Attempts, httpStatus, d.ErrorCode,
	)
	p.fail(err)
}

// ---- LogoutInteractions ----

const logoutInteractionColumns = `id, client_id, app_session_id, binding_hash, csrf, op_session_id, user_id, redirect_uri, state, expires_at, completed`

func scanLogoutInteraction(row pgx.Row) (LogoutInteraction, error) {
	var v LogoutInteraction
	if err := row.Scan(&v.ID, &v.ClientID, &v.AppSessionID, &v.BindingHash, &v.CSRF, &v.OPSessionID, &v.UserID, &v.RedirectURI, &v.State, &v.ExpiresAt, &v.Completed); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return LogoutInteraction{}, ErrNotFound
		}
		return LogoutInteraction{}, err
	}
	return v, nil
}

func (p *postgresTx) LogoutInteraction(id string) (LogoutInteraction, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+logoutInteractionColumns+` FROM logout_interactions WHERE id = $1`, id)
	return scanLogoutInteraction(row)
}

func (p *postgresTx) SaveLogoutInteraction(v LogoutInteraction) {
	if p.poisoned() {
		return
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO logout_interactions (id, client_id, app_session_id, binding_hash, csrf, op_session_id, user_id, redirect_uri, state, expires_at, completed)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (id) DO UPDATE SET
			client_id=$2, app_session_id=$3, binding_hash=$4, csrf=$5, op_session_id=$6,
			user_id=$7, redirect_uri=$8, state=$9, expires_at=$10, completed=$11`,
		v.ID, v.ClientID, v.AppSessionID, v.BindingHash, v.CSRF, v.OPSessionID, v.UserID, v.RedirectURI, v.State, v.ExpiresAt, v.Completed,
	)
	p.fail(err)
}

func (p *postgresTx) LogoutMaintenanceDue(now time.Time) bool {
	// The logout worker calls this every tick; there is no persisted
	// "last swept at" marker in the relational schema (nor in fileState),
	// so maintenance is always considered due and the prune queries below
	// are cheap no-ops when there is nothing to do.
	return true
}

// ---- Pruning ----

func (p *postgresTx) PruneSessions(now time.Time) {
	if p.poisoned() {
		return
	}
	rows, err := p.tx.Query(p.ctx, `SELECT id FROM sessions WHERE ended_at IS NULL AND expires_at <= $1`, now)
	if err != nil {
		p.fail(err)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			p.fail(err)
			return
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		p.fail(err)
		return
	}
	for _, id := range ids {
		p.EndSession(id, "system", "expired", now)
	}
}

// PruneLogoutState ends expired sessions, then hard-deletes 30-day-old
// logout operations/deliveries, expired logout interactions, and 30-day-
// ended app sessions/sessions - matching fileState.PruneLogoutState.
func (p *postgresTx) PruneLogoutState(now time.Time) {
	if p.poisoned() {
		return
	}
	p.PruneSessions(now)
	if p.poisoned() {
		return
	}
	cutoff := now.Add(-30 * 24 * time.Hour)
	stmts := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM logout_operations WHERE created_at < $1`, []any{cutoff}},
		{`DELETE FROM logout_interactions WHERE expires_at <= $1`, []any{now}},
		{`DELETE FROM logout_deliveries WHERE created_at < $1`, []any{cutoff}},
		{`DELETE FROM app_sessions WHERE ended_at IS NOT NULL AND ended_at < $1`, []any{cutoff}},
		{`DELETE FROM sessions WHERE ended_at IS NOT NULL AND ended_at < $1`, []any{cutoff}},
	}
	for _, s := range stmts {
		if _, err := p.tx.Exec(p.ctx, s.sql, s.args...); err != nil {
			p.fail(err)
			return
		}
	}
}

// PruneOIDCState deletes expired transactions, expired-and-retention-
// lapsed codes, expired access tokens, and refresh families past their
// retain_until (cascading to their tokens via ON DELETE CASCADE) -
// matching fileState.PruneOIDCState exactly, including the dual-condition
// authorization_codes predicate that protects replay-detection evidence.
func (p *postgresTx) PruneOIDCState(now time.Time) {
	if p.poisoned() {
		return
	}
	stmts := []string{
		`DELETE FROM refresh_families WHERE retain_until <= $1`,
		`DELETE FROM authz_transactions WHERE expires_at <= $1`,
		`DELETE FROM authorization_codes WHERE expires_at <= $1 AND (retain_until IS NULL OR retain_until <= $1)`,
		`DELETE FROM access_tokens WHERE expires_at <= $1`,
	}
	for _, s := range stmts {
		if _, err := p.tx.Exec(p.ctx, s, now); err != nil {
			p.fail(err)
			return
		}
	}
}

// ---- Access tokens / revocation ----

const accessTokenColumns = `hash, client_id, user_id, audience, scopes, grant_type, subject_kind, family_id, original_grant, code_hash, op_session_id, app_session_id, id_token_expires_at, issued_at, expires_at, revoked`

func scanAccessToken(row pgx.Row) (AccessToken, error) {
	var a AccessToken
	var idTokenExp *time.Time
	if err := row.Scan(&a.Hash, &a.ClientID, &a.UserID, &a.Audience, &a.Scopes, &a.GrantType, &a.SubjectKind,
		&a.FamilyID, &a.OriginalGrant, &a.CodeHash, &a.OPSessionID, &a.AppSessionID, &idTokenExp, &a.IssuedAt, &a.ExpiresAt, &a.Revoked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AccessToken{}, ErrNotFound
		}
		return AccessToken{}, err
	}
	if idTokenExp != nil {
		a.IDTokenExpiresAt = *idTokenExp
	}
	return a, nil
}

func (p *postgresTx) AccessToken(hash string) (AccessToken, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+accessTokenColumns+` FROM access_tokens WHERE hash = $1`, hash)
	return scanAccessToken(row)
}

func (p *postgresTx) ListAccessTokens() []AccessToken {
	rows, err := p.tx.Query(p.ctx, `SELECT `+accessTokenColumns+` FROM access_tokens ORDER BY issued_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []AccessToken
	for rows.Next() {
		a, err := scanAccessToken(rows)
		if err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

func (p *postgresTx) SaveAccessToken(a AccessToken) {
	if p.poisoned() {
		return
	}
	var idTokenExp *time.Time
	if !a.IDTokenExpiresAt.IsZero() {
		idTokenExp = &a.IDTokenExpiresAt
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO access_tokens (hash, client_id, user_id, audience, scopes, grant_type, subject_kind, family_id,
			original_grant, code_hash, op_session_id, app_session_id, id_token_expires_at, issued_at, expires_at, revoked)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (hash) DO UPDATE SET
			client_id=$2, user_id=$3, audience=$4, scopes=$5, grant_type=$6, subject_kind=$7, family_id=$8,
			original_grant=$9, code_hash=$10, op_session_id=$11, app_session_id=$12, id_token_expires_at=$13,
			expires_at=$15, revoked=$16`,
		a.Hash, a.ClientID, a.UserID, a.Audience, nzs(a.Scopes), a.GrantType, a.SubjectKind, a.FamilyID,
		a.OriginalGrant, a.CodeHash, a.OPSessionID, a.AppSessionID, idTokenExp, a.IssuedAt, a.ExpiresAt, a.Revoked,
	)
	p.fail(err)
}

func (p *postgresTx) RevokeAccessToken(hash string) {
	if p.poisoned() {
		return
	}
	_, err := p.tx.Exec(p.ctx, `UPDATE access_tokens SET revoked = true WHERE hash = $1`, hash)
	p.fail(err)
}

func (p *postgresTx) RevokeAccessTokensForUser(userID string) {
	if p.poisoned() {
		return
	}
	p.revokeFamiliesMatching(`user_id = $1`, userID)
	if p.poisoned() {
		return
	}
	if _, err := p.tx.Exec(p.ctx, `UPDATE access_tokens SET revoked = true WHERE user_id = $1`, userID); err != nil {
		p.fail(err)
	}
}

func (p *postgresTx) RevokeAccessTokensForClient(clientID string) {
	if p.poisoned() {
		return
	}
	p.revokeFamiliesMatching(`client_id = $1`, clientID)
	if p.poisoned() {
		return
	}
	if _, err := p.tx.Exec(p.ctx, `UPDATE access_tokens SET revoked = true WHERE client_id = $1`, clientID); err != nil {
		p.fail(err)
	}
}

func (p *postgresTx) RevokeAccessTokensForCode(codeHash string) {
	if p.poisoned() {
		return
	}
	p.revokeFamiliesMatching(`code_hash = $1`, codeHash)
	if p.poisoned() {
		return
	}
	if _, err := p.tx.Exec(p.ctx, `UPDATE access_tokens SET revoked = true WHERE code_hash = $1`, codeHash); err != nil {
		p.fail(err)
	}
}

// revokeFamiliesMatching revokes every refresh family matching the given
// predicate, one at a time via RevokeRefreshFamily so each family's own
// access-token cascade also runs (matching fileState's per-family call to
// RevokeRefreshFamily rather than a single bulk UPDATE).
func (p *postgresTx) revokeFamiliesMatching(where string, args ...any) {
	rows, err := p.tx.Query(p.ctx, `SELECT id FROM refresh_families WHERE `+where+` AND NOT revoked`, args...)
	if err != nil {
		p.fail(err)
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			p.fail(err)
			return
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		p.fail(err)
		return
	}
	for _, id := range ids {
		p.RevokeRefreshFamily(id)
	}
}

// ---- Clients ----

const clientColumns = `id, origin, initial_token_id, metadata, secret, issued_at, updated_at, updated_at_ns`

// scanClient reconstructs UpdatedAt from the separate updated_at_ns bigint
// column, not the updated_at timestamptz column: Postgres timestamptz has
// only microsecond precision, but UpdatedAt.UnixNano() is compared for
// exact equality against RefreshFamily.ClientRevision, Consent.PolicyRevision,
// and AuthzTransaction/AuthorizationCode.ClientUpdatedAt elsewhere in the
// domain - returning the truncated timestamptz value here would silently
// break every one of those revision-pin comparisons whenever a client was
// saved with sub-microsecond timing (time.Now() usually doesn't have that
// precision, so this can pass unnoticed until it doesn't).
func scanClient(row pgx.Row) (ClientRecord, error) {
	var c ClientRecord
	var metadata []byte
	var updatedAtNS int64
	if err := row.Scan(&c.ID, &c.Origin, &c.InitialTokenID, &metadata, &c.Secret, &c.IssuedAt, &c.UpdatedAt, &updatedAtNS); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ClientRecord{}, ErrNotFound
		}
		return ClientRecord{}, err
	}
	c.UpdatedAt = time.Unix(0, updatedAtNS).UTC()
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &c.Metadata); err != nil {
			return ClientRecord{}, err
		}
	}
	return c, nil
}

func (p *postgresTx) Client(id string) (ClientRecord, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+clientColumns+` FROM clients WHERE id = $1`, id)
	return scanClient(row)
}

func (p *postgresTx) Clients() []ClientRecord {
	rows, err := p.tx.Query(p.ctx, `SELECT `+clientColumns+` FROM clients ORDER BY issued_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []ClientRecord
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

// SaveClient enforces the strict monotonic UpdatedAt bump (store.go:
// "SaveClient must advance UpdatedAt monotonically, even with an unchanged
// clock") and, on any update to an existing client, invalidates its
// grants exactly as fileState.SaveClient does.
func (p *postgresTx) SaveClient(c ClientRecord) {
	if p.poisoned() {
		return
	}
	existing, err := p.Client(c.ID)
	hadOld := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		p.fail(err)
		return
	}
	if hadOld && !c.UpdatedAt.After(existing.UpdatedAt) {
		c.UpdatedAt = existing.UpdatedAt.Add(time.Nanosecond)
	}

	metadata, err := json.Marshal(c.Metadata)
	if err != nil {
		p.fail(err)
		return
	}
	_, err = p.tx.Exec(p.ctx, `
		INSERT INTO clients (id, origin, initial_token_id, metadata, secret, issued_at, updated_at, updated_at_ns)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (id) DO UPDATE SET
			origin=$2, initial_token_id=$3, metadata=$4, secret=$5, issued_at=$6, updated_at=$7, updated_at_ns=$8`,
		c.ID, c.Origin, c.InitialTokenID, metadata, c.Secret, c.IssuedAt, c.UpdatedAt, c.UpdatedAt.UnixNano(),
	)
	if err != nil {
		p.fail(err)
		return
	}
	if hadOld {
		p.invalidateClientGrants(c.ID)
	}
}

func (p *postgresTx) DeleteClient(id string) {
	if p.poisoned() {
		return
	}
	if _, err := p.tx.Exec(p.ctx, `DELETE FROM oauth_policies WHERE client_id = $1`, id); err != nil {
		p.fail(err)
		return
	}
	p.DeleteRegistrationToken(id)
	p.invalidateClientGrants(id)
	if p.poisoned() {
		return
	}
	if _, err := p.tx.Exec(p.ctx, `DELETE FROM clients WHERE id = $1`, id); err != nil {
		p.fail(err)
	}
}

// invalidateClientGrants: end every app session for the client (cascading
// per EndAppSession), revoke its access tokens/refresh families, and
// hard-delete its authorization codes, authz transactions, and consents -
// matching fileState.invalidateClientGrants exactly.
func (p *postgresTx) invalidateClientGrants(clientID string) {
	if p.poisoned() {
		return
	}
	rows, err := p.tx.Query(p.ctx, `SELECT id FROM app_sessions WHERE client_id = $1 AND ended_at IS NULL`, clientID)
	if err != nil {
		p.fail(err)
		return
	}
	var appIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			p.fail(err)
			return
		}
		appIDs = append(appIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		p.fail(err)
		return
	}
	now := p.now()
	for _, id := range appIDs {
		p.EndAppSession(id, "security", "client_changed", now)
	}
	p.RevokeAccessTokensForClient(clientID)
	if p.poisoned() {
		return
	}
	stmts := []string{
		`DELETE FROM authorization_codes WHERE client_id = $1`,
		`DELETE FROM authz_transactions WHERE client_id = $1`,
		`DELETE FROM consents WHERE client_id = $1`,
	}
	for _, s := range stmts {
		if _, err := p.tx.Exec(p.ctx, s, clientID); err != nil {
			p.fail(err)
			return
		}
	}
}

// ---- OAuthPolicy / OAuthAccess ----
//
// Both read paths return the Go zero value for a missing row, never
// ErrNotFound - AccessTokenActive and RefreshFamilyActive call them
// unconditionally and depend on this.

func (p *postgresTx) OAuthPolicy(id string) OAuthPolicy {
	var policy OAuthPolicy
	var resources []byte
	err := p.tx.QueryRow(p.ctx, `
		SELECT grants, resources, default_resource, introspection_enabled, introspection_audiences, refresh_inspection, refresh_enabled, password_enabled
		FROM oauth_policies WHERE client_id = $1`, id).
		Scan(&policy.Grants, &resources, &policy.DefaultResource, &policy.IntrospectionEnabled, &policy.IntrospectionAudiences, &policy.RefreshInspection, &policy.RefreshEnabled, &policy.PasswordEnabled)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			p.fail(err)
		}
		return OAuthPolicy{}
	}
	if len(resources) > 0 {
		if err := json.Unmarshal(resources, &policy.Resources); err != nil {
			p.fail(err)
			return OAuthPolicy{}
		}
	}
	return policy
}

// SaveOAuthPolicy invalidates the client's grants exactly like SaveClient -
// any policy change can widen or narrow what existing tokens/families are
// entitled to, so they must be re-evaluated from a clean slate.
func (p *postgresTx) SaveOAuthPolicy(id string, policy OAuthPolicy) {
	if p.poisoned() {
		return
	}
	resources, err := json.Marshal(policy.Resources)
	if err != nil {
		p.fail(err)
		return
	}
	_, err = p.tx.Exec(p.ctx, `
		INSERT INTO oauth_policies (client_id, grants, resources, default_resource, introspection_enabled, introspection_audiences, refresh_inspection, refresh_enabled, password_enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (client_id) DO UPDATE SET
			grants=$2, resources=$3, default_resource=$4, introspection_enabled=$5, introspection_audiences=$6,
			refresh_inspection=$7, refresh_enabled=$8, password_enabled=$9`,
		id, nzs(policy.Grants), resources, policy.DefaultResource, policy.IntrospectionEnabled, nzs(policy.IntrospectionAudiences), policy.RefreshInspection, policy.RefreshEnabled, policy.PasswordEnabled,
	)
	if err != nil {
		p.fail(err)
		return
	}
	p.invalidateClientGrants(id)
}

func (p *postgresTx) OAuthAccess(id string) OAuthAccess {
	rows, err := p.tx.Query(p.ctx, `SELECT audience, scopes FROM oauth_access WHERE user_id = $1`, id)
	if err != nil {
		p.fail(err)
		return OAuthAccess{}
	}
	defer rows.Close()
	out := OAuthAccess{}
	for rows.Next() {
		var audience string
		var scopes []string
		if err := rows.Scan(&audience, &scopes); err != nil {
			p.fail(err)
			return OAuthAccess{}
		}
		out[audience] = scopes
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

// SaveOAuthAccess replaces the user's entire access map (matching
// fileState's whole-map replace semantics), then cascades: end their app
// sessions and revoke their tokens/families, narrower than
// DeleteUserSessions (no session/code/transaction/consent changes).
func (p *postgresTx) SaveOAuthAccess(id string, access OAuthAccess) {
	if p.poisoned() {
		return
	}
	if _, err := p.tx.Exec(p.ctx, `DELETE FROM oauth_access WHERE user_id = $1`, id); err != nil {
		p.fail(err)
		return
	}
	for audience, scopes := range access {
		if _, err := p.tx.Exec(p.ctx, `INSERT INTO oauth_access (user_id, audience, scopes) VALUES ($1, $2, $3)`, id, audience, nzs(scopes)); err != nil {
			p.fail(err)
			return
		}
	}
	rows, err := p.tx.Query(p.ctx, `SELECT id FROM app_sessions WHERE user_id = $1 AND ended_at IS NULL`, id)
	if err != nil {
		p.fail(err)
		return
	}
	var appIDs []string
	for rows.Next() {
		var appID string
		if err := rows.Scan(&appID); err != nil {
			rows.Close()
			p.fail(err)
			return
		}
		appIDs = append(appIDs, appID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		p.fail(err)
		return
	}
	now := p.now()
	for _, appID := range appIDs {
		p.EndAppSession(appID, "security", "access_policy_changed", now)
	}
	p.RevokeAccessTokensForUser(id)
}

// ---- RefreshFamily / RefreshToken ----

const refreshFamilyColumns = `id, app_session_id, op_session_id, client_id, user_id, code_hash, audience, scopes, auth_time, client_revision, created_at, absolute_expiry, idle_expiry, retain_until, revoked`

func scanRefreshFamily(row pgx.Row) (RefreshFamily, error) {
	var f RefreshFamily
	if err := row.Scan(&f.ID, &f.AppSessionID, &f.OPSessionID, &f.ClientID, &f.UserID, &f.CodeHash, &f.Audience, &f.Scopes,
		&f.AuthTime, &f.ClientRevision, &f.CreatedAt, &f.AbsoluteExpiry, &f.IdleExpiry, &f.RetainUntil, &f.Revoked); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RefreshFamily{}, ErrNotFound
		}
		return RefreshFamily{}, err
	}
	return f, nil
}

func (p *postgresTx) RefreshFamily(id string) (RefreshFamily, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+refreshFamilyColumns+` FROM refresh_families WHERE id = $1`, id)
	return scanRefreshFamily(row)
}

func (p *postgresTx) ListRefreshFamilies() []RefreshFamily {
	rows, err := p.tx.Query(p.ctx, `SELECT `+refreshFamilyColumns+` FROM refresh_families ORDER BY created_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []RefreshFamily
	for rows.Next() {
		f, err := scanRefreshFamily(rows)
		if err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

func (p *postgresTx) SaveRefreshFamily(f RefreshFamily) {
	if p.poisoned() {
		return
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO refresh_families (id, app_session_id, op_session_id, client_id, user_id, code_hash, audience, scopes,
			auth_time, client_revision, created_at, absolute_expiry, idle_expiry, retain_until, revoked)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
		ON CONFLICT (id) DO UPDATE SET
			app_session_id=$2, op_session_id=$3, client_id=$4, user_id=$5, code_hash=$6, audience=$7, scopes=$8,
			auth_time=$9, client_revision=$10, absolute_expiry=$12, idle_expiry=$13, retain_until=$14, revoked=$15`,
		f.ID, f.AppSessionID, f.OPSessionID, f.ClientID, f.UserID, f.CodeHash, f.Audience, nzs(f.Scopes),
		f.AuthTime, f.ClientRevision, f.CreatedAt, f.AbsoluteExpiry, f.IdleExpiry, f.RetainUntil, f.Revoked,
	)
	p.fail(err)
}

// RevokeRefreshFamily atomically revokes the family and every access
// token minted from it, in one transaction - matching fileState's
// two-part update. A no-op if the family doesn't exist.
func (p *postgresTx) RevokeRefreshFamily(id string) {
	if p.poisoned() {
		return
	}
	if _, err := p.tx.Exec(p.ctx, `UPDATE refresh_families SET revoked = true WHERE id = $1`, id); err != nil {
		p.fail(err)
		return
	}
	if _, err := p.tx.Exec(p.ctx, `UPDATE access_tokens SET revoked = true WHERE family_id = $1`, id); err != nil {
		p.fail(err)
	}
}

func (p *postgresTx) RefreshToken(hash string) (RefreshToken, error) {
	var t RefreshToken
	err := p.tx.QueryRow(p.ctx, `SELECT hash, family_id, scopes, issued_at, consumed FROM refresh_tokens WHERE hash = $1`, hash).
		Scan(&t.Hash, &t.FamilyID, &t.Scopes, &t.IssuedAt, &t.Consumed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RefreshToken{}, ErrNotFound
		}
		return RefreshToken{}, err
	}
	return t, nil
}

func (p *postgresTx) ListRefreshTokens() []RefreshToken {
	rows, err := p.tx.Query(p.ctx, `SELECT hash, family_id, scopes, issued_at, consumed FROM refresh_tokens ORDER BY issued_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []RefreshToken
	for rows.Next() {
		var t RefreshToken
		if err := rows.Scan(&t.Hash, &t.FamilyID, &t.Scopes, &t.IssuedAt, &t.Consumed); err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

// SaveRefreshToken performs a plain upsert. The single-use / replay
// mechanism (refresh.go: read old, branch on Consumed, save) runs in
// application code against a value read from RefreshToken above within
// the same serializable transaction; SERIALIZABLE isolation plus the
// Write-level retry-on-40001 in postgres_store.go is what makes two
// concurrent redemptions resolve to exactly one winner, matching
// fileState's single-lock behavior without a per-row FOR UPDATE here.
func (p *postgresTx) SaveRefreshToken(t RefreshToken) {
	if p.poisoned() {
		return
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO refresh_tokens (hash, family_id, scopes, issued_at, consumed) VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (hash) DO UPDATE SET family_id=$2, scopes=$3, consumed=$5`,
		t.Hash, t.FamilyID, nzs(t.Scopes), t.IssuedAt, t.Consumed,
	)
	p.fail(err)
}

// ---- InitialAccessToken / RegistrationAccessToken ----

func (p *postgresTx) InitialToken(hash string) (InitialAccessToken, error) {
	var t InitialAccessToken
	err := p.tx.QueryRow(p.ctx, `SELECT hash, id, label, issued_by, issued_at, expires_at, max_uses, uses, revoked FROM initial_access_tokens WHERE hash = $1`, hash).
		Scan(&t.Hash, &t.ID, &t.Label, &t.IssuedBy, &t.IssuedAt, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.Revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return InitialAccessToken{}, ErrNotFound
		}
		return InitialAccessToken{}, err
	}
	return t, nil
}

func (p *postgresTx) InitialTokens() []InitialAccessToken {
	rows, err := p.tx.Query(p.ctx, `SELECT hash, id, label, issued_by, issued_at, expires_at, max_uses, uses, revoked FROM initial_access_tokens ORDER BY issued_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []InitialAccessToken
	for rows.Next() {
		var t InitialAccessToken
		if err := rows.Scan(&t.Hash, &t.ID, &t.Label, &t.IssuedBy, &t.IssuedAt, &t.ExpiresAt, &t.MaxUses, &t.Uses, &t.Revoked); err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

// SaveInitialToken is a plain upsert. The atomic use-counting invariant
// (registration.go: Uses++ under a re-validated "active" check) is
// implemented in application code as read-then-save within the same
// serializable transaction, relying on the same SERIALIZABLE-plus-retry
// property as refresh token rotation above to guarantee exactly one
// winner under concurrent registration attempts against the same token.
func (p *postgresTx) SaveInitialToken(t InitialAccessToken) {
	if p.poisoned() {
		return
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO initial_access_tokens (hash, id, label, issued_by, issued_at, expires_at, max_uses, uses, revoked)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		ON CONFLICT (hash) DO UPDATE SET
			id=$2, label=$3, issued_by=$4, expires_at=$6, max_uses=$7, uses=$8, revoked=$9`,
		t.Hash, t.ID, t.Label, t.IssuedBy, t.IssuedAt, t.ExpiresAt, t.MaxUses, t.Uses, t.Revoked,
	)
	p.fail(err)
}

func (p *postgresTx) RegistrationToken(clientID string) (RegistrationAccessToken, error) {
	var t RegistrationAccessToken
	err := p.tx.QueryRow(p.ctx, `SELECT hash, client_id, issued_at FROM registration_access_tokens WHERE client_id = $1`, clientID).
		Scan(&t.Hash, &t.ClientID, &t.IssuedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RegistrationAccessToken{}, ErrNotFound
		}
		return RegistrationAccessToken{}, err
	}
	return t, nil
}

// SaveRegistrationToken silently replaces any existing token for the
// client (at most one per client) - matching fileState's map[clientID]=v.
// Per store.go's documented contract, this must NOT touch clients.updated_at
// or invalidate grants, and it does not.
func (p *postgresTx) SaveRegistrationToken(t RegistrationAccessToken) {
	if p.poisoned() {
		return
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO registration_access_tokens (client_id, hash, issued_at) VALUES ($1,$2,$3)
		ON CONFLICT (client_id) DO UPDATE SET hash=$2, issued_at=$3`,
		t.ClientID, t.Hash, t.IssuedAt,
	)
	p.fail(err)
}

func (p *postgresTx) DeleteRegistrationToken(clientID string) {
	if p.poisoned() {
		return
	}
	_, err := p.tx.Exec(p.ctx, `DELETE FROM registration_access_tokens WHERE client_id = $1`, clientID)
	p.fail(err)
}

// ---- AuthzTransaction ----

const authzTransactionColumns = `id, client_id, redirect_uri, scopes, state, response_mode, nonce, code_challenge, code_challenge_method, prompt, max_age, login_hint, browser_binding_hash, op_session_id, app_session_id, user_id, auth_time, client_updated_at_ns, reauthenticate_after, consent_granted, revoked, consumed, expires_at, created_at`

func scanAuthzTransaction(row pgx.Row) (AuthzTransaction, error) {
	var t AuthzTransaction
	var maxAge *int64
	var reauthAfter *time.Time
	var clientUpdatedNS int64
	if err := row.Scan(&t.ID, &t.ClientID, &t.RedirectURI, &t.Scopes, &t.State, &t.ResponseMode, &t.Nonce,
		&t.CodeChallenge, &t.CodeChallengeMethod, &t.Prompt, &maxAge, &t.LoginHint, &t.BrowserBindingHash,
		&t.OPSessionID, &t.AppSessionID, &t.UserID, &t.AuthTime, &clientUpdatedNS, &reauthAfter,
		&t.ConsentGranted, &t.Revoked, &t.Consumed, &t.ExpiresAt, &t.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AuthzTransaction{}, ErrNotFound
		}
		return AuthzTransaction{}, err
	}
	t.MaxAge = maxAge
	t.ClientUpdatedAt = time.Unix(0, clientUpdatedNS).UTC()
	if reauthAfter != nil {
		t.ReauthenticateAfter = *reauthAfter
	}
	return t, nil
}

func (p *postgresTx) AuthzTransaction(id string) (AuthzTransaction, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+authzTransactionColumns+` FROM authz_transactions WHERE id = $1`, id)
	return scanAuthzTransaction(row)
}

func (p *postgresTx) ListAuthzTransactions() []AuthzTransaction {
	rows, err := p.tx.Query(p.ctx, `SELECT `+authzTransactionColumns+` FROM authz_transactions ORDER BY created_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []AuthzTransaction
	for rows.Next() {
		t, err := scanAuthzTransaction(rows)
		if err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

func (p *postgresTx) SaveAuthzTransaction(t AuthzTransaction) {
	if p.poisoned() {
		return
	}
	var reauthAfter *time.Time
	if !t.ReauthenticateAfter.IsZero() {
		reauthAfter = &t.ReauthenticateAfter
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO authz_transactions (id, client_id, redirect_uri, scopes, state, response_mode, nonce, code_challenge,
			code_challenge_method, prompt, max_age, login_hint, browser_binding_hash, op_session_id, app_session_id,
			user_id, auth_time, client_updated_at_ns, reauthenticate_after, consent_granted, revoked, consumed, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)
		ON CONFLICT (id) DO UPDATE SET
			client_id=$2, redirect_uri=$3, scopes=$4, state=$5, response_mode=$6, nonce=$7, code_challenge=$8,
			code_challenge_method=$9, prompt=$10, max_age=$11, login_hint=$12, browser_binding_hash=$13,
			op_session_id=$14, app_session_id=$15, user_id=$16, auth_time=$17, client_updated_at_ns=$18,
			reauthenticate_after=$19, consent_granted=$20, revoked=$21, consumed=$22, expires_at=$23`,
		t.ID, t.ClientID, t.RedirectURI, nzs(t.Scopes), t.State, t.ResponseMode, t.Nonce, t.CodeChallenge,
		t.CodeChallengeMethod, nzs(t.Prompt), t.MaxAge, t.LoginHint, t.BrowserBindingHash, t.OPSessionID, t.AppSessionID,
		t.UserID, t.AuthTime, t.ClientUpdatedAt.UnixNano(), reauthAfter, t.ConsentGranted, t.Revoked, t.Consumed, t.ExpiresAt, t.CreatedAt,
	)
	p.fail(err)
}

func (p *postgresTx) DeleteAuthzTransaction(id string) {
	if p.poisoned() {
		return
	}
	_, err := p.tx.Exec(p.ctx, `DELETE FROM authz_transactions WHERE id = $1`, id)
	p.fail(err)
}

// ---- AuthorizationCode ----

const authorizationCodeColumns = `hash, transaction_id, client_id, user_id, redirect_uri, scopes, nonce, auth_time, code_challenge, code_challenge_method, client_updated_at_ns, op_session_id, app_session_id, revoked, consumed, created_at, expires_at, retain_until`

func scanAuthorizationCode(row pgx.Row) (AuthorizationCode, error) {
	var c AuthorizationCode
	var clientUpdatedNS int64
	var createdAt, retainUntil *time.Time
	if err := row.Scan(&c.Hash, &c.TransactionID, &c.ClientID, &c.UserID, &c.RedirectURI, &c.Scopes, &c.Nonce,
		&c.AuthTime, &c.CodeChallenge, &c.CodeChallengeMethod, &clientUpdatedNS, &c.OPSessionID, &c.AppSessionID,
		&c.Revoked, &c.Consumed, &createdAt, &c.ExpiresAt, &retainUntil); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return AuthorizationCode{}, ErrNotFound
		}
		return AuthorizationCode{}, err
	}
	c.ClientUpdatedAt = time.Unix(0, clientUpdatedNS).UTC()
	if createdAt != nil {
		c.CreatedAt = *createdAt
	}
	if retainUntil != nil {
		c.RetainUntil = *retainUntil
	}
	return c, nil
}

func (p *postgresTx) AuthorizationCode(hash string) (AuthorizationCode, error) {
	row := p.tx.QueryRow(p.ctx, `SELECT `+authorizationCodeColumns+` FROM authorization_codes WHERE hash = $1`, hash)
	return scanAuthorizationCode(row)
}

func (p *postgresTx) ListAuthorizationCodes() []AuthorizationCode {
	rows, err := p.tx.Query(p.ctx, `SELECT `+authorizationCodeColumns+` FROM authorization_codes ORDER BY created_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []AuthorizationCode
	for rows.Next() {
		c, err := scanAuthorizationCode(rows)
		if err != nil {
			p.fail(err)
			return nil
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

func (p *postgresTx) SaveAuthorizationCode(c AuthorizationCode) {
	if p.poisoned() {
		return
	}
	var createdAt, retainUntil *time.Time
	if !c.CreatedAt.IsZero() {
		createdAt = &c.CreatedAt
	}
	if !c.RetainUntil.IsZero() {
		retainUntil = &c.RetainUntil
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO authorization_codes (hash, transaction_id, client_id, user_id, redirect_uri, scopes, nonce,
			auth_time, code_challenge, code_challenge_method, client_updated_at_ns, op_session_id, app_session_id,
			revoked, consumed, created_at, expires_at, retain_until)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (hash) DO UPDATE SET
			transaction_id=$2, client_id=$3, user_id=$4, redirect_uri=$5, scopes=$6, nonce=$7, auth_time=$8,
			code_challenge=$9, code_challenge_method=$10, client_updated_at_ns=$11, op_session_id=$12,
			app_session_id=$13, revoked=$14, consumed=$15, expires_at=$17, retain_until=$18`,
		c.Hash, c.TransactionID, c.ClientID, c.UserID, c.RedirectURI, nzs(c.Scopes), c.Nonce, c.AuthTime,
		c.CodeChallenge, c.CodeChallengeMethod, c.ClientUpdatedAt.UnixNano(), c.OPSessionID, c.AppSessionID,
		c.Revoked, c.Consumed, createdAt, c.ExpiresAt, retainUntil,
	)
	p.fail(err)
}

// ---- Consent ----

func (p *postgresTx) Consent(userID, clientID string) (Consent, error) {
	var c Consent
	err := p.tx.QueryRow(p.ctx, `SELECT user_id, client_id, scopes, policy_revision, granted_at, revoked FROM consents WHERE user_id = $1 AND client_id = $2`, userID, clientID).
		Scan(&c.UserID, &c.ClientID, &c.Scopes, &c.PolicyRevision, &c.GrantedAt, &c.Revoked)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Consent{}, ErrNotFound
		}
		return Consent{}, err
	}
	c.ID = consentID(userID, clientID)
	return c, nil
}

func (p *postgresTx) ListConsents() []Consent {
	rows, err := p.tx.Query(p.ctx, `SELECT user_id, client_id, scopes, policy_revision, granted_at, revoked FROM consents ORDER BY granted_at`)
	if err != nil {
		p.fail(err)
		return nil
	}
	defer rows.Close()
	var out []Consent
	for rows.Next() {
		var c Consent
		if err := rows.Scan(&c.UserID, &c.ClientID, &c.Scopes, &c.PolicyRevision, &c.GrantedAt, &c.Revoked); err != nil {
			p.fail(err)
			return nil
		}
		c.ID = consentID(c.UserID, c.ClientID)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		p.fail(err)
	}
	return out
}

// SaveConsent cascades exactly as fileState.SaveConsent: when the saved
// consent is revoked, first end the user's app sessions for this client
// and revoke their refresh families for this client, then persist.
func (p *postgresTx) SaveConsent(c Consent) {
	if p.poisoned() {
		return
	}
	if c.Revoked {
		rows, err := p.tx.Query(p.ctx, `SELECT id FROM app_sessions WHERE user_id = $1 AND client_id = $2 AND ended_at IS NULL`, c.UserID, c.ClientID)
		if err != nil {
			p.fail(err)
			return
		}
		var appIDs []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				p.fail(err)
				return
			}
			appIDs = append(appIDs, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			p.fail(err)
			return
		}
		now := p.now()
		for _, id := range appIDs {
			p.EndAppSession(id, c.UserID, "access_revoked", now)
		}
		if p.poisoned() {
			return
		}
		p.revokeFamiliesMatching(`user_id = $1 AND client_id = $2`, c.UserID, c.ClientID)
		if p.poisoned() {
			return
		}
	}
	_, err := p.tx.Exec(p.ctx, `
		INSERT INTO consents (user_id, client_id, scopes, policy_revision, granted_at, revoked)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (user_id, client_id) DO UPDATE SET scopes=$3, policy_revision=$4, granted_at=$5, revoked=$6`,
		c.UserID, c.ClientID, nzs(c.Scopes), c.PolicyRevision, c.GrantedAt, c.Revoked,
	)
	p.fail(err)
}
