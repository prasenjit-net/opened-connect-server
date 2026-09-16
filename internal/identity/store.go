// Package identity defines the identity domain and its transactional storage
// boundary. A database adapter can implement Store without changing HTTP or UI code.
package identity

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound     = errors.New("record not found")
	ErrConflict     = errors.New("email address is already in use")
	ErrUnauthorized = errors.New("sign in required")
	ErrForbidden    = errors.New("administrator access required")
	ErrCredentials  = errors.New("invalid email or password")
	ErrLastAdmin    = errors.New("at least one active administrator must remain")
	ErrInitialized  = errors.New("identity storage is already initialized")
)

// SessionCookieName is the browser session cookie's name, shared by the
// management API (internal/api) and the OpenID Connect protocol endpoints
// (internal/oidc) so both recognize the same signed-in browser session.
const SessionCookieName = "ocs_session"

type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
)

type Profile struct {
	Claims
	Sub                 string    `json:"sub"`
	ClaimUpdatedAt      int64     `json:"updated_at"`
	EmailVerified       bool      `json:"email_verified"`
	PhoneNumberVerified bool      `json:"phone_number_verified"`
	ID                  string    `json:"id"`
	Email               string    `json:"email"`
	Name                string    `json:"name"`
	Role                Role      `json:"role"`
	Active              bool      `json:"active"`
	CreatedAt           time.Time `json:"createdAt"`
	UpdatedAt           time.Time `json:"updatedAt"`
}

type User struct {
	Profile
	PasswordHash string `json:"passwordHash"`
}

type Session struct {
	Hash      string    `json:"hash"`
	UserID    string    `json:"userId"`
	CSRF      string    `json:"csrf"`
	ExpiresAt time.Time `json:"expiresAt"`
	// AuthTime is when the credential check that created this session
	// succeeded. It is the authentication-timestamp evidence OpenID Connect's
	// auth_time claim and max_age freshness checks require. Sessions from
	// before this field existed decode with a zero value, which is always
	// treated as stale by freshness checks, forcing reauthentication.
	AuthTime time.Time `json:"authTime,omitempty"`
}

// ReadTx values are snapshots; callers cannot mutate stored records through them.
type ReadTx interface {
	ListAuthzTransactions() []AuthzTransaction
	ListAuthorizationCodes() []AuthorizationCode
	ListAccessTokens() []AccessToken
	ListConsents() []Consent
	Client(id string) (ClientRecord, error)
	Clients() []ClientRecord
	User(id string) (User, error)
	UserByEmail(email string) (User, error)
	Users() []User
	Session(hash string) (Session, error)
	AuthzTransaction(id string) (AuthzTransaction, error)
	AuthorizationCode(hash string) (AuthorizationCode, error)
	AccessToken(hash string) (AccessToken, error)
	Consent(userID, clientID string) (Consent, error)
}

// Security mutations must invalidate protocol grants atomically: SaveClient and
// DeleteClient invalidate the client's codes, transactions, consent and tokens.
// SaveUser on password/email/role/active changes, DeleteUser and
// DeleteUserSessions invalidate the user's same protocol state as well as sessions.
// SaveClient must advance UpdatedAt monotonically, even with an unchanged clock.
type Tx interface {
	SaveClient(ClientRecord)
	DeleteClient(id string)
	ReadTx
	SaveUser(User) error
	DeleteUser(id string)
	SaveSession(Session)
	DeleteSession(hash string)
	DeleteUserSessions(userID string)
	PruneSessions(now time.Time)
	SaveAuthzTransaction(AuthzTransaction)
	DeleteAuthzTransaction(id string)
	SaveAuthorizationCode(AuthorizationCode)
	SaveAccessToken(AccessToken)
	RevokeAccessToken(hash string)
	RevokeAccessTokensForUser(userID string)
	RevokeAccessTokensForClient(clientID string)
	RevokeAccessTokensForCode(codeHash string)
	SaveConsent(Consent)
	PruneOIDCState(now time.Time)
}

// Store callbacks execute atomically. Write must roll back all changes when the
// callback returns an error. Callbacks must not call back into Store.
type Store interface {
	Read(context.Context, func(ReadTx) error) error
	Write(context.Context, func(Tx) error) error
}
