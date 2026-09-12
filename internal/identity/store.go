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
}

// ReadTx values are snapshots; callers cannot mutate stored records through them.
type ReadTx interface {
	Client(id string) (ClientRecord, error)
	Clients() []ClientRecord
	User(id string) (User, error)
	UserByEmail(email string) (User, error)
	Users() []User
	Session(hash string) (Session, error)
}

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
}

// Store callbacks execute atomically. Write must roll back all changes when the
// callback returns an error. Callbacks must not call back into Store.
type Store interface {
	Read(context.Context, func(ReadTx) error) error
	Write(context.Context, func(Tx) error) error
}
