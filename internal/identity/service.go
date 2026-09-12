package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/mail"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

type Service struct {
	store     Store
	ttl       time.Duration
	dummyHash string
	now       func() time.Time
}
type Principal struct {
	User    Profile
	Session Session
}
type LoginResult struct {
	Principal
	Token string
}
type UserInput struct {
	*Claims
	EmailVerified       bool   `json:"email_verified"`
	PhoneNumberVerified bool   `json:"phone_number_verified"`
	Name                string `json:"name"`
	Email               string `json:"email"`
	Role                Role   `json:"role"`
	Active              bool   `json:"active"`
}
type ListOptions struct {
	Query    string
	Role     Role
	Status   string
	Page     int
	PageSize int
}
type UserList struct {
	Users    []Profile `json:"users"`
	Total    int       `json:"total"`
	Page     int       `json:"page"`
	PageSize int       `json:"pageSize"`
}

func NewService(store Store, ttl time.Duration) (*Service, error) {
	dummy, err := randomToken()
	if err != nil {
		return nil, err
	}
	hash, err := HashPassword(dummy)
	if err != nil {
		return nil, err
	}
	return &Service{store: store, ttl: ttl, dummyHash: hash, now: time.Now}, nil
}
func SessionHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func normalize(input UserInput) (UserInput, error) {
	if input.PhoneNumberVerified && (input.Claims == nil || strings.TrimSpace(input.PhoneNumber) == "") {
		return input, ValidationError("A phone number is required before it can be marked verified.")
	}
	if err := validateClaims(input.Claims); err != nil {
		return input, err
	}
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.Name = strings.TrimSpace(input.Name)
	address, err := mail.ParseAddress(input.Email)
	if err != nil || address.Address != input.Email || len(input.Email) > 254 {
		return input, ValidationError("Enter a valid email address.")
	}
	if !utf8.ValidString(input.Name) || utf8.RuneCountInString(input.Name) < 1 || utf8.RuneCountInString(input.Name) > 100 {
		return input, ValidationError("Name must contain 1–100 characters.")
	}
	if input.Role != RoleUser && input.Role != RoleAdmin {
		return input, ValidationError("Role must be user or admin.")
	}
	return input, nil
}
func (s *Service) buildUser(input UserInput, password string) (User, error) {
	input, err := normalize(input)
	if err != nil {
		return User{}, err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return User{}, err
	}
	id, err := randomToken()
	if err != nil {
		return User{}, err
	}
	now := s.now().UTC()
	claims := Claims{}
	if input.Claims != nil {
		claims = *input.Claims
	}
	return cloneUser(User{Profile: Profile{Claims: claims, EmailVerified: input.EmailVerified, PhoneNumberVerified: input.PhoneNumberVerified, ID: id, Name: input.Name, Email: input.Email, Role: input.Role, Active: input.Active, CreatedAt: now, UpdatedAt: now}, PasswordHash: hash}), nil
}

func (s *Service) Bootstrap(ctx context.Context, name, email, password string) (Profile, error) {
	user, err := s.buildUser(UserInput{Name: name, Email: email, Role: RoleAdmin, Active: true}, password)
	if err != nil {
		return Profile{}, err
	}
	err = s.store.Write(ctx, func(tx Tx) error {
		if len(tx.Users()) != 0 {
			return ErrInitialized
		}
		return tx.SaveUser(user)
	})
	return user.Profile, err
}
func (s *Service) Initialized(ctx context.Context) (bool, error) {
	var yes bool
	err := s.store.Read(ctx, func(tx ReadTx) error { yes = len(tx.Users()) > 0; return nil })
	return yes, err
}

func (s *Service) principal(tx ReadTx, hash string, admin bool) (Principal, error) {
	sess, err := tx.Session(hash)
	if err != nil || !sess.ExpiresAt.After(s.now()) {
		return Principal{}, ErrUnauthorized
	}
	user, err := tx.User(sess.UserID)
	if err != nil || !user.Active {
		return Principal{}, ErrUnauthorized
	}
	if admin && user.Role != RoleAdmin {
		return Principal{}, ErrForbidden
	}
	return Principal{User: user.Profile, Session: sess}, nil
}
func (s *Service) Authenticate(ctx context.Context, hash string) (Principal, error) {
	var p Principal
	err := s.store.Read(ctx, func(tx ReadTx) error { var err error; p, err = s.principal(tx, hash, false); return err })
	return p, err
}
func (s *Service) Login(ctx context.Context, email, password, oldHash string) (LoginResult, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	var found User
	err := s.store.Read(ctx, func(tx ReadTx) error { var err error; found, err = tx.UserByEmail(email); return err })
	if err != nil && !errors.Is(err, ErrNotFound) {
		return LoginResult{}, err
	}
	hash := found.PasswordHash
	if err != nil {
		hash = s.dummyHash
	}
	if !VerifyPassword(hash, password) || err != nil || !found.Active {
		return LoginResult{}, ErrCredentials
	}
	token, err := randomToken()
	if err != nil {
		return LoginResult{}, err
	}
	csrf, err := randomToken()
	if err != nil {
		return LoginResult{}, err
	}
	result := LoginResult{Token: token, Principal: Principal{User: found.Profile, Session: Session{Hash: SessionHash(token), UserID: found.ID, CSRF: csrf, ExpiresAt: s.now().UTC().Add(s.ttl)}}}
	err = s.store.Write(ctx, func(tx Tx) error {
		current, err := tx.User(found.ID)
		if err != nil || !current.Active || current.PasswordHash != found.PasswordHash || current.Email != found.Email {
			return ErrCredentials
		}
		result.User = current.Profile
		tx.PruneSessions(s.now())
		tx.DeleteSession(oldHash)
		tx.SaveSession(result.Session)
		return nil
	})
	return result, err
}
func (s *Service) Logout(ctx context.Context, hash string) error {
	return s.store.Write(ctx, func(tx Tx) error { tx.DeleteSession(hash); return nil })
}

func (s *Service) GetUser(ctx context.Context, hash, id string) (Profile, error) {
	var result Profile
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		user, err := tx.User(id)
		if err != nil {
			return err
		}
		result = user.Profile
		return nil
	})
	return result, err
}
func (s *Service) ListUsers(ctx context.Context, hash string, opts ListOptions) (UserList, error) {
	if opts.Page < 1 {
		opts.Page = 1
	}
	if opts.PageSize < 1 || opts.PageSize > 100 {
		opts.PageSize = 10
	}
	if opts.Role != "" && opts.Role != RoleAdmin && opts.Role != RoleUser {
		return UserList{}, ValidationError("Invalid role filter.")
	}
	if opts.Status != "" && opts.Status != "active" && opts.Status != "disabled" {
		return UserList{}, ValidationError("Invalid status filter.")
	}
	result := UserList{Users: []Profile{}, Page: opts.Page, PageSize: opts.PageSize}
	q := strings.ToLower(strings.TrimSpace(opts.Query))
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		for _, u := range tx.Users() {
			if q != "" && !strings.Contains(strings.ToLower(u.Name+" "+u.Email), q) {
				continue
			}
			if opts.Role != "" && u.Role != opts.Role {
				continue
			}
			if opts.Status == "active" && !u.Active || opts.Status == "disabled" && u.Active {
				continue
			}
			result.Users = append(result.Users, u.Profile)
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	sort.Slice(result.Users, func(i, j int) bool {
		a, b := result.Users[i], result.Users[j]
		if a.CreatedAt.Equal(b.CreatedAt) {
			return a.ID < b.ID
		}
		return a.CreatedAt.After(b.CreatedAt)
	})
	result.Total = len(result.Users)
	// Bound page before multiplication to avoid overflow from untrusted input.
	maxPage := (result.Total + opts.PageSize - 1) / opts.PageSize
	if maxPage < 1 {
		maxPage = 1
	}
	if result.Page > maxPage {
		result.Page = maxPage
	}
	start := (result.Page - 1) * opts.PageSize
	end := start + opts.PageSize
	if end > result.Total {
		end = result.Total
	}
	result.Users = result.Users[start:end]
	return result, nil
}
func (s *Service) CreateUser(ctx context.Context, hash string, input UserInput, password string) (Profile, error) {
	// Check permissions before doing expensive password hashing.
	p, err := s.Authenticate(ctx, hash)
	if err != nil {
		return Profile{}, err
	}
	if p.User.Role != RoleAdmin {
		return Profile{}, ErrForbidden
	}
	if input.Role == "" {
		input.Role = RoleUser
	}
	input.Active = true
	user, err := s.buildUser(input, password)
	if err != nil {
		return Profile{}, err
	}
	err = s.store.Write(ctx, func(tx Tx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		return tx.SaveUser(user)
	})
	return user.Profile, err
}
func lastAdmin(tx ReadTx, user User) bool {
	if user.Role != RoleAdmin || !user.Active {
		return false
	}
	for _, other := range tx.Users() {
		if other.ID != user.ID && other.Role == RoleAdmin && other.Active {
			return false
		}
	}
	return true
}
func (s *Service) UpdateUser(ctx context.Context, hash, id string, input UserInput) (Profile, error) {
	input, err := normalize(input)
	if err != nil {
		return Profile{}, err
	}
	var result Profile
	err = s.store.Write(ctx, func(tx Tx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		user, err := tx.User(id)
		if err != nil {
			return err
		}
		if (!input.Active || input.Role != RoleAdmin) && lastAdmin(tx, user) {
			return ErrLastAdmin
		}
		if user.Role != input.Role || user.Active != input.Active || user.Email != input.Email {
			tx.DeleteUserSessions(id)
		}
		if input.Claims != nil {
			user.Claims = *input.Claims
		}
		user.EmailVerified = input.EmailVerified
		user.PhoneNumberVerified = input.PhoneNumberVerified
		user.Name = input.Name
		user.Email = input.Email
		user.Role = input.Role
		user.Active = input.Active
		user.UpdatedAt = s.now().UTC()
		user = cloneUser(user)
		if err = tx.SaveUser(user); err != nil {
			return err
		}
		result = user.Profile
		return nil
	})
	return result, err
}
func (s *Service) DeleteUser(ctx context.Context, hash, id string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		user, err := tx.User(id)
		if err != nil {
			return err
		}
		if lastAdmin(tx, user) {
			return ErrLastAdmin
		}
		tx.DeleteUser(id)
		return nil
	})
}
func (s *Service) UpdateProfile(ctx context.Context, hash string, input ProfileInput) (Profile, error) {
	if err := validateClaims(input.Claims); err != nil {
		return Profile{}, err
	}
	var result Profile
	err := s.store.Write(ctx, func(tx Tx) error {
		p, err := s.principal(tx, hash, false)
		if err != nil {
			return err
		}
		u, err := tx.User(p.User.ID)
		if err != nil {
			return err
		}
		email := u.Email
		if input.Email != nil {
			email = *input.Email
		}
		normalized, err := normalize(UserInput{Name: input.Name, Email: email, Role: u.Role, Active: u.Active})
		if err != nil {
			return err
		}
		if normalized.Email != u.Email {
			u.EmailVerified = false
		}
		if input.Claims != nil {
			if input.PhoneNumber != u.PhoneNumber {
				u.PhoneNumberVerified = false
			}
			u.Claims = *input.Claims
		}
		u.Name = normalized.Name
		u.Email = normalized.Email
		u.UpdatedAt = s.now().UTC()
		u = cloneUser(u)
		if err = tx.SaveUser(u); err != nil {
			return err
		}
		result = u.Profile
		return nil
	})
	return result, err
}
func (s *Service) ChangePassword(ctx context.Context, hash, current, password string) error {
	var original User
	err := s.store.Read(ctx, func(tx ReadTx) error {
		p, err := s.principal(tx, hash, false)
		if err != nil {
			return err
		}
		original, err = tx.User(p.User.ID)
		return err
	})
	if err != nil {
		return err
	}
	if !VerifyPassword(original.PasswordHash, current) {
		return ValidationError("Current password is incorrect.")
	}
	if current == password {
		return ValidationError("Choose a different password.")
	}
	encoded, err := HashPassword(password)
	if err != nil {
		return err
	}
	return s.store.Write(ctx, func(tx Tx) error {
		p, err := s.principal(tx, hash, false)
		if err != nil {
			return err
		}
		u, err := tx.User(p.User.ID)
		if err != nil {
			return err
		}
		if u.PasswordHash != original.PasswordHash {
			return ErrUnauthorized
		}
		u.PasswordHash = encoded
		u.UpdatedAt = s.now().UTC()
		if err = tx.SaveUser(u); err != nil {
			return err
		}
		tx.DeleteUserSessions(u.ID)
		return nil
	})
}
