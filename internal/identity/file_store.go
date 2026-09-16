package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

const currentVersion = 2

type FileStore struct{ path string }
type fileState struct {
	ClientsMap         map[string]ClientRecord      `json:"clients,omitempty"`
	Version            int                          `json:"version"`
	UsersMap           map[string]User              `json:"users"`
	Sessions           map[string]Session           `json:"sessions"`
	AuthzTransactions  map[string]AuthzTransaction  `json:"authzTransactions,omitempty"`
	AuthorizationCodes map[string]AuthorizationCode `json:"authorizationCodes,omitempty"`
	AccessTokens       map[string]AccessToken       `json:"accessTokens,omitempty"`
	Consents           map[string]Consent           `json:"consents,omitempty"`
}

func NewFileStore(dir string) (*FileStore, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("data directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(abs, 0700); err != nil {
		return nil, err
	}
	if err = os.Chmod(abs, 0700); err != nil {
		return nil, err
	}
	return &FileStore{path: filepath.Join(abs, "identity.json")}, nil
}

func (s *FileStore) Read(ctx context.Context, fn func(ReadTx) error) error {
	return s.withState(ctx, false, func(tx *fileState) error { return fn(tx) })
}
func (s *FileStore) Write(ctx context.Context, fn func(Tx) error) error {
	return s.withState(ctx, true, func(tx *fileState) error { return fn(tx) })
}

func freshFileState() fileState {
	return fileState{
		Version:            currentVersion,
		UsersMap:           map[string]User{},
		Sessions:           map[string]Session{},
		AuthzTransactions:  map[string]AuthzTransaction{},
		AuthorizationCodes: map[string]AuthorizationCode{},
		AccessTokens:       map[string]AccessToken{},
		Consents:           map[string]Consent{},
	}
}

func (s *FileStore) withState(ctx context.Context, write bool, fn func(*fileState) error) error {
	// Use a fresh descriptor per transaction so independent instances (including
	// the init CLI) cannot race one another or bypass a shared in-process lock.
	lock := flock.New(s.path + ".lock")
	defer lock.Close()
	ok, err := lock.TryLockContext(ctx, 10*time.Millisecond)
	if err != nil {
		return err
	}
	if !ok {
		return ctx.Err()
	}
	defer lock.Unlock()
	state := freshFileState()
	content, err := os.ReadFile(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read identities: %w", err)
	}
	if err == nil {
		state = fileState{}
		if err = json.Unmarshal(content, &state); err != nil {
			return fmt.Errorf("invalid identity store: %w", err)
		}
		if state.UsersMap == nil || state.Sessions == nil {
			return fmt.Errorf("unsupported or invalid identity store")
		}
		switch state.Version {
		case 1:
			// No data-shape change for the OIDC record maps added in version 2;
			// they simply start empty below.
			state.Version = 2
		case currentVersion:
			// current
		default:
			return fmt.Errorf("unsupported or invalid identity store")
		}
		if state.AuthzTransactions == nil {
			state.AuthzTransactions = map[string]AuthzTransaction{}
		}
		if state.AuthorizationCodes == nil {
			state.AuthorizationCodes = map[string]AuthorizationCode{}
		}
		if state.AccessTokens == nil {
			state.AccessTokens = map[string]AccessToken{}
		}
		if state.Consents == nil {
			state.Consents = map[string]Consent{}
		}
		if err = os.Chmod(s.path, 0600); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = s.transformClientSecrets(&state, false); err != nil {
		return err
	}
	if err = fn(&state); err != nil {
		return err
	}
	if !write {
		return nil
	}
	if err = s.transformClientSecrets(&state, true); err != nil {
		return err
	}
	content, err = json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".identity-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err = tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(name, s.path); err != nil {
		return err
	}
	return nil
}

func (s *fileState) User(id string) (User, error) {
	u, ok := s.UsersMap[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return cloneUser(u), nil
}
func (s *fileState) UserByEmail(email string) (User, error) {
	for _, u := range s.UsersMap {
		if strings.EqualFold(u.Email, email) {
			return cloneUser(u), nil
		}
	}
	return User{}, ErrNotFound
}
func (s *fileState) Users() []User {
	result := make([]User, 0, len(s.UsersMap))
	for _, u := range s.UsersMap {
		result = append(result, cloneUser(u))
	}
	return result
}
func (s *fileState) Session(hash string) (Session, error) {
	v, ok := s.Sessions[hash]
	if !ok {
		return Session{}, ErrNotFound
	}
	return v, nil
}
func (s *fileState) SaveUser(user User) error {
	for _, u := range s.UsersMap {
		if u.ID != user.ID && strings.EqualFold(u.Email, user.Email) {
			return ErrConflict
		}
	}
	if old, ok := s.UsersMap[user.ID]; ok && (old.PasswordHash != user.PasswordHash || old.Email != user.Email || old.Role != user.Role || old.Active != user.Active) {
		s.DeleteUserSessions(user.ID)
	}
	s.UsersMap[user.ID] = cloneUser(user)
	return nil
}
func (s *fileState) DeleteUser(id string)        { delete(s.UsersMap, id); s.DeleteUserSessions(id) }
func (s *fileState) SaveSession(session Session) { s.Sessions[session.Hash] = session }
func (s *fileState) DeleteSession(hash string)   { delete(s.Sessions, hash) }
func (s *fileState) DeleteUserSessions(id string) {
	s.RevokeAccessTokensForUser(id)
	for k, c := range s.AuthorizationCodes {
		if c.UserID == id {
			delete(s.AuthorizationCodes, k)
		}
	}
	for k, t := range s.AuthzTransactions {
		if t.UserID == id {
			delete(s.AuthzTransactions, k)
		}
	}
	for k, c := range s.Consents {
		if c.UserID == id {
			delete(s.Consents, k)
		}
	}
	for k, sess := range s.Sessions {
		if sess.UserID == id {
			delete(s.Sessions, k)
		}
	}
}
func (s *fileState) PruneSessions(now time.Time) {
	for k, sess := range s.Sessions {
		if !sess.ExpiresAt.After(now) {
			delete(s.Sessions, k)
		}
	}
}

func (s *fileState) Client(id string) (ClientRecord, error) {
	c, ok := s.ClientsMap[id]
	if !ok {
		return ClientRecord{}, ErrNotFound
	}
	return cloneClient(c), nil
}
func (s *fileState) Clients() []ClientRecord {
	result := make([]ClientRecord, 0, len(s.ClientsMap))
	for _, c := range s.ClientsMap {
		result = append(result, cloneClient(c))
	}
	return result
}
func (s *fileState) SaveClient(c ClientRecord) {
	if s.ClientsMap == nil {
		s.ClientsMap = map[string]ClientRecord{}
	}
	if old, ok := s.ClientsMap[c.ID]; ok {
		if !c.UpdatedAt.After(old.UpdatedAt) {
			c.UpdatedAt = old.UpdatedAt.Add(time.Nanosecond)
		}
		s.invalidateClientGrants(c.ID)
	}
	s.ClientsMap[c.ID] = cloneClient(c)
}
func (s *fileState) DeleteClient(id string) { s.invalidateClientGrants(id); delete(s.ClientsMap, id) }
func (s *fileState) invalidateClientGrants(id string) {
	s.RevokeAccessTokensForClient(id)
	for k, c := range s.AuthorizationCodes {
		if c.ClientID == id {
			delete(s.AuthorizationCodes, k)
		}
	}
	for k, t := range s.AuthzTransactions {
		if t.ClientID == id {
			delete(s.AuthzTransactions, k)
		}
	}
	for k, c := range s.Consents {
		if c.ClientID == id {
			delete(s.Consents, k)
		}
	}
}

func (s *fileState) AuthzTransaction(id string) (AuthzTransaction, error) {
	t, ok := s.AuthzTransactions[id]
	if !ok {
		return AuthzTransaction{}, ErrNotFound
	}
	return cloneAuthzTransaction(t), nil
}
func (s *fileState) SaveAuthzTransaction(t AuthzTransaction) {
	if s.AuthzTransactions == nil {
		s.AuthzTransactions = map[string]AuthzTransaction{}
	}
	s.AuthzTransactions[t.ID] = cloneAuthzTransaction(t)
}
func (s *fileState) DeleteAuthzTransaction(id string) { delete(s.AuthzTransactions, id) }

func (s *fileState) AuthorizationCode(hash string) (AuthorizationCode, error) {
	c, ok := s.AuthorizationCodes[hash]
	if !ok {
		return AuthorizationCode{}, ErrNotFound
	}
	return cloneAuthorizationCode(c), nil
}
func (s *fileState) SaveAuthorizationCode(c AuthorizationCode) {
	if s.AuthorizationCodes == nil {
		s.AuthorizationCodes = map[string]AuthorizationCode{}
	}
	s.AuthorizationCodes[c.Hash] = cloneAuthorizationCode(c)
}

func (s *fileState) AccessToken(hash string) (AccessToken, error) {
	a, ok := s.AccessTokens[hash]
	if !ok {
		return AccessToken{}, ErrNotFound
	}
	return cloneAccessToken(a), nil
}
func (s *fileState) SaveAccessToken(a AccessToken) {
	if s.AccessTokens == nil {
		s.AccessTokens = map[string]AccessToken{}
	}
	s.AccessTokens[a.Hash] = cloneAccessToken(a)
}
func (s *fileState) RevokeAccessToken(hash string) {
	if a, ok := s.AccessTokens[hash]; ok {
		a.Revoked = true
		s.AccessTokens[hash] = a
	}
}
func (s *fileState) RevokeAccessTokensForUser(userID string) {
	for hash, a := range s.AccessTokens {
		if a.UserID == userID {
			a.Revoked = true
			s.AccessTokens[hash] = a
		}
	}
}
func (s *fileState) RevokeAccessTokensForClient(clientID string) {
	for hash, a := range s.AccessTokens {
		if a.ClientID == clientID {
			a.Revoked = true
			s.AccessTokens[hash] = a
		}
	}
}
func (s *fileState) RevokeAccessTokensForCode(codeHash string) {
	for hash, a := range s.AccessTokens {
		if a.CodeHash == codeHash {
			a.Revoked = true
			s.AccessTokens[hash] = a
		}
	}
}

func (s *fileState) Consent(userID, clientID string) (Consent, error) {
	c, ok := s.Consents[consentID(userID, clientID)]
	if !ok {
		return Consent{}, ErrNotFound
	}
	return cloneConsent(c), nil
}
func (s *fileState) SaveConsent(c Consent) {
	if s.Consents == nil {
		s.Consents = map[string]Consent{}
	}
	if c.ID == "" {
		c.ID = consentID(c.UserID, c.ClientID)
	}
	s.Consents[c.ID] = cloneConsent(c)
}

// PruneOIDCState deletes expired authorization transactions, expired
// unused codes, consumed codes past their token retention deadline, and expired
// access tokens. It mirrors PruneSessions
// and is called opportunistically from write paths that touch this state.
func (s *fileState) PruneOIDCState(now time.Time) {
	for k, t := range s.AuthzTransactions {
		if !t.ExpiresAt.After(now) {
			delete(s.AuthzTransactions, k)
		}
	}
	for k, c := range s.AuthorizationCodes {
		if !c.ExpiresAt.After(now) && !c.RetainUntil.After(now) {
			delete(s.AuthorizationCodes, k)
		}
	}
	for k, a := range s.AccessTokens {
		if !a.ExpiresAt.After(now) {
			delete(s.AccessTokens, k)
		}
	}
}

func (s *fileState) ListAuthzTransactions() []AuthzTransaction {
	out := make([]AuthzTransaction, 0, len(s.AuthzTransactions))
	for _, v := range s.AuthzTransactions {
		out = append(out, cloneAuthzTransaction(v))
	}
	return out
}
func (s *fileState) ListAuthorizationCodes() []AuthorizationCode {
	out := make([]AuthorizationCode, 0, len(s.AuthorizationCodes))
	for _, v := range s.AuthorizationCodes {
		out = append(out, cloneAuthorizationCode(v))
	}
	return out
}
func (s *fileState) ListAccessTokens() []AccessToken {
	out := make([]AccessToken, 0, len(s.AccessTokens))
	for _, v := range s.AccessTokens {
		out = append(out, cloneAccessToken(v))
	}
	return out
}
func (s *fileState) ListConsents() []Consent {
	out := make([]Consent, 0, len(s.Consents))
	for _, v := range s.Consents {
		out = append(out, cloneConsent(v))
	}
	return out
}
