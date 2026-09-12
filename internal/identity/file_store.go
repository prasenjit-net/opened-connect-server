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

type FileStore struct{ path string }
type fileState struct {
	Version  int                `json:"version"`
	UsersMap map[string]User    `json:"users"`
	Sessions map[string]Session `json:"sessions"`
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
	state := fileState{Version: 1, UsersMap: map[string]User{}, Sessions: map[string]Session{}}
	content, err := os.ReadFile(s.path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read identities: %w", err)
	}
	if err == nil {
		state = fileState{}
		if err = json.Unmarshal(content, &state); err != nil {
			return fmt.Errorf("invalid identity store: %w", err)
		}
		if state.Version != 1 || state.UsersMap == nil || state.Sessions == nil {
			return fmt.Errorf("unsupported or invalid identity store")
		}
		if err = os.Chmod(s.path, 0600); err != nil {
			return err
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if err = fn(&state); err != nil {
		return err
	}
	if !write {
		return nil
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
	return u, nil
}
func (s *fileState) UserByEmail(email string) (User, error) {
	for _, u := range s.UsersMap {
		if strings.EqualFold(u.Email, email) {
			return u, nil
		}
	}
	return User{}, ErrNotFound
}
func (s *fileState) Users() []User {
	result := make([]User, 0, len(s.UsersMap))
	for _, u := range s.UsersMap {
		result = append(result, u)
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
	s.UsersMap[user.ID] = user
	return nil
}
func (s *fileState) DeleteUser(id string)        { delete(s.UsersMap, id); s.DeleteUserSessions(id) }
func (s *fileState) SaveSession(session Session) { s.Sessions[session.Hash] = session }
func (s *fileState) DeleteSession(hash string)   { delete(s.Sessions, hash) }
func (s *fileState) DeleteUserSessions(id string) {
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
