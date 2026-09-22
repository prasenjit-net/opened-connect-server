package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
)

// executeSerializedState applies the existing Store callback semantics to a
// versioned state document. Database adapters lock this document inside their
// native transaction before calling this function, so the domain rules remain
// identical to FileStore while the physical representation evolves.
func executeSerializedState(ctx context.Context, content []byte, write bool, secrets *FileStore, fn func(*fileState) error) ([]byte, error) {
	state := freshFileState()
	if len(content) != 0 {
		state = fileState{}
		if err := json.Unmarshal(content, &state); err != nil {
			return nil, fmt.Errorf("invalid identity store: %w", err)
		}
		if state.UsersMap == nil || state.Sessions == nil {
			return nil, fmt.Errorf("unsupported or invalid identity store")
		}
		if state.Version < 1 || state.Version > currentVersion {
			return nil, fmt.Errorf("unsupported or invalid identity store")
		}
		state.Version = currentVersion
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
	}
	for key, token := range state.AccessTokens {
		if token.GrantType == "" && token.UserID != "" && token.Audience == "userinfo" {
			token.GrantType = "authorization_code"
			token.SubjectKind = "user"
			state.AccessTokens[key] = token
		}
	}
	if err := secrets.transformClientSecrets(&state, false); err != nil {
		return nil, err
	}
	for hash, session := range state.Sessions {
		if session.ID == "" {
			session.ID = activityID("legacy-session", hash)
			session.CreatedAt = session.AuthTime
			state.Sessions[hash] = session
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := fn(&state); err != nil {
		return nil, err
	}
	if !write {
		return nil, nil
	}
	if err := secrets.transformClientSecrets(&state, true); err != nil {
		return nil, err
	}
	state.Version = currentVersion
	return json.Marshal(state)
}

func databaseSecretStore(dataDir, backend string) (*FileStore, error) {
	// The sidecar only protects client secrets and never stores identity state.
	_ = backend
	return NewFileStore(filepath.Join(dataDir, ".secret-protector"))
}
