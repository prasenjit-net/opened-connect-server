package identity

import "path/filepath"

func databaseSecretStore(dataDir, backend string) (*FileStore, error) {
	// The sidecar only protects client secrets and never stores identity state.
	_ = backend
	return NewFileStore(filepath.Join(dataDir, ".secret-protector"))
}
