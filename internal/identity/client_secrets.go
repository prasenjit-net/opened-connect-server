package identity

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// Runs under the store's cross-process lock. The local encryption key is separate
// from identity.json; database adapters can use their own secret protection.
func (s *FileStore) transformClientSecrets(state *fileState, encrypt bool) error {
	needed := false
	for _, c := range state.ClientsMap {
		if c.Secret != "" {
			needed = true
			break
		}
	}
	if !needed {
		return nil
	}
	path := filepath.Join(filepath.Dir(s.path), "client-secrets.key")
	key, err := os.ReadFile(path)
	if os.IsNotExist(err) && encrypt {
		key = make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return err
		}
		f, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return e
		}
		_, err = f.Write(key)
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	} else if err != nil {
		return fmt.Errorf("read client encryption key: %w", err)
	}
	if len(key) != 32 {
		return fmt.Errorf("invalid client encryption key")
	}
	if err := os.Chmod(path, 0600); err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	for id, c := range state.ClientsMap {
		if c.Secret == "" {
			continue
		}
		if encrypt {
			nonce := make([]byte, gcm.NonceSize())
			if _, err := rand.Read(nonce); err != nil {
				return err
			}
			c.Secret = base64.RawStdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(c.Secret), []byte(id)))
		} else {
			data, err := base64.RawStdEncoding.DecodeString(c.Secret)
			if err != nil || len(data) < gcm.NonceSize() {
				return fmt.Errorf("invalid encrypted client secret")
			}
			plain, err := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte(id))
			if err != nil {
				return fmt.Errorf("decrypt client secret: %w", err)
			}
			c.Secret = string(plain)
		}
		state.ClientsMap[id] = c
	}
	return nil
}
