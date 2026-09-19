package oidc

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// randomToken generates a 256-bit, high-entropy opaque value, matching the
// shape identity's own session/client-id/client-secret tokens use.
func randomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken returns the SHA-256 hex digest of an opaque token. Only hashes
// are ever persisted for transactions, codes, and access tokens, mirroring
// how identity.SessionHash protects session tokens at rest.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
