package oidc

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

var (
	ErrClientAuthRequired = errors.New("client authentication required")
	ErrClientAuthInvalid  = errors.New("invalid client credentials")
	ErrClientAuthConflict = errors.New("multiple client authentication methods presented")
	ErrClientAuthLimited  = errors.New("too many client authentication attempts")
)

type presentedClientAuth struct {
	clientID string
	secret   string
	method   string // "client_secret_basic", "client_secret_post", or "none"
}

// extractClientAuth reads exactly one client authentication mechanism from
// a token request. Presenting both HTTP Basic and a client_secret form
// field is rejected outright rather than silently preferring one.
func extractClientAuth(r *http.Request, form url.Values) (presentedClientAuth, error) {
	basicID, basicSecret, hasBasic := r.BasicAuth()
	postSecret := form.Get("client_secret")
	postID := form.Get("client_id")
	if hasBasic && postSecret != "" {
		return presentedClientAuth{}, ErrClientAuthConflict
	}
	if hasBasic {
		return presentedClientAuth{clientID: basicID, secret: basicSecret, method: "client_secret_basic"}, nil
	}
	if postSecret != "" {
		return presentedClientAuth{clientID: postID, secret: postSecret, method: "client_secret_post"}, nil
	}
	if postID == "" {
		return presentedClientAuth{}, ErrClientAuthRequired
	}
	return presentedClientAuth{clientID: postID, method: "none"}, nil
}

// authenticateClient enforces the client's registered token_endpoint_auth_method
// exactly: the presented mechanism must match, secrets are compared in
// constant time, and repeated failures for one client_id are rate-limited.
func (s *Service) authenticateClient(r *http.Request, form url.Values) (identity.ProtocolClient, error) {
	presented, err := extractClientAuth(r, form)
	if err != nil {
		return identity.ProtocolClient{}, err
	}
	if presented.clientID == "" {
		return identity.ProtocolClient{}, ErrClientAuthInvalid
	}
	if !s.clientAuthLimiter.allow(presented.clientID) {
		return identity.ProtocolClient{}, ErrClientAuthLimited
	}
	client, err := s.Identity.ProtocolClient(r.Context(), presented.clientID)
	if err != nil || !client.Compatible || client.TokenEndpointAuthMethod != presented.method {
		return identity.ProtocolClient{}, ErrClientAuthInvalid
	}
	if presented.method != "none" {
		if subtle.ConstantTimeCompare([]byte(client.Secret), []byte(presented.secret)) != 1 || client.Secret == "" {
			return identity.ProtocolClient{}, ErrClientAuthInvalid
		}
	}
	return client, nil
}

// clientAuthLimiter caps repeated client authentication attempts per
// client_id, mirroring internal/api/auth.go's loginLimiter shape. It's
// duplicated rather than shared to avoid making internal/oidc depend on
// internal/api.
type clientAuthLimiter struct {
	mu      sync.Mutex
	entries map[string]clientAuthLimitEntry
}
type clientAuthLimitEntry struct {
	count   int
	expires time.Time
}

func newClientAuthLimiter() *clientAuthLimiter {
	return &clientAuthLimiter{entries: map[string]clientAuthLimitEntry{}}
}
func (l *clientAuthLimiter) allow(clientID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for k, e := range l.entries {
		if !e.expires.After(now) {
			delete(l.entries, k)
		}
	}
	e, exists := l.entries[clientID]
	if e.count >= 30 {
		return false
	}
	if !exists && len(l.entries) >= 10000 {
		return false
	}
	if e.count == 0 {
		e.expires = now.Add(15 * time.Minute)
	}
	e.count++
	l.entries[clientID] = e
	return true
}
