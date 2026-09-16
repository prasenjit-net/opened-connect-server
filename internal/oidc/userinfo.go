package oidc

import (
	"encoding/json"
	"net/http"
	"slices"
	"strings"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return ""
	}
	return strings.TrimSpace(auth[len(prefix):])
}

// UserInfoHandler implements GET/POST /userinfo. Only a Bearer access token
// issued for this resource with the openid scope is accepted; browser
// session cookies and ID tokens are never credentials here, and eligibility
// (token revocation/expiry, account status) is re-checked on every call.
func (s *Service) UserInfoHandler(w http.ResponseWriter, r *http.Request) {
	token := bearerToken(r)
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "A bearer access token is required.")
		return
	}
	hash := hashToken(token)
	var (
		found   bool
		record  identity.AccessToken
		profile identity.Profile
	)
	err := s.Store.Read(r.Context(), func(tx identity.ReadTx) error {
		rec, err := tx.AccessToken(hash)
		if err != nil {
			return nil
		}
		if rec.Revoked || !s.Now().Before(rec.ExpiresAt) || rec.Audience != "userinfo" || !slices.Contains(rec.Scopes, "openid") {
			return nil
		}
		user, err := tx.User(rec.UserID)
		if err != nil || !user.Active {
			return nil
		}
		record, profile, found = rec, user.Profile, true
		return nil
	})
	if err != nil || !found {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "The access token is invalid, expired, or revoked.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(ProjectUserInfo(profile, record.Scopes))
}
