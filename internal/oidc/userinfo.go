package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func bearerToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(r.Header.Values("Authorization")) != 1 {
		return ""
	}
	return parts[1]
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
		if errors.Is(err, identity.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if rec.Revoked || !s.Now().Before(rec.ExpiresAt) || rec.Audience != "userinfo" || !slices.Contains(rec.Scopes, "openid") {
			return nil
		}
		client, err := tx.Client(rec.ClientID)
		if errors.Is(err, identity.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !identity.RuntimeClient(client).Compatible || client.UpdatedAt.After(rec.IssuedAt) {
			return nil
		}
		user, err := tx.User(rec.UserID)
		if errors.Is(err, identity.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if !user.Active {
			return nil
		}
		record, profile, found = rec, user.Profile, true
		return nil
	})
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Unable to load UserInfo.")
		return
	}
	if !found {
		w.Header().Set("WWW-Authenticate", `Bearer realm="oidc", error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "The access token is invalid, expired, or revoked.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(ProjectUserInfo(profile, record.Scopes))
}
