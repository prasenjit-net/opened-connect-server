package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

var errInvalidGrant = errors.New("invalid or expired authorization code")

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope"`
}

// TokenHandler implements POST /token for the authorization_code grant.
// Requests are form-encoded only (independent of internal/api's JSON-only
// rule), and every response is an OAuth-shaped error or a no-store token
// response — never internal/api's management JSON envelope.
func (s *Service) TokenHandler(w http.ResponseWriter, r *http.Request) {
	form, client, ok := s.oauthRequest(w, r)
	if !ok {
		return
	}
	switch form.Get("grant_type") {
	case "authorization_code":
	case "client_credentials":
		s.issueResourceToken(w, r, form, client)
		return
	case "password":
		if s.Config.PasswordGrantEnabled {
			s.issueResourceToken(w, r, form, client)
			return
		}
		writeOAuthError(w, 400, "unsupported_grant_type", "Password grant is disabled.")
		return
	case "refresh_token":
		if s.Config.RefreshTokensEnabled {
			s.refreshToken(w, r, form, client)
			return
		}
		writeOAuthError(w, 400, "unsupported_grant_type", "Refresh tokens are disabled.")
		return
	default:
		writeOAuthError(w, 400, "unsupported_grant_type", "Unsupported grant type.")
		return
	}
	if form.Has("resource") {
		writeOAuthError(w, 400, "invalid_target", "Authorization codes are bound to UserInfo.")
		return
	}
	code := form.Get("code")
	redirectURI := form.Get("redirect_uri")
	verifier := form.Get("code_verifier")
	if code == "" || redirectURI == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code, redirect_uri, and code_verifier are required.")
		return
	}

	codeHash := hashToken(code)
	var scopes []string
	var accessToken, idToken, refreshToken, familyID string
	replay := false
	txErr := s.Store.Write(r.Context(), func(tx identity.Tx) error {
		now := s.Now()
		record, err := tx.AuthorizationCode(codeHash)
		if err != nil && !errors.Is(err, identity.ErrNotFound) {
			return err
		}
		if err != nil || record.Revoked || record.ClientID != client.ID || record.RedirectURI != redirectURI || VerifyPKCE(verifier, record.CodeChallenge) != nil {
			return errInvalidGrant
		}
		current, err := tx.Client(client.ID)
		if err != nil && !errors.Is(err, identity.ErrNotFound) {
			return err
		}
		if err != nil || !identity.RuntimeClient(current).Compatible || current.UpdatedAt.UnixNano() != client.UpdatedAt || !current.UpdatedAt.Equal(record.ClientUpdatedAt) {
			return errInvalidGrant
		}
		// Only an authenticated, correctly bound replay may revoke issued tokens.
		// Commit the revocation; returning an error here would roll it back.
		if record.Consumed {
			tx.RevokeAccessTokensForCode(codeHash)
			replay = true
			return nil
		}
		if !now.Before(record.ExpiresAt) {
			return errInvalidGrant
		}
		user, err := tx.User(record.UserID)
		if err != nil && !errors.Is(err, identity.ErrNotFound) {
			return err
		}
		if err != nil || !user.Active {
			return errInvalidGrant
		}
		accessToken, err = randomToken()
		if err != nil {
			return err
		}
		idToken, err = s.signIDToken(client, user.Sub, record.Nonce, time.Unix(record.AuthTime, 0).UTC(), now)
		if err != nil {
			return err
		}
		scopes = record.Scopes
		record.Consumed = true
		record.RetainUntil = now.Add(s.Config.AccessTokenTTL)
		if slices.Contains(scopes, "offline_access") {
			refreshToken, familyID, err = s.initialRefresh(tx, client.ID, record, now)
			if err != nil {
				return err
			}
			family, _ := tx.RefreshFamily(familyID)
			record.RetainUntil = family.RetainUntil
		}
		tx.SaveAuthorizationCode(record)
		tx.SaveAccessToken(identity.AccessToken{GrantType: "authorization_code", SubjectKind: "user", FamilyID: familyID, IDTokenExpiresAt: now.Add(s.Config.IDTokenTTL), Hash: hashToken(accessToken), ClientID: client.ID, UserID: user.ID, Audience: "userinfo", Scopes: scopes, CodeHash: codeHash, IssuedAt: now, ExpiresAt: now.Add(s.Config.AccessTokenTTL)})
		tx.PruneOIDCState(now)
		return nil
	})
	if errors.Is(txErr, errInvalidGrant) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The authorization code is invalid, expired, or already used.")
		return
	}
	if txErr != nil {
		writeOAuthError(w, http.StatusServiceUnavailable, "server_error", "Unable to issue tokens.")
		return
	}

	if replay {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The authorization code has already been used.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.Config.AccessTokenTTL.Seconds()),
		IDToken:      idToken,
		Scope:        strings.Join(scopes, " "),
	})
}
