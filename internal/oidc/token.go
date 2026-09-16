package oidc

import (
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

var errInvalidGrant = errors.New("invalid or expired authorization code")

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Scope       string `json:"scope"`
}

// TokenHandler implements POST /token for the authorization_code grant.
// Requests are form-encoded only (independent of internal/api's JSON-only
// rule), and every response is an OAuth-shaped error or a no-store token
// response — never internal/api's management JSON envelope.
func (s *Service) TokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "Use POST.")
		return
	}
	contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if contentType != "application/x-www-form-urlencoded" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Use application/x-www-form-urlencoded.")
		return
	}
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Malformed form body.")
		return
	}
	form := r.PostForm

	client, err := s.authenticateClient(r, form)
	if err != nil {
		status := http.StatusUnauthorized
		if errors.Is(err, ErrClientAuthLimited) {
			status = http.StatusTooManyRequests
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="oidc"`)
		writeOAuthError(w, status, "invalid_client", "Client authentication failed.")
		return
	}

	if form.Get("grant_type") != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "Only authorization_code is supported.")
		return
	}
	code := form.Get("code")
	redirectURI := form.Get("redirect_uri")
	verifier := form.Get("code_verifier")
	if code == "" || redirectURI == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code, redirect_uri, and code_verifier are required.")
		return
	}

	now := s.Now()
	codeHash := hashToken(code)
	var (
		userProfile identity.Profile
		scopes      []string
		nonce       string
		authTime    int64
	)
	// Re-read the code, verify it, and consume it inside one transaction so
	// concurrent exchanges of the same code produce at most one success.
	txErr := s.Store.Write(r.Context(), func(tx identity.Tx) error {
		record, err := tx.AuthorizationCode(codeHash)
		if err != nil {
			return errInvalidGrant
		}
		if record.Consumed {
			// The code has already been exchanged: this is a reuse attempt,
			// a signal the code may have leaked. Revoke whatever access
			// token the original, legitimate exchange minted.
			tx.RevokeAccessTokensForCode(codeHash)
			return errInvalidGrant
		}
		if !now.Before(record.ExpiresAt) || record.ClientID != client.ID || record.RedirectURI != redirectURI {
			return errInvalidGrant
		}
		if err := VerifyPKCE(verifier, record.CodeChallenge); err != nil {
			return errInvalidGrant
		}
		user, err := tx.User(record.UserID)
		if err != nil || !user.Active {
			return errInvalidGrant
		}
		currentClient, err := tx.Client(record.ClientID)
		if err != nil || currentClient.UpdatedAt.Unix() != record.ClientUpdatedAt.Unix() {
			return errInvalidGrant
		}
		record.Consumed = true
		tx.SaveAuthorizationCode(record)
		tx.PruneOIDCState(now)

		userProfile = user.Profile
		scopes = record.Scopes
		nonce = record.Nonce
		authTime = record.AuthTime
		return nil
	})
	if txErr != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "The authorization code is invalid, expired, or already used.")
		return
	}

	accessToken, err := randomToken()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Unable to issue an access token.")
		return
	}
	if err := s.Store.Write(r.Context(), func(tx identity.Tx) error {
		tx.SaveAccessToken(identity.AccessToken{
			Hash: hashToken(accessToken), ClientID: client.ID, UserID: userProfile.ID,
			Audience: "userinfo", Scopes: scopes, CodeHash: codeHash,
			IssuedAt: now, ExpiresAt: now.Add(s.Config.AccessTokenTTL),
		})
		return nil
	}); err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Unable to issue an access token.")
		return
	}

	idToken, err := s.signIDToken(client, userProfile.Sub, nonce, time.Unix(authTime, 0).UTC(), now)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Unable to sign the ID token.")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(tokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int64(s.Config.AccessTokenTTL.Seconds()),
		IDToken:     idToken,
		Scope:       strings.Join(scopes, " "),
	})
}
