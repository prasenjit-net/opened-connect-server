package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

type oauthFailure struct{ code, description string }

func (e *oauthFailure) Error() string       { return e.description }
func oauthError(code, message string) error { return &oauthFailure{code, message} }
func (s *Service) tokenFailure(w http.ResponseWriter, err error) {
	var failure *oauthFailure
	if errors.As(err, &failure) {
		writeOAuthError(w, 400, failure.code, failure.description)
		return
	}
	writeOAuthError(w, 503, "server_error", "Unable to complete token operation.")
}
func (s *Service) oauthRequest(w http.ResponseWriter, r *http.Request) (url.Values, identity.ProtocolClient, bool) {
	if !s.allowTraffic(w, r, r.URL.Path) {
		return nil, identity.ProtocolClient{}, false
	}
	if r.Method != "POST" {
		w.Header().Set("Allow", "POST")
		writeOAuthError(w, 405, "invalid_request", "Use POST.")
		return nil, identity.ProtocolClient{}, false
	}
	form, err := parseProtocolForm(r)
	if errors.Is(err, errMultipleResources) {
		writeOAuthError(w, 400, "invalid_target", "Only one resource is supported.")
		return nil, identity.ProtocolClient{}, false
	}
	if err != nil {
		writeOAuthError(w, 400, "invalid_request", "Malformed, duplicate, or oversized form parameters.")
		return nil, identity.ProtocolClient{}, false
	}
	c, err := s.authenticateClient(r, form)
	if err != nil {
		if errors.Is(err, ErrClientAuthUnavailable) {
			writeOAuthError(w, 503, "server_error", "Client authentication is temporarily unavailable.")
			return nil, c, false
		}
		status := 401
		code := "invalid_client"
		if errors.Is(err, ErrClientAuthConflict) {
			status = 400
			code = "invalid_request"
		}
		if errors.Is(err, ErrClientAuthLimited) {
			status = 429
			w.Header().Set("Retry-After", "60")
		}
		if status == 401 {
			w.Header().Set("WWW-Authenticate", `Basic realm="oauth"`)
		}
		writeOAuthError(w, status, code, "Client authentication failed.")
		return nil, c, false
	}
	return form, c, true
}
func writeTokenResponse(w http.ResponseWriter, response tokenResponse) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(response)
}
func (s *Service) OAuthMetadataHandler(w http.ResponseWriter, r *http.Request) {
	doc := s.discoveryDocument()
	d := map[string]any{"issuer": doc.Issuer, "authorization_endpoint": doc.AuthorizationEndpoint, "token_endpoint": doc.TokenEndpoint, "jwks_uri": doc.JWKSURI, "revocation_endpoint": doc.RevocationEndpoint, "introspection_endpoint": doc.IntrospectionEndpoint, "grant_types_supported": doc.GrantTypesSupported, "response_types_supported": doc.ResponseTypesSupported, "token_endpoint_auth_methods_supported": doc.TokenEndpointAuthMethodsSupported, "introspection_endpoint_auth_methods_supported": doc.IntrospectionAuthMethods, "revocation_endpoint_auth_methods_supported": doc.RevocationAuthMethods, "code_challenge_methods_supported": doc.CodeChallengeMethodsSupported}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.NewEncoder(w).Encode(d)
}
func (s *Service) supportedGrants() []string {
	g := []string{"authorization_code", "client_credentials"}
	if s.Config.RefreshTokensEnabled {
		g = append(g, "refresh_token")
	}
	if s.Config.PasswordGrantEnabled {
		g = append(g, "password")
	}
	return g
}
func (s *Service) RevokeHandler(w http.ResponseWriter, r *http.Request) {
	form, c, ok := s.oauthRequest(w, r)
	if !ok {
		return
	}
	if form.Get("token") == "" {
		writeOAuthError(w, 400, "invalid_request", "token is required.")
		return
	}
	hash := hashToken(form.Get("token"))
	err := s.Store.Write(r.Context(), func(tx identity.Tx) error {
		current, e := tx.Client(c.ID)
		if e != nil {
			return e
		}
		if current.UpdatedAt.UnixNano() != c.UpdatedAt {
			return oauthError("invalid_client", "Client policy changed.")
		}
		t, e := tx.AccessToken(hash)
		if e == nil {
			if t.ClientID == c.ID {
				tx.RevokeAccessToken(hash)
			}
			return nil
		}
		if !errors.Is(e, identity.ErrNotFound) {
			return e
		}
		rt, e := tx.RefreshToken(hash)
		if errors.Is(e, identity.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		f, e := tx.RefreshFamily(rt.FamilyID)
		if errors.Is(e, identity.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if f.ClientID == c.ID {
			tx.RevokeRefreshFamily(f.ID)
		}
		return nil
	})
	if err != nil {
		s.tokenFailure(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
}
func (s *Service) IntrospectHandler(w http.ResponseWriter, r *http.Request) {
	form, c, ok := s.oauthRequest(w, r)
	if !ok {
		return
	}
	if form.Get("token") == "" {
		writeOAuthError(w, 400, "invalid_request", "token is required.")
		return
	}
	out := map[string]any{"active": false}
	denied := false
	err := s.Store.Read(r.Context(), func(tx identity.ReadTx) error {
		current, e := tx.Client(c.ID)
		if e != nil {
			return e
		}
		p := tx.OAuthPolicy(c.ID)
		if current.UpdatedAt.UnixNano() != c.UpdatedAt || c.TokenEndpointAuthMethod == "none" || !p.IntrospectionEnabled {
			denied = true
			return nil
		}
		hash := hashToken(form.Get("token"))
		t, e := tx.AccessToken(hash)
		if e == nil {
			active, e := identity.AccessTokenActive(tx, t, s.Now(), s.Config.Resources)
			if e != nil {
				return e
			}
			if !active || !slices.Contains(p.IntrospectionAudiences, t.Audience) {
				return nil
			}
			subject := t.UserID
			if t.SubjectKind == "client" {
				subject = "client:" + t.ClientID
			}
			out = map[string]any{"active": true, "client_id": t.ClientID, "sub": subject, "token_type": "Bearer", "scope": strings.Join(t.Scopes, " "), "aud": t.Audience, "iss": s.Config.Issuer, "iat": t.IssuedAt.Unix(), "exp": t.ExpiresAt.Unix()}
			return nil
		}
		if !errors.Is(e, identity.ErrNotFound) {
			return e
		}
		rt, e := tx.RefreshToken(hash)
		if errors.Is(e, identity.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		f, e := tx.RefreshFamily(rt.FamilyID)
		if errors.Is(e, identity.ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if !s.Config.RefreshTokensEnabled || !p.RefreshInspection || !slices.Contains(p.IntrospectionAudiences, f.Audience) || f.ClientID != c.ID || rt.Consumed {
			return nil
		}
		active, e := identity.RefreshFamilyActive(tx, f, s.Now())
		if e != nil {
			return e
		}
		if !active {
			return nil
		}
		out = map[string]any{"active": true, "client_id": f.ClientID, "sub": f.UserID, "scope": strings.Join(rt.Scopes, " "), "aud": f.Audience, "iss": s.Config.Issuer, "iat": rt.IssuedAt.Unix(), "exp": minTime(f.AbsoluteExpiry, f.IdleExpiry).Unix()}
		return nil
	})
	if err != nil {
		s.tokenFailure(w, err)
		return
	}
	if denied {
		writeOAuthError(w, 403, "access_denied", "Introspection is not permitted.")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (s *Service) resourceGrant(tx identity.ReadTx, c identity.ClientRecord, grant string, form url.Values, userID string) (string, []string, error) {
	p := tx.OAuthPolicy(c.ID)
	if !slices.Contains(identity.RuntimeClient(c).GrantTypes, grant) || !slices.Contains(p.Grants, grant) {
		return "", nil, oauthError("unauthorized_client", "Grant is not permitted for this client.")
	}
	if identity.RuntimeClient(c).TokenEndpointAuthMethod == "none" {
		return "", nil, oauthError("unauthorized_client", "A confidential client is required.")
	}
	if grant == "password" && !p.PasswordEnabled {
		return "", nil, oauthError("unauthorized_client", "Password grant is not approved.")
	}
	aud := form.Get("resource")
	if form.Has("resource") && aud == "" {
		return "", nil, oauthError("invalid_target", "Resource must not be empty.")
	}
	if aud == "" {
		aud = p.DefaultResource
	}
	res, ok := identity.ResourceByAudience(s.Config.Resources, aud)
	allowed, permitted := p.Resources[aud]
	if !ok || !res.Enabled || !permitted {
		return "", nil, oauthError("invalid_target", "Select a permitted resource.")
	}
	scopes := strings.Fields(form.Get("scope"))
	if !form.Has("scope") {
		scopes = allowed.Default
	}
	if len(scopes) == 0 || !identity.ValidResourceScopes(scopes) || !identity.ScopeSubset(scopes, allowed.Allowed) || !identity.ScopeSubset(scopes, res.Scopes) {
		return "", nil, oauthError("invalid_scope", "Scopes are not permitted.")
	}
	if grant == "password" && !identity.ScopeSubset(scopes, tx.OAuthAccess(userID)[aud]) {
		return "", nil, oauthError("invalid_grant", "The account is not permitted to access this resource.")
	}
	return aud, scopes, nil
}
func (s *Service) issueResourceToken(w http.ResponseWriter, r *http.Request, form url.Values, c identity.ProtocolClient) {
	grant := form.Get("grant_type")
	var user identity.User
	if c.TokenEndpointAuthMethod == "none" {
		writeOAuthError(w, 400, "unauthorized_client", "A confidential client is required.")
		return
	}
	// Check client authorization before accepting any resource-owner credentials.
	err := s.Store.Read(r.Context(), func(tx identity.ReadTx) error {
		p := tx.OAuthPolicy(c.ID)
		if !slices.Contains(c.GrantTypes, grant) || !slices.Contains(p.Grants, grant) || (grant == "password" && !p.PasswordEnabled) {
			return oauthError("unauthorized_client", "Grant is not permitted.")
		}
		return nil
	})
	if err != nil {
		s.tokenFailure(w, err)
		return
	}
	if grant == "password" {
		if form.Get("username") == "" || form.Get("password") == "" {
			writeOAuthError(w, 400, "invalid_request", "username and password are required.")
			return
		}
		for _, key := range []string{"all", "peer:" + requestSource(r), "client:" + c.ID, "account:" + identity.SessionHash(strings.ToLower(strings.TrimSpace(form.Get("username"))))} {
			if !s.passwordLimiter.take(key, 30, 15*time.Minute) {
				w.Header().Set("Retry-After", "900")
				writeOAuthError(w, 429, "temporarily_unavailable", "Too many password requests.")
				return
			}
		}
		select {
		case s.passwordSlots <- struct{}{}:
			defer func() { <-s.passwordSlots }()
		default:
			w.Header().Set("Retry-After", "1")
			writeOAuthError(w, 429, "temporarily_unavailable", "Password verification is busy.")
			return
		}
		user, err = s.Identity.VerifyOAuthPassword(r.Context(), form.Get("username"), form.Get("password"))
		form.Del("password")
		if err != nil {
			if errors.Is(err, identity.ErrCredentials) {
				err = oauthError("invalid_grant", "Invalid account credentials.")
			}
			s.tokenFailure(w, err)
			return
		}
	}
	raw, err := randomToken()
	if err != nil {
		s.tokenFailure(w, err)
		return
	}
	var scopes []string
	err = s.Store.Write(r.Context(), func(tx identity.Tx) error {
		now := s.Now()
		current, e := tx.Client(c.ID)
		if e != nil {
			return e
		}
		if current.UpdatedAt.UnixNano() != c.UpdatedAt {
			return oauthError("invalid_grant", "Client changed during issuance.")
		}
		if grant == "password" {
			u, e := tx.User(user.ID)
			if e != nil && !errors.Is(e, identity.ErrNotFound) {
				return e
			}
			if e != nil || !u.Active || u.PasswordHash != user.PasswordHash || u.Email != user.Email {
				return oauthError("invalid_grant", "Account changed during issuance.")
			}
		}
		aud, approved, e := s.resourceGrant(tx, current, grant, form, user.ID)
		if e != nil {
			return e
		}
		scopes = approved
		kind := "client"
		if grant == "password" {
			kind = "user"
		}
		tx.SaveAccessToken(identity.AccessToken{Hash: hashToken(raw), ClientID: c.ID, UserID: user.ID, SubjectKind: kind, GrantType: grant, Audience: aud, Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(s.Config.AccessTokenTTL)})
		tx.PruneOIDCState(now)
		return nil
	})
	if err != nil {
		s.tokenFailure(w, err)
		return
	}
	writeTokenResponse(w, tokenResponse{AccessToken: raw, TokenType: "Bearer", ExpiresIn: int64(s.Config.AccessTokenTTL.Seconds()), Scope: strings.Join(scopes, " ")})
}
