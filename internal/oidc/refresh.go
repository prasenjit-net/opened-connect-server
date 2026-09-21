package oidc

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func (s *Service) initialRefresh(tx identity.Tx, clientID string, code identity.AuthorizationCode, now time.Time) (string, string, error) {
	p := tx.OAuthPolicy(clientID)
	c, err := tx.Client(clientID)
	if err != nil {
		return "", "", err
	}
	if !s.Config.RefreshTokensEnabled || !p.RefreshEnabled || !slices.Contains(p.Grants, "refresh_token") || !slices.Contains(identity.RuntimeClient(c).GrantTypes, "refresh_token") {
		return "", "", errInvalidGrant
	}
	raw, err := randomToken()
	if err != nil {
		return "", "", err
	}
	id, err := randomToken()
	if err != nil {
		return "", "", err
	}
	f := identity.RefreshFamily{AppSessionID: code.AppSessionID, OPSessionID: code.OPSessionID, ID: id, ClientID: clientID, UserID: code.UserID, CodeHash: code.Hash, Audience: "userinfo", Scopes: code.Scopes, AuthTime: code.AuthTime, ClientRevision: c.UpdatedAt.UnixNano(), CreatedAt: now, AbsoluteExpiry: now.Add(s.Config.RefreshMaxTTL), IdleExpiry: now.Add(s.Config.RefreshInactivityTTL), RetainUntil: now.Add(s.Config.RefreshMaxTTL + s.Config.AccessTokenTTL)}
	active, err := identity.RefreshFamilyActive(tx, f, now)
	if err != nil {
		return "", "", err
	}
	if !active {
		return "", "", errInvalidGrant
	}
	tx.SaveRefreshFamily(f)
	tx.SaveRefreshToken(identity.RefreshToken{Hash: hashToken(raw), FamilyID: id, Scopes: code.Scopes, IssuedAt: now})
	return raw, id, nil
}

// Rotation and replay revocation share the same serializable transaction. A
// wrong client's presentation never consumes or revokes another client's grant.
func (s *Service) refreshToken(w http.ResponseWriter, r *http.Request, form url.Values, c identity.ProtocolClient) {
	if form.Get("refresh_token") == "" {
		writeOAuthError(w, 400, "invalid_request", "refresh_token is required.")
		return
	}
	replay := false
	var response tokenResponse
	err := s.Store.Write(r.Context(), func(tx identity.Tx) error {
		invalid := oauthError("invalid_grant", "The refresh token is invalid, expired, or already used.")
		old, e := tx.RefreshToken(hashToken(form.Get("refresh_token")))
		if errors.Is(e, identity.ErrNotFound) {
			return invalid
		}
		if e != nil {
			return e
		}
		f, e := tx.RefreshFamily(old.FamilyID)
		if errors.Is(e, identity.ErrNotFound) {
			return invalid
		}
		if e != nil {
			return e
		}
		if f.ClientID != c.ID {
			return invalid
		}
		current, e := tx.Client(c.ID)
		if e != nil {
			return e
		}
		if current.UpdatedAt.UnixNano() != c.UpdatedAt {
			return invalid
		}
		if old.Consumed {
			tx.RevokeRefreshFamily(f.ID)
			replay = true
			return nil
		}
		now := s.Now()
		active, e := identity.RefreshFamilyActive(tx, f, now)
		if e != nil {
			return e
		}
		if !active {
			return invalid
		}
		if form.Has("resource") && form.Get("resource") != f.Audience {
			return oauthError("invalid_target", "Refresh cannot change the resource.")
		}
		scopes := old.Scopes
		if form.Has("scope") {
			scopes = strings.Fields(form.Get("scope"))
			if len(scopes) == 0 || !identity.ScopeSubset(scopes, old.Scopes) {
				return oauthError("invalid_scope", "Refresh scopes must be a nonempty subset of the current grant.")
			}
		}
		access, e := randomToken()
		if e != nil {
			return e
		}
		next, e := randomToken()
		if e != nil {
			return e
		}
		old.Consumed = true
		tx.SaveRefreshToken(old)
		f.IdleExpiry = minTime(now.Add(s.Config.RefreshInactivityTTL), f.AbsoluteExpiry)
		tx.SaveRefreshFamily(f)
		tx.SaveRefreshToken(identity.RefreshToken{Hash: hashToken(next), FamilyID: f.ID, Scopes: scopes, IssuedAt: now})
		tx.SaveAccessToken(identity.AccessToken{AppSessionID: f.AppSessionID, OPSessionID: f.OPSessionID, Hash: hashToken(access), ClientID: c.ID, UserID: f.UserID, SubjectKind: "user", GrantType: "refresh_token", OriginalGrant: "authorization_code", FamilyID: f.ID, CodeHash: f.CodeHash, Audience: f.Audience, Scopes: scopes, IssuedAt: now, ExpiresAt: now.Add(s.Config.AccessTokenTTL)})
		tx.PruneOIDCState(now)
		response = tokenResponse{AccessToken: access, RefreshToken: next, TokenType: "Bearer", ExpiresIn: int64(s.Config.AccessTokenTTL.Seconds()), Scope: strings.Join(scopes, " ")}
		return nil
	})
	if err != nil {
		s.tokenFailure(w, err)
		return
	}
	if replay {
		writeOAuthError(w, 400, "invalid_grant", "Refresh token reuse detected; the grant has been revoked.")
		return
	}
	writeTokenResponse(w, response)
}
