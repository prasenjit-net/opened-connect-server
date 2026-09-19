package identity

import (
	"errors"
	"slices"
	"time"
)

// AccessTokenActive is shared by UserInfo, introspection and monitoring. It
// distinguishes an invalid token from a storage failure.
func AccessTokenActive(tx ReadTx, t AccessToken, now time.Time, resources []Resource) (bool, error) {
	if t.Revoked || !now.Before(t.ExpiresAt) {
		return false, nil
	}
	c, err := tx.Client(t.ClientID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if c.UpdatedAt.After(t.IssuedAt) {
		return false, nil
	}
	if t.FamilyID != "" {
		f, e := tx.RefreshFamily(t.FamilyID)
		if errors.Is(e, ErrNotFound) {
			return false, nil
		}
		if e != nil {
			return false, e
		}
		if f.Revoked {
			return false, nil
		}
	}
	grant := t.GrantType
	if grant == "refresh_token" {
		grant = t.OriginalGrant
	}
	if grant == "" && t.UserID != "" && t.Audience == "userinfo" {
		grant = "authorization_code"
	}
	switch grant {
	case "authorization_code":
		if t.SubjectKind == "client" || t.UserID == "" || t.Audience != "userinfo" || !RuntimeClient(c).Compatible || !slices.Contains(c.Metadata.list("grant_types"), "authorization_code") {
			return false, nil
		}
	case "client_credentials", "password":
		p := tx.OAuthPolicy(c.ID)
		r, ok := ResourceByAudience(resources, t.Audience)
		if !ok || !r.Enabled || !slices.Contains(p.Grants, grant) || !slices.Contains(c.Metadata.list("grant_types"), grant) || !ScopeSubset(t.Scopes, p.Resources[t.Audience].Allowed) || !ScopeSubset(t.Scopes, r.Scopes) {
			return false, nil
		}
		if grant == "client_credentials" {
			return t.SubjectKind == "client" && t.UserID == "", nil
		}
		if !p.PasswordEnabled || t.SubjectKind != "user" || !ScopeSubset(t.Scopes, tx.OAuthAccess(t.UserID)[t.Audience]) {
			return false, nil
		}
	default:
		return false, nil
	}
	u, err := tx.User(t.UserID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return u.Active, nil
}
func RefreshFamilyActive(tx ReadTx, f RefreshFamily, now time.Time) (bool, error) {
	if f.Revoked || !now.Before(f.AbsoluteExpiry) || !now.Before(f.IdleExpiry) {
		return false, nil
	}
	c, err := tx.Client(f.ClientID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	p := tx.OAuthPolicy(c.ID)
	if !p.RefreshEnabled || !slices.Contains(p.Grants, "refresh_token") || !slices.Contains(c.Metadata.list("grant_types"), "refresh_token") || c.UpdatedAt.UnixNano() != f.ClientRevision {
		return false, nil
	}
	u, err := tx.User(f.UserID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !u.Active {
		return false, nil
	}
	consent, err := tx.Consent(f.UserID, f.ClientID)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return !consent.Revoked && consent.PolicyRevision == f.ClientRevision && ScopeSubset(f.Scopes, consent.Scopes) && slices.Contains(consent.Scopes, "offline_access"), nil
}
