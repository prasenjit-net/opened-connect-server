package identity

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
)

// OAuth permissions are administrative policy, never profile claims or DCR metadata.
type Resource struct {
	Audience string   `json:"audience" mapstructure:"audience" yaml:"audience"`
	Scopes   []string `json:"scopes" mapstructure:"scopes" yaml:"scopes"`
	Enabled  bool     `json:"enabled" mapstructure:"enabled" yaml:"enabled"`
}
type ResourceScopes struct {
	Allowed []string `json:"allowed"`
	Default []string `json:"default"`
}
type OAuthPolicy struct {
	Grants                 []string                  `json:"grants"`
	Resources              map[string]ResourceScopes `json:"resources"`
	DefaultResource        string                    `json:"defaultResource"`
	IntrospectionEnabled   bool                      `json:"introspectionEnabled"`
	IntrospectionAudiences []string                  `json:"introspectionAudiences"`
	RefreshInspection      bool                      `json:"refreshInspection"`
	RefreshEnabled         bool                      `json:"refreshEnabled"`
	PasswordEnabled        bool                      `json:"passwordEnabled"`
}
type OAuthAccess map[string][]string

func clonePolicy(p OAuthPolicy) OAuthPolicy {
	p.Grants = cloneStrings(p.Grants)
	p.IntrospectionAudiences = cloneStrings(p.IntrospectionAudiences)
	r := map[string]ResourceScopes{}
	for k, v := range p.Resources {
		r[k] = ResourceScopes{append([]string{}, v.Allowed...), append([]string{}, v.Default...)}
	}
	p.Resources = r
	return p
}
func cloneAccess(a OAuthAccess) OAuthAccess {
	out := OAuthAccess{}
	for k, v := range a {
		out[k] = cloneStrings(v)
	}
	return out
}
func ResourceByAudience(resources []Resource, aud string) (Resource, bool) {
	for _, r := range resources {
		if r.Audience == aud {
			return r, true
		}
	}
	return Resource{}, false
}
func ScopeSubset(requested, allowed []string) bool {
	for _, scope := range requested {
		if !slices.Contains(allowed, scope) {
			return false
		}
	}
	return true
}
func validScopeList(scopes []string) bool {
	if len(scopes) > 100 {
		return false
	}
	seen := map[string]bool{}
	for _, sc := range scopes {
		if sc == "" || len(sc) > 200 || seen[sc] {
			return false
		}
		seen[sc] = true
		for _, c := range sc {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return false
			}
		}
	}
	return true
}
func ValidResourceScopes(scopes []string) bool {
	if !validScopeList(scopes) {
		return false
	}
	for _, s := range scopes {
		if slices.Contains([]string{"openid", "offline_access", "profile", "email", "address", "phone"}, s) {
			return false
		}
	}
	return true
}
func (s *Service) GetOAuthPolicy(ctx context.Context, session, id string) (OAuthPolicy, error) {
	var out OAuthPolicy
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if _, e := s.principal(tx, session, true); e != nil {
			return e
		}
		if _, e := tx.Client(id); e != nil {
			return e
		}
		out = tx.OAuthPolicy(id)
		return nil
	})
	return out, err
}
func (s *Service) SetOAuthPolicy(ctx context.Context, session, id string, p OAuthPolicy, resources []Resource) error {
	return s.store.Write(ctx, func(tx Tx) error {
		if _, e := s.principal(tx, session, true); e != nil {
			return e
		}
		c, e := tx.Client(id)
		if e != nil {
			return e
		}
		if len(p.Resources) > 100 || len(p.IntrospectionAudiences) > 100 || !validScopeList(p.Grants) {
			return ValidationError("Invalid OAuth policy limits.")
		}
		for _, g := range p.Grants {
			if !slices.Contains([]string{"client_credentials", "password", "refresh_token"}, g) || !slices.Contains(c.Metadata.list("grant_types"), g) {
				return ValidationError("OAuth policy grants must be registered on the client.")
			}
		}
		if (p.PasswordEnabled || p.IntrospectionEnabled || slices.Contains(p.Grants, "client_credentials") || slices.Contains(p.Grants, "password")) && !slices.Contains([]string{"client_secret_basic", "client_secret_post"}, c.Metadata.text("token_endpoint_auth_method")) {
			return ValidationError("This OAuth permission requires a confidential client.")
		}
		if p.RefreshEnabled && (!slices.Contains(p.Grants, "refresh_token") || !slices.Contains(c.Metadata.list("grant_types"), "authorization_code")) {
			return ValidationError("Offline access requires authorization_code and refresh_token permissions.")
		}
		if p.PasswordEnabled && !slices.Contains(p.Grants, "password") {
			return ValidationError("Password permission requires the password grant.")
		}
		if p.RefreshInspection && !p.IntrospectionEnabled {
			return ValidationError("Refresh inspection requires introspection permission.")
		}
		for aud, v := range p.Resources {
			r, ok := ResourceByAudience(resources, aud)
			if !ok || !ValidResourceScopes(v.Allowed) || !validScopeList(v.Default) || !ScopeSubset(v.Allowed, r.Scopes) || !ScopeSubset(v.Default, v.Allowed) {
				return ValidationError("Invalid resource or scopes in client policy.")
			}
		}
		if p.DefaultResource != "" {
			if _, ok := p.Resources[p.DefaultResource]; !ok {
				return ValidationError("Default resource must be permitted.")
			}
		}
		for _, aud := range p.IntrospectionAudiences {
			if aud != "userinfo" {
				if _, ok := ResourceByAudience(resources, aud); !ok {
					return ValidationError("Unknown introspection audience.")
				}
			}
		}
		tx.SaveOAuthPolicy(id, p)
		return nil
	})
}
func (s *Service) GetOAuthAccess(ctx context.Context, session, id string) (OAuthAccess, error) {
	var out OAuthAccess
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if _, e := s.principal(tx, session, true); e != nil {
			return e
		}
		if _, e := tx.User(id); e != nil {
			return e
		}
		out = tx.OAuthAccess(id)
		return nil
	})
	return out, err
}
func (s *Service) SetOAuthAccess(ctx context.Context, session, id string, a OAuthAccess, resources []Resource) error {
	return s.store.Write(ctx, func(tx Tx) error {
		if _, e := s.principal(tx, session, true); e != nil {
			return e
		}
		if _, e := tx.User(id); e != nil {
			return e
		}
		if len(a) > 100 {
			return ValidationError("Too many resources.")
		}
		for aud, sc := range a {
			r, ok := ResourceByAudience(resources, aud)
			if !ok || !ValidResourceScopes(sc) || !ScopeSubset(sc, r.Scopes) {
				return ValidationError("Invalid user resource entitlement.")
			}
		}
		tx.SaveOAuthAccess(id, a)
		return nil
	})
}

// VerifyOAuthPassword checks credentials without creating a browser session.
// Callers must recheck this snapshot during their issuance transaction.
func (s *Service) VerifyOAuthPassword(ctx context.Context, email, password string) (User, error) {
	if len(email) > 254 || len(password) > 128 || password == "" {
		return User{}, ErrCredentials
	}
	var u User
	err := s.store.Read(ctx, func(tx ReadTx) error {
		var e error
		u, e = tx.UserByEmail(strings.ToLower(strings.TrimSpace(email)))
		return e
	})
	if err != nil && !errors.Is(err, ErrNotFound) {
		return User{}, err
	}
	hash := u.PasswordHash
	if err != nil {
		hash = s.dummyHash
	}
	if !VerifyPassword(hash, password) || err != nil || !u.Active {
		return User{}, ErrCredentials
	}
	return u, nil
}

type RefreshFamily struct {
	ID             string    `json:"id"`
	ClientID       string    `json:"clientId"`
	UserID         string    `json:"userId"`
	CodeHash       string    `json:"codeHash"`
	Audience       string    `json:"audience"`
	Scopes         []string  `json:"scopes"`
	AuthTime       int64     `json:"authTime"`
	ClientRevision int64     `json:"clientRevision"`
	CreatedAt      time.Time `json:"createdAt"`
	AbsoluteExpiry time.Time `json:"absoluteExpiry"`
	IdleExpiry     time.Time `json:"idleExpiry"`
	RetainUntil    time.Time `json:"retainUntil"`
	Revoked        bool      `json:"revoked"`
}
type RefreshToken struct {
	Hash     string    `json:"hash"`
	FamilyID string    `json:"familyId"`
	Scopes   []string  `json:"scopes"`
	IssuedAt time.Time `json:"issuedAt"`
	Consumed bool      `json:"consumed"`
}

func cloneFamily(f RefreshFamily) RefreshFamily { f.Scopes = cloneStrings(f.Scopes); return f }
func cloneRefresh(t RefreshToken) RefreshToken  { t.Scopes = cloneStrings(t.Scopes); return t }
