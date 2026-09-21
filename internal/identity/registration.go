package identity

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"
)

var ErrRegistrationCredential = errors.New("invalid registration credential")
var ErrRegistrationInactive = errors.New("registration credential is no longer active")

type RegistrationError struct{ Code, Description string }

func (e *RegistrationError) Error() string { return e.Description }

type InitialAccessToken struct {
	ID        string    `json:"id"`
	Hash      string    `json:"hash"`
	Label     string    `json:"label"`
	IssuedBy  string    `json:"issuedBy"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	MaxUses   int       `json:"maxUses"`
	Uses      int       `json:"uses"`
	Revoked   bool      `json:"revoked"`
}
type RegistrationAccessToken struct {
	Hash     string    `json:"hash"`
	ClientID string    `json:"clientId"`
	IssuedAt time.Time `json:"issuedAt"`
}
type InitialTokenView struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	IssuedBy  string    `json:"issuedBy"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	MaxUses   int       `json:"maxUses"`
	Uses      int       `json:"uses"`
	Status    string    `json:"status"`
}
type InitialTokenInput struct {
	Label         string `json:"label"`
	MaxUses       int    `json:"maxUses"`
	LifetimeHours int    `json:"lifetimeHours"`
}
type InitialTokenList struct {
	Tokens   []InitialTokenView `json:"tokens"`
	Total    int                `json:"total"`
	Page     int                `json:"page"`
	PageSize int                `json:"pageSize"`
}

func initialTokenView(t InitialAccessToken, now time.Time) InitialTokenView {
	status := "active"
	switch {
	case t.Revoked:
		status = "revoked"
	case !t.ExpiresAt.After(now):
		status = "expired"
	case t.Uses >= t.MaxUses:
		status = "consumed"
	}
	return InitialTokenView{t.ID, t.Label, t.IssuedBy, t.IssuedAt, t.ExpiresAt, t.MaxUses, t.Uses, status}
}
func registrationToken(prefix string) (string, error) {
	token, err := randomToken()
	return prefix + token, err
}
func (s *Service) IssueInitialToken(ctx context.Context, session string, in InitialTokenInput) (InitialTokenView, string, error) {
	var view InitialTokenView
	in.Label = strings.TrimSpace(in.Label)
	if in.Label == "" || len(in.Label) > 100 {
		return view, "", ValidationError("A label of 1–100 characters is required.")
	}
	if in.MaxUses == 0 {
		in.MaxUses = 1
	}
	if in.LifetimeHours == 0 {
		in.LifetimeHours = 24
	}
	if in.MaxUses < 1 || in.MaxUses > 100 || in.LifetimeHours < 1 || in.LifetimeHours > 720 {
		return view, "", ValidationError("Use limits must be 1–100 and lifetime 1–720 hours.")
	}
	token, err := registrationToken("iat_")
	if err != nil {
		return view, "", err
	}
	id, err := randomToken()
	if err != nil {
		return view, "", err
	}
	err = s.store.Write(ctx, func(tx Tx) error {
		p, err := s.principal(tx, session, true)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		t := InitialAccessToken{ID: id, Hash: SessionHash(token), Label: in.Label, IssuedBy: p.User.ID, IssuedAt: now, ExpiresAt: now.Add(time.Duration(in.LifetimeHours) * time.Hour), MaxUses: in.MaxUses}
		tx.SaveInitialToken(t)
		view = initialTokenView(t, now)
		return nil
	})
	if err != nil {
		return view, "", err
	}
	return view, token, nil
}
func (s *Service) ListInitialTokens(ctx context.Context, session, query string, page int) (InitialTokenList, error) {
	out := InitialTokenList{Tokens: []InitialTokenView{}, PageSize: 10}
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if _, err := s.principal(tx, session, true); err != nil {
			return err
		}
		q := strings.ToLower(strings.TrimSpace(query))
		all := []InitialTokenView{}
		for _, t := range tx.InitialTokens() {
			v := initialTokenView(t, s.now())
			if q == "" || strings.Contains(strings.ToLower(v.Label+" "+v.ID+" "+v.Status), q) {
				all = append(all, v)
			}
		}
		sort.Slice(all, func(i, j int) bool {
			if all[i].IssuedAt.Equal(all[j].IssuedAt) {
				return all[i].ID < all[j].ID
			}
			return all[i].IssuedAt.After(all[j].IssuedAt)
		})
		out.Total = len(all)
		out.Page = max(1, min(page, max(1, (len(all)+9)/10)))
		start := (out.Page - 1) * 10
		out.Tokens = all[start:min(start+10, len(all))]
		return nil
	})
	return out, err
}
func (s *Service) RevokeInitialToken(ctx context.Context, session, id string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		if _, err := s.principal(tx, session, true); err != nil {
			return err
		}
		for _, t := range tx.InitialTokens() {
			if t.ID == id {
				if initialTokenView(t, s.now()).Status != "active" {
					return ErrRegistrationInactive
				}
				t.Revoked = true
				tx.SaveInitialToken(t)
				return nil
			}
		}
		return ErrNotFound
	})
}
func (s *Service) ManageRegistrationToken(ctx context.Context, session, id string, issue bool) (string, error) {
	token := ""
	var err error
	if issue {
		token, err = registrationToken("rat_")
		if err != nil {
			return "", err
		}
	}
	err = s.store.Write(ctx, func(tx Tx) error {
		if _, err := s.principal(tx, session, true); err != nil {
			return err
		}
		if _, err := tx.Client(id); err != nil {
			return err
		}
		if !issue {
			tx.DeleteRegistrationToken(id)
			return nil
		}
		tx.SaveRegistrationToken(RegistrationAccessToken{Hash: SessionHash(token), ClientID: id, IssuedAt: s.now().UTC()})
		return nil
	})
	if err != nil {
		return "", err
	}
	return token, nil
}
func validInitialToken(tx ReadTx, token string, now time.Time) (InitialAccessToken, error) {
	if !strings.HasPrefix(token, "iat_") {
		return InitialAccessToken{}, ErrRegistrationCredential
	}
	t, err := tx.InitialToken(SessionHash(token))
	if err != nil || initialTokenView(t, now).Status != "active" {
		return InitialAccessToken{}, ErrRegistrationCredential
	}
	return t, nil
}
func (s *Service) CheckInitialToken(ctx context.Context, token string) error {
	return s.store.Read(ctx, func(tx ReadTx) error { _, err := validInitialToken(tx, token, s.now()); return err })
}

// Protocol registration deliberately differs from strict administrative input:
// unknown extension metadata is ignored, but server-owned fields are rejected.
func dynamicMetadata(input ClientMetadata, allowHTTP bool) (ClientMetadata, error) {
	fail := func(code, msg string) (ClientMetadata, error) { return nil, &RegistrationError{code, msg} }
	filtered := ClientMetadata{}
	var grants []string
	_ = json.Unmarshal(input["grant_types"], &grants)
	for _, g := range grants {
		if g == "password" {
			return fail("invalid_client_metadata", "The password grant requires admin registration.")
		}
	}
	if len(grants) > 0 && !slices.Contains(grants, "authorization_code") && !slices.Contains(grants, "client_credentials") {
		return fail("invalid_client_metadata", "Registration requires authorization_code or client_credentials.")
	}

	for k, v := range input {
		base, _, _ := strings.Cut(k, "#")
		if slices.Contains(strings.Fields("client_id client_secret client_id_issued_at client_secret_expires_at registration_access_token registration_client_uri origin registration_origin registration_token_active registration_token_issued_at registration_initial_token_id has_client_secret updated_at protocol_compatible protocol_incompatibilities role admin oauth_policy oauthPolicy resources refreshEnabled passwordEnabled introspectionEnabled grants"), k) {
			return fail("invalid_client_metadata", "Server-owned metadata cannot be supplied: "+k)
		}
		if slices.Contains(clientStringFields, base) || slices.Contains(clientArrayFields, k) || slices.Contains([]string{"jwks", "default_max_age", "require_auth_time"}, k) {
			filtered[k] = v
		}
	}
	m, err := normalizeClientMetadata(filtered)
	if err != nil {
		code := "invalid_client_metadata"
		var fieldError *ClientMetadataError
		if errors.As(err, &fieldError) && fieldError.Field == "redirect_uris" {
			code = "invalid_redirect_uri"
		}
		return fail(code, err.Error())
	}
	if ok, reasons := auditMetadata(m); !ok {
		return fail("invalid_client_metadata", strings.Join(reasons, "; "))
	}
	if slices.Contains(m.list("grant_types"), "client_credentials") && !slices.Contains([]string{"client_secret_basic", "client_secret_post"}, m.text("token_endpoint_auth_method")) {
		return fail("invalid_client_metadata", "client_credentials requires client_secret_basic or client_secret_post authentication.")
	}
	for _, k := range []string{"sector_identifier_uri", "request_object_signing_alg", "request_object_encryption_alg", "request_object_encryption_enc"} {
		if m.text(k) != "" {
			return fail("invalid_client_metadata", k+" is not supported by this provider.")
		}
	}
	if len(m.list("request_uris")) > 0 || len(m.list("default_acr_values")) > 0 {
		return fail("invalid_client_metadata", "Request objects and default ACR values are not supported.")
	}
	for _, raw := range append(append(m.list("post_logout_redirect_uris"), m.text("frontchannel_logout_uri")), m.text("backchannel_logout_uri")) {
		if raw != "" && !allowHTTP && !strings.HasPrefix(raw, "https://") {
			return nil, &RegistrationError{"invalid_client_metadata", "Logout URLs must use HTTPS."}
		}
	}
	for _, raw := range m.list("redirect_uris") {
		u, _ := url.Parse(raw)
		if m.text("application_type") == "web" && u.Scheme != "https" && !allowHTTP {
			return fail("invalid_redirect_uri", "Web redirect URIs must use HTTPS.")
		}
	}
	if m.text("subject_type") == "" {
		m.set("subject_type", "public")
	}
	return m, nil
}
func protocolClient(c ClientRecord) ClientView {
	v := ClientView{"client_id": c.ID, "client_id_issued_at": c.IssuedAt}
	for k, value := range cloneClient(c).Metadata {
		v[k] = value
	}
	if c.Secret != "" {
		v["client_secret"] = c.Secret
		v["client_secret_expires_at"] = 0
	}
	return v
}
func (s *Service) RegisterClient(ctx context.Context, initial string, input ClientMetadata, allowHTTP bool) (ClientView, error) {
	if err := s.CheckInitialToken(ctx, initial); err != nil {
		return nil, err
	}
	m, err := dynamicMetadata(input, allowHTTP)
	if err != nil {
		return nil, err
	}
	id, err := randomToken()
	if err != nil {
		return nil, err
	}
	rat, err := registrationToken("rat_")
	if err != nil {
		return nil, err
	}
	c := ClientRecord{ID: id, Metadata: m, Origin: "dynamic"}
	if needsClientSecret(m) {
		c.Secret, err = newClientSecret()
		if err != nil {
			return nil, err
		}
	}
	err = s.store.Write(ctx, func(tx Tx) error {
		t, e := validInitialToken(tx, initial, s.now())
		if e != nil {
			return e
		}
		if _, e = tx.Client(id); !errors.Is(e, ErrNotFound) {
			return errors.New("client identifier collision")
		}
		c.IssuedAt = s.now().Unix()
		c.UpdatedAt = s.now().UTC()
		c.InitialTokenID = t.ID
		tx.SaveClient(c)
		tx.SaveRegistrationToken(RegistrationAccessToken{Hash: SessionHash(rat), ClientID: id, IssuedAt: c.UpdatedAt})
		t.Uses++
		tx.SaveInitialToken(t)
		return nil
	})
	if err != nil {
		return nil, err
	}
	v := protocolClient(c)
	v["registration_access_token"] = rat
	return v, nil
}
func (s *Service) ReadRegistration(ctx context.Context, token, id string) (ClientView, error) {
	var out ClientView
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if !strings.HasPrefix(token, "rat_") {
			return ErrRegistrationCredential
		}
		t, err := tx.RegistrationToken(id)
		if err != nil || subtle.ConstantTimeCompare([]byte(t.Hash), []byte(SessionHash(token))) != 1 {
			return ErrRegistrationCredential
		}
		c, err := tx.Client(id)
		if err != nil {
			return ErrRegistrationCredential
		}
		out = protocolClient(c)
		return nil
	})
	return out, err
}
