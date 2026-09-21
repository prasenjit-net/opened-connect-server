package identity

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// ClientMetadata uses the registration specification's top-level JSON names,
// including language-tagged display metadata such as client_name#fr.
type ClientMetadata map[string]json.RawMessage
type ClientRecord struct {
	Origin         string         `json:"origin,omitempty"`
	InitialTokenID string         `json:"initialTokenId,omitempty"`
	ID             string         `json:"id"`
	Metadata       ClientMetadata `json:"metadata"`
	Secret         string         `json:"secret,omitempty"`
	IssuedAt       int64          `json:"issuedAt"`
	UpdatedAt      time.Time      `json:"updatedAt"`
}
type ClientView map[string]any
type ClientList struct {
	Clients  []ClientView `json:"clients"`
	Total    int          `json:"total"`
	Page     int          `json:"page"`
	PageSize int          `json:"pageSize"`
}

func (m ClientMetadata) text(key string) string {
	var s string
	_ = json.Unmarshal(m[key], &s)
	return s
}
func (m ClientMetadata) list(key string) []string {
	var s []string
	_ = json.Unmarshal(m[key], &s)
	return s
}
func (m ClientMetadata) set(key string, value any) { m[key], _ = json.Marshal(value) }
func cloneClient(c ClientRecord) ClientRecord {
	m := make(ClientMetadata, len(c.Metadata))
	for k, v := range c.Metadata {
		m[k] = append(json.RawMessage(nil), v...)
	}
	c.Metadata = m
	return c
}
func clientView(c ClientRecord) ClientView {
	v := ClientView{"client_id": c.ID, "client_id_issued_at": c.IssuedAt, "updated_at": c.UpdatedAt.Unix(), "has_client_secret": c.Secret != ""}
	v["registration_origin"] = "manual"
	if c.Origin != "" {
		v["registration_origin"] = c.Origin
	}
	if c.InitialTokenID != "" {
		v["registration_initial_token_id"] = c.InitialTokenID
	}
	for k, value := range c.Metadata {
		v[k] = append(json.RawMessage(nil), value...)
	}
	if c.Secret != "" {
		v["client_secret_expires_at"] = 0
	}
	compatible, reasons := auditMetadata(c.Metadata)
	v["protocol_compatible"] = compatible
	if !compatible {
		v["protocol_incompatibilities"] = reasons
	}
	return v
}
func needsClientSecret(m ClientMetadata) bool {
	if strings.HasPrefix(m.text("token_endpoint_auth_method"), "client_secret_") {
		return true
	}
	for _, k := range []string{"id_token_signed_response_alg", "userinfo_signed_response_alg", "request_object_signing_alg"} {
		if strings.HasPrefix(m.text(k), "HS") {
			return true
		}
	}
	for _, k := range []string{"id_token_encrypted_response_alg", "userinfo_encrypted_response_alg", "request_object_encryption_alg"} {
		a := m.text(k)
		if a == "dir" || strings.HasPrefix(a, "A") || strings.HasPrefix(a, "PBES2") {
			return true
		}
	}
	return false
}
func (s *Service) ListClients(ctx context.Context, hash, query string, page int) (ClientList, error) {
	result := ClientList{Clients: []ClientView{}, Page: page, PageSize: 10}
	var records []ClientRecord
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		q := strings.ToLower(strings.TrimSpace(query))
		for _, c := range tx.Clients() {
			if q == "" || strings.Contains(strings.ToLower(c.ID+" "+c.Metadata.text("client_name")), q) {
				records = append(records, c)
			}
		}
		return nil
	})
	if err != nil {
		return result, err
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].IssuedAt == records[j].IssuedAt {
			return records[i].ID < records[j].ID
		}
		return records[i].IssuedAt > records[j].IssuedAt
	})
	result.Total = len(records)
	maxPage := max(1, (result.Total+9)/10)
	result.Page = max(1, min(page, maxPage))
	start := (result.Page - 1) * 10
	for _, c := range records[start:min(start+10, result.Total)] {
		result.Clients = append(result.Clients, clientView(c))
	}
	return result, nil
}
func (s *Service) GetClient(ctx context.Context, hash, id string) (ClientView, error) {
	var result ClientView
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		c, err := tx.Client(id)
		if err != nil {
			return err
		}
		result = adminClientView(tx, c)
		return nil
	})
	return result, err
}
func (s *Service) SaveClient(ctx context.Context, hash, id string, input ClientMetadata) (ClientView, error) {
	var result ClientView
	err := s.store.Write(ctx, func(tx Tx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		m, err := normalizeClientMetadata(input)
		if err == nil {
			err = validateLogoutTransport(m, s.allowLogoutHTTP)
		}
		if err != nil {
			return err
		}
		var c ClientRecord
		if id == "" {
			c.ID, err = randomToken()
			if err != nil {
				return err
			}
			c.IssuedAt = s.now().Unix()
		} else {
			c, err = tx.Client(id)
			if err != nil {
				return err
			}
		}
		issued := ""
		if needsClientSecret(m) {
			if c.Secret == "" {
				c.Secret, err = newClientSecret()
				if err != nil {
					return err
				}
				issued = c.Secret
			}
		} else {
			c.Secret = ""
		}
		c.Metadata = m
		c.UpdatedAt = s.now().UTC()
		tx.SaveClient(c)
		result = adminClientView(tx, c)
		if issued != "" {
			result["client_secret"] = issued
		}
		return nil
	})
	return result, err
}
func (s *Service) DeleteClient(ctx context.Context, hash, id string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		if _, err := tx.Client(id); err != nil {
			return err
		}
		tx.DeleteClient(id)
		return nil
	})
}
func (s *Service) RotateClientSecret(ctx context.Context, hash, id string) (ClientView, error) {
	var result ClientView
	err := s.store.Write(ctx, func(tx Tx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		c, err := tx.Client(id)
		if err != nil {
			return err
		}
		if !needsClientSecret(c.Metadata) {
			return ValidationError("This client does not use a client secret.")
		}
		c.Secret, err = newClientSecret()
		if err != nil {
			return err
		}
		c.UpdatedAt = s.now().UTC()
		tx.SaveClient(c)
		result = adminClientView(tx, c)
		result["client_secret"] = c.Secret
		return nil
	})
	return result, err
}

func adminClientView(tx ReadTx, c ClientRecord) ClientView {
	v := clientView(c)
	v["registration_token_active"] = false
	if token, err := tx.RegistrationToken(c.ID); err == nil {
		v["registration_token_active"] = true
		v["registration_token_issued_at"] = token.IssuedAt
	}
	return v
}

// 512 bits accommodates HS512 and symmetric encryption metadata accepted by
// administrative registration as well as the dynamic registration profile.
func newClientSecret() (string, error) {
	a, err := randomToken()
	if err != nil {
		return "", err
	}
	b, err := randomToken()
	if err != nil {
		return "", err
	}
	return a + b, nil
}
