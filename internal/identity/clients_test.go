package identity

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func metadata(t *testing.T, raw string) ClientMetadata {
	t.Helper()
	var m ClientMetadata
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatal(err)
	}
	return m
}
func TestClientMetadataValidation(t *testing.T) {
	base := `{"redirect_uris":["https://app.example.com/callback"]}`
	for _, raw := range []string{
		`{"redirect_uris":[]}`,
		`{"redirect_uris":["https://app.example.com/cb#fragment"]}`,
		`{"redirect_uris":["https://*.example.com/cb"]}`,
		`{"redirect_uris":["https://user:pass@app.example.com/cb"]}`,
		`{"redirect_uris":["javascript:alert(1)"]}`,
		`{"redirect_uris":["http://app.example.com/cb"]}`,
		`{"redirect_uris":["https://app.example.com/cb"],"application_type":"native"}`,
		`{"redirect_uris":["http://localhost/cb"],"response_types":["id_token"],"grant_types":["implicit"]}`,
		`{"redirect_uris":["https://app.example.com/cb"],"response_types":["id_token"]}`,
		`{"redirect_uris":["https://app.example.com/cb"],"response_types":["id_token"],"grant_types":["implicit"],"id_token_signed_response_alg":"none"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"default_max_age":-1}`,
		`{"redirect_uris":["https://app.example.com/cb"],"require_auth_time":"true"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"client_secret":"chosen"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"client_id":"chosen"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"jwks":{"keys":[{"kty":"oct","k":"abc"}]}}`,
		`{"redirect_uris":["https://app.example.com/cb"],"jwks":{"keys":[{"kty":"RSA","n":"AQ","e":"AQAB","d":"AQ"}]}}`,
		`{"redirect_uris":["https://app.example.com/cb"],"jwks_uri":"http://example.com/jwks"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":"private_key_jwt"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_signing_alg":"none"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"id_token_encrypted_response_enc":"A128GCM"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"client_name#":"Bad tag"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"grant_types":null}`,
		`{"redirect_uris":["https://a.example.com/cb","https://b.example.com/cb"],"subject_type":"pairwise"}`,
	} {
		t.Run(raw, func(t *testing.T) {
			if _, err := normalizeClientMetadata(metadata(t, raw)); err == nil {
				t.Fatal("accepted invalid metadata")
			}
		})
	}
	for _, raw := range []string{
		base,
		`{"redirect_uris":["http://127.0.0.1:3000/cb"],"application_type":"native","token_endpoint_auth_method":"none"}`,
		`{"redirect_uris":["com.example.app:/cb"],"application_type":"native"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"client_name#fr":"Portail","default_max_age":0,"require_auth_time":false}`,
		`{"redirect_uris":["https://app.example.com/cb"],"id_token_encrypted_response_alg":"RSA-OAEP-256","jwks_uri":"https://app.example.com/jwks"}`,
		`{"redirect_uris":["https://app.example.com/cb"],"response_types":["token code id_token"],"grant_types":["authorization_code","implicit"]}`,
	} {
		if _, err := normalizeClientMetadata(metadata(t, raw)); err != nil {
			t.Fatal(raw, err)
		}
	}
	m, err := normalizeClientMetadata(metadata(t, base))
	if err != nil {
		t.Fatal(err)
	}
	if m.text("application_type") != "web" || m.text("id_token_signed_response_alg") != "RS256" {
		t.Fatal("missing defaults")
	}
}
func TestClientStoreSnapshotsAndServiceAuthorization(t *testing.T) {
	s, store, _ := fixture(t)
	ctx := context.Background()
	login, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	hash := login.Session.Hash
	input := metadata(t, `{"redirect_uris":["https://app.example.com/cb"],"token_endpoint_auth_method":"none"}`)
	result, err := s.SaveClient(ctx, hash, "", input)
	if err != nil {
		t.Fatal(err)
	}
	id := result["client_id"].(string)
	if _, err := s.SaveClient(ctx, "invalid", "", input); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("service bypassed authentication")
	}
	if err := store.Read(ctx, func(tx ReadTx) error {
		c, err := tx.Client(id)
		if err != nil {
			return err
		}
		c.Metadata.set("client_name", "mutated")
		again, err := tx.Client(id)
		if err != nil {
			return err
		}
		if again.Metadata.text("client_name") != "" {
			t.Fatal("snapshot mutated store")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
