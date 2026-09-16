package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoveryDocumentReflectsCapabilities(t *testing.T) {
	dir := t.TempDir()
	keys, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := New(nil, nil, keys, Config{Issuer: "https://issuer.example.com/"})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	rec := httptest.NewRecorder()
	svc.DiscoveryHandler(rec, req)

	var doc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc["issuer"] != "https://issuer.example.com" {
		t.Fatalf("expected trailing slash trimmed from issuer, got %v", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "https://issuer.example.com/authorize" {
		t.Fatalf("unexpected authorization_endpoint: %v", doc["authorization_endpoint"])
	}
	for _, absent := range []string{"registration_endpoint", "revocation_endpoint", "introspection_endpoint", "end_session_endpoint"} {
		if _, ok := doc[absent]; ok {
			t.Fatalf("expected %s to be omitted, not just false", absent)
		}
	}
	responseTypes, _ := doc["response_types_supported"].([]any)
	if len(responseTypes) != 1 || responseTypes[0] != "code" {
		t.Fatalf("expected only code response type advertised, got %v", responseTypes)
	}
	if doc["request_parameter_supported"] != false {
		t.Fatal("expected request_parameter_supported to be explicitly false")
	}
}

func TestJWKSHandlerNeverExposesPrivateMaterial(t *testing.T) {
	dir := t.TempDir()
	keys, err := NewFileKeyStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	svc := New(nil, nil, keys, Config{Issuer: "https://issuer.example.com"})

	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	rec := httptest.NewRecorder()
	svc.JWKSHandler(rec, req)

	body := rec.Body.String()
	for _, forbidden := range []string{"\"d\":", "\"p\":", "\"q\":", "PRIVATE KEY"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("JWKS response leaked private material marker %q: %s", forbidden, body)
		}
	}
	var set map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatal(err)
	}
	keysArr, _ := set["keys"].([]any)
	if len(keysArr) != 1 {
		t.Fatalf("expected exactly one published key, got %d", len(keysArr))
	}
}
