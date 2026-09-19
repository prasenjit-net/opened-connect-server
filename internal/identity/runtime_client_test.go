package identity

import (
	"context"
	"testing"
)

func TestProtocolClientDoesNotRequireSession(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	admin, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.SaveClient(ctx, admin.Session.Hash, "", metadata(t, `{"redirect_uris":["https://app.example.com/cb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	id := created["client_id"].(string)

	// No session hash is passed at all: a protocol request has no admin browser session.
	client, err := s.ProtocolClient(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if client.ID != id {
		t.Fatalf("expected client id %s, got %s", id, client.ID)
	}
	if !client.Compatible {
		t.Fatalf("expected default client to be protocol-compatible, got reasons=%v", client.IncompatibilityReasons)
	}
	if len(client.RedirectURIs) != 1 || client.RedirectURIs[0] != "https://app.example.com/cb" {
		t.Fatalf("unexpected redirect URIs: %v", client.RedirectURIs)
	}
	if client.TokenEndpointAuthMethod != "client_secret_basic" || client.Secret == "" {
		t.Fatalf("expected a client secret to be present in plaintext for a secret_basic client")
	}
}

func TestProtocolClientFlagsIncompatibleMetadata(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	admin, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.SaveClient(ctx, admin.Session.Hash, "", metadata(t, `{"redirect_uris":["https://a.example.com/cb","https://b.example.com/cb"],"subject_type":"pairwise","sector_identifier_uri":"https://sector.example.com/redirects.json"}`))
	if err != nil {
		t.Fatal(err)
	}
	id := created["client_id"].(string)
	client, err := s.ProtocolClient(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if client.Compatible {
		t.Fatal("expected pairwise client to be flagged incompatible")
	}
	if len(client.IncompatibilityReasons) == 0 {
		t.Fatal("expected incompatibility reasons")
	}
}

func TestClientViewExposesProtocolCompatibility(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	admin, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	view, err := s.SaveClient(ctx, admin.Session.Hash, "", metadata(t, `{"redirect_uris":["https://app.example.com/cb"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if compatible, ok := view["protocol_compatible"].(bool); !ok || !compatible {
		t.Fatalf("expected protocol_compatible=true in client view, got %v", view["protocol_compatible"])
	}
	if _, present := view["protocol_incompatibilities"]; present {
		t.Fatal("compatible client should not carry incompatibility reasons")
	}
}
