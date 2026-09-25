package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

const testPassword = "a secure test password"

type testFixture struct {
	svc         *Service
	idsvc       *identity.Service
	store       identity.Store
	dataDir     string
	clientID    string
	adminHash   string
	adminToken  string
	adminID     string
	redirectURI string
}

// newTestFixture builds a real file-backed identity store with a bootstrapped
// admin and one registered client, plus an oidc.Service wired to a
// freshly-provisioned signing key store — mirroring how server.New wires
// things in production, without any mocks.
func newTestFixture(t *testing.T, redirectURI string) *testFixture {
	t.Helper()
	dataDir := t.TempDir()
	store, err := identity.NewFileStore(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	idsvc, err := identity.NewService(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	admin, err := idsvc.Bootstrap(ctx, "Admin", "admin@example.com", testPassword)
	if err != nil {
		t.Fatal(err)
	}
	login, err := idsvc.Login(ctx, admin.Email, testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	// A public client (token_endpoint_auth_method "none") keeps most tests
	// focused on the authorization/consent/code-exchange flow itself,
	// without also having to carry a client secret through every request;
	// TestConfidentialClientAuthenticatesWithClientSecretBasic exercises the
	// secret-based path explicitly.
	var metadata identity.ClientMetadata
	raw := fmt.Sprintf(`{"redirect_uris":[%q],"token_endpoint_auth_method":"none"}`, redirectURI)
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil {
		t.Fatal(err)
	}
	view, err := idsvc.SaveClient(ctx, login.Session.Hash, "", metadata)
	if err != nil {
		t.Fatal(err)
	}
	clientID, _ := view["client_id"].(string)

	keys, err := NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Load(ctx); err != nil {
		t.Fatal(err)
	}

	svc := New(idsvc, store, keys, Config{
		Issuer:         "https://issuer.example.com",
		TransactionTTL: 10 * time.Minute,
		CodeTTL:        time.Minute,
		AccessTokenTTL: 10 * time.Minute,
		IDTokenTTL:     5 * time.Minute,
	})
	return &testFixture{
		svc: svc, idsvc: idsvc, store: store, dataDir: dataDir,
		clientID: clientID, adminHash: login.Session.Hash, adminToken: login.Token, adminID: admin.ID,
		redirectURI: redirectURI,
	}
}
