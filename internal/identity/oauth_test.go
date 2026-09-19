package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOAuthMigrationPreservesLegacyTokenAndClonesPolicy(t *testing.T) {
	_, store, user := fixture(t)
	now := time.Now()
	var metadata ClientMetadata
	_ = json.Unmarshal([]byte(`{"grant_types":["authorization_code"],"response_types":["code"],"token_endpoint_auth_method":"none"}`), &metadata)
	if err := store.Write(t.Context(), func(tx Tx) error {
		tx.SaveClient(ClientRecord{ID: "rp", Metadata: metadata, UpdatedAt: now.Add(-time.Second)})
		tx.SaveAccessToken(AccessToken{Hash: "legacy", ClientID: "rp", UserID: user.ID, Audience: "userinfo", Scopes: []string{"openid"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	state["version"] = 3
	raw, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(store.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.Read(t.Context(), func(tx ReadTx) error {
		token, e := tx.AccessToken("legacy")
		if e != nil {
			return e
		}
		if token.GrantType != "authorization_code" || token.SubjectKind != "user" || token.FamilyID != "" {
			t.Fatalf("incorrect migration %+v", token)
		}
		active, e := AccessTokenActive(tx, token, now, nil)
		if !active {
			t.Fatal("valid legacy token lost authority")
		}
		if len(tx.OAuthPolicy("rp").Grants) != 0 || len(tx.ListRefreshFamilies()) != 0 {
			t.Fatal("migration created new authority")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if err = reopened.Write(t.Context(), func(tx Tx) error {
		p := OAuthPolicy{Resources: map[string]ResourceScopes{"https://api.example": {Allowed: []string{"read"}, Default: []string{"read"}}}}
		tx.SaveOAuthPolicy("rp", p)
		p.Resources["https://api.example"].Allowed[0] = "write"
		copy := tx.OAuthPolicy("rp")
		copy.Resources["https://api.example"].Allowed[0] = "delete"
		if tx.OAuthPolicy("rp").Resources["https://api.example"].Allowed[0] != "read" {
			t.Fatal("policy snapshot aliases stored state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &state); err != nil {
		t.Fatal(err)
	}
	if state["version"] != float64(currentVersion) {
		t.Fatal("migration not persisted")
	}
}

func TestRefreshLifecycleSecurityInvalidation(t *testing.T) {
	for _, action := range []string{"client", "policy", "entitlement", "user", "consent", "registration"} {
		t.Run(action, func(t *testing.T) {
			_, store, user := fixture(t)
			now := time.Now()
			if err := store.Write(t.Context(), func(tx Tx) error {
				tx.SaveClient(ClientRecord{ID: "client", Metadata: ClientMetadata{}, UpdatedAt: now})
				tx.SaveRefreshFamily(RefreshFamily{ID: "family", ClientID: "client", UserID: user.ID, AbsoluteExpiry: now.Add(time.Hour), IdleExpiry: now.Add(time.Hour), RetainUntil: now.Add(2 * time.Hour)})
				tx.SaveRefreshToken(RefreshToken{Hash: "refresh-hash", FamilyID: "family", IssuedAt: now})
				tx.SaveAccessToken(AccessToken{Hash: "access-hash", ClientID: "client", UserID: user.ID, FamilyID: "family", IssuedAt: now, ExpiresAt: now.Add(time.Hour)})
				switch action {
				case "client":
					tx.DeleteClient("client")
				case "policy":
					tx.SaveOAuthPolicy("client", OAuthPolicy{})
				case "entitlement":
					tx.SaveOAuthAccess(user.ID, OAuthAccess{})
				case "user":
					tx.DeleteUser(user.ID)
				case "consent":
					tx.SaveConsent(Consent{ClientID: "client", UserID: user.ID, Revoked: true})
				case "registration":
					tx.DeleteRegistrationToken("client")
				}
				f, e := tx.RefreshFamily("family")
				if e != nil {
					return e
				}
				a, e := tx.AccessToken("access-hash")
				if e != nil {
					return e
				}
				shouldRevoke := action != "registration"
				if f.Revoked != shouldRevoke || a.Revoked != shouldRevoke {
					t.Fatal("incorrect family security invalidation")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
