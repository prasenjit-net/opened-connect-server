package oidc

import (
	"encoding/json"
	"errors"
	"github.com/prasenjit-net/openid-connect-server/internal/identity"
	"net/http/httptest"
	"testing"
)

func TestAdminRevocationBlocksProtocolUse(t *testing.T) {
	for _, kind := range []string{"tokens", "consents"} {
		t.Run(kind, func(t *testing.T) {
			f := newTestFixture(t, "https://rp.example.com/cb")
			code := obtainCode(t, f, "openid profile")
			response := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier))
			if response.Code != 200 {
				t.Fatal(response.Body.String())
			}
			var tokens tokenResponse
			if err := json.Unmarshal(response.Body.Bytes(), &tokens); err != nil {
				t.Fatal(err)
			}
			records, err := f.idsvc.Activity(t.Context(), f.adminHash, kind, identity.ActivityOptions{})
			if err != nil || len(records.Records) != 1 {
				t.Fatalf("missing %s record: %+v %v", kind, records, err)
			}
			if kind == "tokens" && records.Records[0].IDTokenExpiresAt == nil {
				t.Fatal("ID token expiry not recorded")
			}
			if err := f.idsvc.RevokeActivity(t.Context(), f.adminHash, kind, records.Records[0].ID); err != nil {
				t.Fatal(err)
			}
			if got := probeUserinfo(f, tokens.AccessToken); got != 401 {
				t.Fatalf("revoked %s still permits access: %d", kind, got)
			}
			if w := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)); w.Code != 400 {
				t.Fatal("code reuse accepted")
			}
		})
	}
}
func TestConsentRevocationCancelsPendingGrantsOnlyForItsClient(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid")
	id, r := probeTransaction(t, f, "")
	principal := principalFor(t, f, f.adminToken)
	// Another client's token must remain unaffected by this user's consent revocation.
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		tx.SaveAccessToken(identity.AccessToken{Hash: "other-token", ClientID: "other-client", UserID: f.adminID})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	consents, err := f.idsvc.Activity(t.Context(), f.adminHash, "consents", identity.ActivityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.idsvc.RevokeActivity(t.Context(), f.adminHash, "consents", consents.Records[0].ID); err != nil {
		t.Fatal(err)
	}
	if w := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)); w.Code != 400 {
		t.Fatal("pending code survived consent revocation")
	}
	if result := f.svc.Decide(r, principal, id, true, []string{"openid"}); result.Status != "error" {
		t.Fatal("pending interaction survived consent revocation")
	}
	if err := f.store.Read(t.Context(), func(tx identity.ReadTx) error {
		other, err := tx.AccessToken("other-token")
		if other.Revoked {
			t.Fatal("unrelated client revoked")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	newID, newR := probeTransaction(t, f, "")
	if view := f.svc.Status(newR, principal, newID); view.Status != "consent_required" {
		t.Fatalf("revoked consent reused: %+v", view)
	}
}
func TestAdminCancelsPendingTransactionAndUnusedCode(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	id, r := probeTransaction(t, f, "")
	rows, err := f.idsvc.Activity(t.Context(), f.adminHash, "transactions", identity.ActivityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.idsvc.RevokeActivity(t.Context(), f.adminHash, "transactions", rows.Records[0].ID); err != nil {
		t.Fatal(err)
	}
	if out := f.svc.Decide(r, principalFor(t, f, f.adminToken), id, true, []string{"openid"}); out.Status != "error" {
		t.Fatal("revoked transaction issued code")
	}
	code := obtainCode(t, f, "openid")
	codes, err := f.idsvc.Activity(t.Context(), f.adminHash, "codes", identity.ActivityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.idsvc.RevokeActivity(t.Context(), f.adminHash, "codes", codes.Records[0].ID); err != nil {
		t.Fatal(err)
	}
	if w := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)); w.Code != 400 {
		t.Fatal("revoked unused code exchanged")
	}
	overview, err := f.idsvc.ActivityOverview(t.Context(), f.adminHash)
	if err != nil {
		t.Fatal(err)
	}
	if overview.Counts["codes"].Revoked != 1 || overview.Counts["transactions"].Revoked != 1 || overview.Users != 1 || overview.Clients != 1 {
		t.Fatalf("incorrect overview: %+v", overview)
	}
}

func TestAdminRevocationSerializesWithTokenIssuance(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid")
	rows, err := f.idsvc.Activity(t.Context(), f.adminHash, "codes", identity.ActivityOptions{})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	revoked := make(chan error, 1)
	issued := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		<-start
		revoked <- f.idsvc.RevokeActivity(t.Context(), f.adminHash, "codes", rows.Records[0].ID)
	}()
	go func() { <-start; issued <- doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)) }()
	close(start)
	revokeErr := <-revoked
	response := <-issued
	if response.Code == 200 {
		var token tokenResponse
		if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil {
			t.Fatal(err)
		}
		if !errors.Is(revokeErr, identity.ErrActivityNotActive) {
			t.Fatalf("consumed code revocation should be rejected: %v", revokeErr)
		}
		if probeUserinfo(f, token.AccessToken) != 200 {
			t.Fatal("rejected code revocation modified issued token")
		}
	} else if response.Code != 400 || revokeErr != nil {
		t.Fatalf("unexpected exchange/revocation result: %d %v", response.Code, revokeErr)
	}
}
