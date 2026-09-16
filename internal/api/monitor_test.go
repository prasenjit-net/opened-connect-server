package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func TestActivityAdminBoundaryPaginationAndRedaction(t *testing.T) {
	rig := newAuthRig(t)
	admin := rig.login(t, "admin@example.com", testPassword)
	created := rig.request(t, "POST", "/admin/users", map[string]any{"name": "Regular", "email": "regular@example.com", "role": "user", "active": true, "password": testPassword}, admin)
	expectStatus(t, created, 201)
	regular := rig.login(t, "regular@example.com", testPassword)
	store, err := identity.NewFileStore(rig.dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.Write(context.Background(), func(tx identity.Tx) error {
		for i := 0; i < 12; i++ {
			tx.SaveAccessToken(identity.AccessToken{Hash: fmt.Sprintf("sensitive-token-hash-%02d", i), ClientID: "portal", UserID: "user", Audience: "userinfo", Scopes: []string{"openid"}, IssuedAt: now.Add(time.Duration(i) * time.Second), ExpiresAt: now.Add(time.Hour)})
		}
		tx.SaveAuthzTransaction(identity.AuthzTransaction{ID: "secret-transaction-id", BrowserBindingHash: "sensitive-browser-binding", Nonce: "sensitive-nonce", State: "sensitive-state", CodeChallenge: "sensitive-challenge", ClientID: "portal", Scopes: []string{"openid"}, CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
		tx.SaveAuthorizationCode(identity.AuthorizationCode{Hash: "sensitive-code-hash", Nonce: "sensitive-code-nonce", CodeChallenge: "sensitive-code-challenge", ClientID: "portal", CreatedAt: now, ExpiresAt: now.Add(time.Minute)})
		tx.SaveConsent(identity.Consent{UserID: "user", ClientID: "portal", GrantedAt: now})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"transactions", "codes", "tokens", "consents", "overview"} {
		path := "/admin/activity/" + kind
		expectStatus(t, rig.request(t, "GET", path, nil, browserSession{}), 401)
		expectStatus(t, rig.request(t, "GET", path, nil, regular), 403)
		result := rig.request(t, "GET", path, nil, admin)
		expectStatus(t, result, 200)
		if result.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("activity can be cached")
		}
		for _, secret := range []string{"sensitive-", "secret-transaction-id", "passwordHash", "browserBindingHash", "codeHash", "codeChallenge"} {
			if strings.Contains(result.Body.String(), secret) {
				t.Fatalf("%s leaked %s", path, secret)
			}
		}
	}
	read := func(path string) identity.ActivityList {
		t.Helper()
		res := rig.request(t, "GET", path, nil, admin)
		expectStatus(t, res, 200)
		var list identity.ActivityList
		if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		return list
	}
	page1 := read("/admin/activity/tokens")
	page2 := read("/admin/activity/tokens?page=2")
	if len(page1.Records) != 10 || len(page2.Records) != 2 || page1.Total != 12 || page1.PageSize != 10 || page2.Page != 2 {
		t.Fatalf("bad pagination: %+v %+v", page1, page2)
	}
	if page1.Records[0].CreatedAt.Before(*page2.Records[0].CreatedAt) {
		t.Fatal("not ordered newest first")
	}
	if got := read("/admin/activity/tokens?q=missing"); got.Total != 0 || len(got.Records) != 0 {
		t.Fatal("search ignored")
	}
	id := page1.Records[0].ID
	path := "/admin/activity/tokens/" + id + "/revoke"
	expectStatus(t, rig.request(t, "POST", path, map[string]any{}, browserSession{}), 401)
	expectStatus(t, rig.request(t, "POST", path, map[string]any{}, regular), 403)
	expectStatus(t, rig.request(t, "POST", path, map[string]any{}, browserSession{cookie: admin.cookie}), 403)
	expectStatus(t, rig.request(t, "POST", path, map[string]any{}, admin), 204)
	expectStatus(t, rig.request(t, "POST", path, map[string]any{}, admin), 204)
	if got := read("/admin/activity/tokens?status=revoked"); got.Total != 1 || got.Records[0].ID != id {
		t.Fatal("revocation not reflected")
	}
	expectStatus(t, rig.request(t, "GET", "/admin/activity/tokens?page=-1", nil, admin), 400)
	expectStatus(t, rig.request(t, "GET", "/admin/activity/tokens?status=bad", nil, admin), 400)
	expectStatus(t, rig.request(t, "GET", "/admin/activity/missing", nil, admin), 404)
	expectStatus(t, rig.request(t, "POST", "/admin/activity/tokens/missing/revoke", map[string]any{}, admin), 404)
	// GET cannot mutate, and browser sessions (rather than protocol bearer
	// credentials) remain the only authority for monitoring APIs.
	expectStatus(t, rig.request(t, http.MethodGet, path, nil, admin), 405)
}

func TestActivityRejectsConsumedCompletedAndExpiredRevocation(t *testing.T) {
	rig := newAuthRig(t)
	admin := rig.login(t, "admin@example.com", testPassword)
	store, err := identity.NewFileStore(rig.dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := store.Write(t.Context(), func(tx identity.Tx) error {
		tx.SaveAuthzTransaction(identity.AuthzTransaction{ID: "completed", Consumed: true, ExpiresAt: now.Add(time.Hour)})
		tx.SaveAuthzTransaction(identity.AuthzTransaction{ID: "expired", ExpiresAt: now.Add(-time.Second)})
		tx.SaveAuthorizationCode(identity.AuthorizationCode{Hash: "consumed", Consumed: true, ExpiresAt: now.Add(time.Hour), TransactionID: "completed"})
		tx.SaveAuthorizationCode(identity.AuthorizationCode{Hash: "expired-code", ExpiresAt: now.Add(-time.Second)})
		tx.SaveAccessToken(identity.AccessToken{Hash: "expired-token", ExpiresAt: now.Add(-time.Second)})
		tx.SaveAccessToken(identity.AccessToken{Hash: "missing-expiry-token"})
		tx.SaveConsent(identity.Consent{UserID: "user", ClientID: "missing-client", GrantedAt: now})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"transactions", "codes", "tokens", "consents"} {
		res := rig.request(t, "GET", "/admin/activity/"+kind, nil, admin)
		expectStatus(t, res, 200)
		var list identity.ActivityList
		if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
			t.Fatal(err)
		}
		if len(list.Records) == 0 {
			t.Fatalf("no %s test records", kind)
		}
		for _, record := range list.Records {
			if record.CanRevoke {
				t.Fatalf("%s %s incorrectly offers revocation", kind, record.Status)
			}
			rejected := rig.request(t, "POST", "/admin/activity/"+kind+"/"+record.ID+"/revoke", map[string]any{}, admin)
			expectStatus(t, rejected, 409)
			if !strings.Contains(rejected.Body.String(), "ACTIVITY_NOT_ACTIVE") {
				t.Fatal("missing lifecycle error")
			}
		}
		after := rig.request(t, "GET", "/admin/activity/"+kind, nil, admin)
		expectStatus(t, after, 200)
		if after.Body.String() != res.Body.String() {
			t.Fatal("rejected revocation changed stored lifecycle")
		}
	}
	// An item can expire after being listed: the POST must check the current
	// state instead of relying on the UI's previously supplied canRevoke flag.
	if err := store.Write(t.Context(), func(tx identity.Tx) error {
		tx.SaveAccessToken(identity.AccessToken{Hash: "stale-list-token", ExpiresAt: now.Add(time.Hour)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	res := rig.request(t, "GET", "/admin/activity/tokens?status=active", nil, admin)
	expectStatus(t, res, 200)
	var list identity.ActivityList
	if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Records) != 1 || !list.Records[0].CanRevoke {
		t.Fatal("active token not revocable")
	}
	if err := store.Write(t.Context(), func(tx identity.Tx) error {
		token, err := tx.AccessToken("stale-list-token")
		if err != nil {
			return err
		}
		token.ExpiresAt = now.Add(-time.Second)
		tx.SaveAccessToken(token)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	expectStatus(t, rig.request(t, "POST", "/admin/activity/tokens/"+list.Records[0].ID+"/revoke", map[string]any{}, admin), 409)
}
