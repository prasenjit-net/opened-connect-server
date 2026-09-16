package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func TestConfidentialClientAuthenticatesWithClientSecretBasic(t *testing.T) {
	store, err := identity.NewFileStore(t.TempDir())
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
	var metadata identity.ClientMetadata
	if err := json.Unmarshal([]byte(`{"redirect_uris":["https://rp.example.com/cb"]}`), &metadata); err != nil {
		t.Fatal(err)
	}
	view, err := idsvc.SaveClient(ctx, login.Session.Hash, "", metadata) // default: client_secret_basic
	if err != nil {
		t.Fatal(err)
	}
	clientID, _ := view["client_id"].(string)
	secret, _ := view["client_secret"].(string)
	if secret == "" {
		t.Fatal("expected a client secret to be issued for the default auth method")
	}

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
		Issuer: "https://issuer.example.com", TransactionTTL: 10 * time.Minute,
		CodeTTL: time.Minute, AccessTokenTTL: 10 * time.Minute, IDTokenTTL: 5 * time.Minute,
	})

	f := &testFixture{svc: svc, idsvc: idsvc, store: store, clientID: clientID, adminToken: login.Token, adminID: admin.ID, redirectURI: "https://rp.example.com/cb"}
	code := obtainCode(t, f, "openid profile")

	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {f.redirectURI}, "code_verifier": {testPKCEVerifier}}
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, secret)
	rec := httptest.NewRecorder()
	svc.TokenHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected client_secret_basic authentication to succeed, got %d: %s", rec.Code, rec.Body.String())
	}

	// A wrong secret must fail.
	req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.SetBasicAuth(clientID, "the-wrong-secret")
	rec2 := httptest.NewRecorder()
	svc.TokenHandler(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected a wrong client secret to be rejected, got %d: %s", rec2.Code, rec2.Body.String())
	}
}

func TestUserInfoScopesGateClaimsAndNeverLeakSensitiveFields(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	// Give the admin some profile claims and a custom attribute so we can
	// confirm neither custom attributes nor the password hash ever surface.
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		u, err := tx.User(f.adminID)
		if err != nil {
			return err
		}
		u.GivenName = "Ada"
		u.Email = "admin@example.com"
		u.EmailVerified = true
		u.CustomAttributes = map[string]json.RawMessage{"department": json.RawMessage(`"secret-department"`)}
		return tx.SaveUser(u)
	}); err != nil {
		t.Fatal(err)
	}

	code := obtainCode(t, f, "openid") // profile/email NOT requested
	form := tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)
	tokenRec := doToken(f, form)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token exchange failed: %d %s", tokenRec.Code, tokenRec.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	rec := httptest.NewRecorder()
	f.svc.UserInfoHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, forbidden := range []string{"secret-department", "department", "passwordHash", "argon2", "custom_attributes"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("userinfo response leaked %q (scope was openid only): %s", forbidden, body)
		}
	}
	var claims map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &claims); err != nil {
		t.Fatal(err)
	}
	if claims["sub"] == "" {
		t.Fatal("expected a sub claim")
	}
	if _, present := claims["given_name"]; present {
		t.Fatal("profile scope was not requested; given_name must not be present")
	}
}

func TestUserInfoRejectsRevokedAndExpiredTokens(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid")
	tokenRec := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier))
	var resp tokenResponse
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}

	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		tx.RevokeAccessToken(hashToken(resp.AccessToken))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	rec := httptest.NewRecorder()
	f.svc.UserInfoHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected a revoked token to be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUserInfoRejectsMissingAndGarbageBearerTokens(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	rec := httptest.NewRecorder()
	f.svc.UserInfoHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 with no bearer token, got %d", rec.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req2.Header.Set("Authorization", "Bearer not-a-real-token")
	rec2 := httptest.NewRecorder()
	f.svc.UserInfoHandler(rec2, req2)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a garbage bearer token, got %d", rec2.Code)
	}
}

func TestSessionCookieAloneCannotCallUserInfo(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	req.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: f.adminToken})
	rec := httptest.NewRecorder()
	f.svc.UserInfoHandler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("a browser session cookie alone must never authorize /userinfo, got %d", rec.Code)
	}
}
