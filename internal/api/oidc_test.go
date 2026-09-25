package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/prasenjit-net/openid-connect-server/internal/config"
	"github.com/prasenjit-net/openid-connect-server/internal/identity"
	"github.com/prasenjit-net/openid-connect-server/internal/oidc"
	"github.com/prasenjit-net/openid-connect-server/internal/version"
)

type oidcRig struct {
	handler http.Handler
}

// newOIDCRig builds the real /api router wired to a live oidc.Service, and
// drives /authorize directly (it's mounted at the server level in
// production, outside this package's router) to seed one real pending
// transaction and its binding cookie for the API-level tests below.
func newOIDCRig(t *testing.T) (rig oidcRig, session browserSession, txnID, binding, clientID string, oidcSvc *oidc.Service) {
	t.Helper()
	dir := t.TempDir()
	store, err := identity.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	idsvc, err := identity.NewService(store, 8*time.Hour)
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
	if err := json.Unmarshal([]byte(`{"redirect_uris":["https://rp.example.com/cb"],"token_endpoint_auth_method":"none"}`), &metadata); err != nil {
		t.Fatal(err)
	}
	view, err := idsvc.SaveClient(ctx, login.Session.Hash, "", metadata)
	if err != nil {
		t.Fatal(err)
	}
	clientID, _ = view["client_id"].(string)

	keys, err := oidc.NewFileKeyStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Provision(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Load(ctx); err != nil {
		t.Fatal(err)
	}
	oidcSvc = oidc.New(idsvc, store, keys, oidc.Config{
		Issuer: "https://issuer.example.com", TransactionTTL: 10 * time.Minute,
		CodeTTL: time.Minute, AccessTokenTTL: 10 * time.Minute, IDTokenTTL: 5 * time.Minute,
	})

	cfg := config.Default()
	cfg.Storage.DataDir = dir
	handler := NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), idsvc, oidcSvc)

	params := url.Values{
		"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://rp.example.com/cb"},
		"scope": {"openid profile"}, "state": {"xyz"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
	}
	authReq := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	authReq.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: login.Token})
	authRec := httptest.NewRecorder()
	oidcSvc.AuthorizeHandler(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("expected /authorize to redirect, got %d: %s", authRec.Code, authRec.Body.String())
	}
	loc, err := url.Parse(authRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	txnID = loc.Query().Get("tx")
	for _, c := range authRec.Result().Cookies() {
		if c.Name == "ocs_authz_binding" {
			binding = c.Value
		}
	}
	if txnID == "" || binding == "" {
		t.Fatalf("failed to seed a transaction: %s", authRec.Header().Get("Location"))
	}

	session = browserSession{cookie: &http.Cookie{Name: identity.SessionCookieName, Value: login.Token}, csrf: login.Session.CSRF}
	return oidcRig{handler: handler}, session, txnID, binding, clientID, oidcSvc
}

func (rig oidcRig) request(t *testing.T, method, path string, body any, session browserSession, binding string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	if session.cookie != nil {
		req.AddCookie(session.cookie)
	}
	if session.csrf != "" {
		req.Header.Set("X-CSRF-Token", session.csrf)
	}
	if binding != "" {
		req.AddCookie(&http.Cookie{Name: "ocs_authz_binding", Value: binding})
	}
	rec := httptest.NewRecorder()
	rig.handler.ServeHTTP(rec, req)
	return rec
}

func TestAPIAuthorizationStatusRequiresConsent(t *testing.T) {
	rig, session, txnID, binding, _, _ := newOIDCRig(t)

	rec := rig.request(t, http.MethodGet, "/user/authorization/"+txnID, nil, session, binding)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var view oidc.TransactionView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Status != "consent_required" {
		t.Fatalf("expected consent_required, got %+v", view)
	}
}

func TestAPIAuthorizationDecisionRequiresCSRF(t *testing.T) {
	rig, session, txnID, binding, _, _ := newOIDCRig(t)

	noCSRF := session
	noCSRF.csrf = ""
	rec := rig.request(t, http.MethodPost, "/user/authorization/"+txnID+"/decision", map[string]any{"approve": true, "scopes": []string{"openid", "profile"}}, noCSRF, binding)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected CSRF protection to reject the request, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestAPIAuthorizationDecisionApproves(t *testing.T) {
	rig, session, txnID, binding, _, _ := newOIDCRig(t)

	rec := rig.request(t, http.MethodPost, "/user/authorization/"+txnID+"/decision", map[string]any{"approve": true, "scopes": []string{"openid", "profile"}}, session, binding)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var view oidc.TransactionView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Status != "complete" || view.RedirectTo == "" {
		t.Fatalf("expected a completed redirect, got %+v", view)
	}
	u, err := url.Parse(view.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code") == "" {
		t.Fatalf("expected an authorization code in the redirect, got %s", view.RedirectTo)
	}
}

func TestBearerAccessTokenCannotUnlockAdminAPI(t *testing.T) {
	rig, session, txnID, binding, clientID, oidcSvc := newOIDCRig(t)
	decisionRec := rig.request(t, http.MethodPost, "/user/authorization/"+txnID+"/decision", map[string]any{"approve": true, "scopes": []string{"openid", "profile"}}, session, binding)
	var decided oidc.TransactionView
	if err := json.Unmarshal(decisionRec.Body.Bytes(), &decided); err != nil {
		t.Fatal(err)
	}
	redirectTo, err := url.Parse(decided.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	code := redirectTo.Query().Get("code")

	// The seeded client is registered with token_endpoint_auth_method
	// "none", so it self-identifies via client_id alone. Drive /token
	// directly against the oidc.Service (it's mounted at the server level
	// in production, outside this package's router) to mint a real access
	// token exactly as an independent relying party would.
	form := url.Values{
		"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
		"redirect_uri": {"https://rp.example.com/cb"}, "code_verifier": {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	oidcSvc.TokenHandler(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("expected the token exchange to succeed, got %d: %s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tokenRec.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	adminReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	adminRec := httptest.NewRecorder()
	rig.handler.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusUnauthorized {
		t.Fatalf("a bearer access token must never unlock /api/admin; got %d: %s", adminRec.Code, adminRec.Body.String())
	}
}
