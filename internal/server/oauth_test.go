package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/prasenjit-net/openid-connect-server/internal/identity"
	"github.com/prasenjit-net/openid-connect-server/internal/version"
)

func TestOAuthHTTPRefreshAndMachineLifecycle(t *testing.T) {
	cfg := provisionedOIDCConfig(t)
	cfg.OAuth.RefreshTokensEnabled = true
	cfg.OAuth.Resources = []identity.Resource{{Audience: "https://api.example", Scopes: []string{"read"}, Enabled: true}}
	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), Options{UIFS: fstest.MapFS{"ui/dist/index.html": {Data: []byte("SPA")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.identity.Bootstrap(t.Context(), "Admin", "admin@example.com", "secure test password"); err != nil {
		t.Fatal(err)
	}
	login, err := app.identity.Login(t.Context(), "admin@example.com", "secure test password", "")
	if err != nil {
		t.Fatal(err)
	}
	create := func(raw string) map[string]any {
		t.Helper()
		var m identity.ClientMetadata
		_ = json.Unmarshal([]byte(raw), &m)
		v, e := app.identity.SaveClient(t.Context(), login.Session.Hash, "", m)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	rp := create(`{"redirect_uris":["https://rp.example/cb"],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"none"}`)
	id := rp["client_id"].(string)
	if err = app.identity.SetOAuthPolicy(t.Context(), login.Session.Hash, id, identity.OAuthPolicy{Grants: []string{"refresh_token"}, RefreshEnabled: true}, cfg.OAuth.Resources); err != nil {
		t.Fatal(err)
	}
	machine := create(`{"grant_types":["client_credentials"],"token_endpoint_auth_method":"client_secret_post"}`)
	mid := machine["client_id"].(string)
	if err = app.identity.SetOAuthPolicy(t.Context(), login.Session.Hash, mid, identity.OAuthPolicy{Grants: []string{"client_credentials"}, Resources: map[string]identity.ResourceScopes{"https://api.example": {Allowed: []string{"read"}, Default: []string{"read"}}}, DefaultResource: "https://api.example", IntrospectionEnabled: true, IntrospectionAudiences: []string{"https://api.example"}}, cfg.OAuth.Resources); err != nil {
		t.Fatal(err)
	}
	// Exercise Secure cookies over TLS, matching the browser security contract.
	srv := httptest.NewTLSServer(app.Handler())
	defer srv.Close()
	app.oidc.Config.Issuer = srv.URL
	jar, _ := cookiejar.New(nil)
	browser := srv.Client()
	browser.Jar = jar
	browser.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	csrf := ""
	call := func(method, path, body, contentType, bearer string) (*http.Response, map[string]any) {
		t.Helper()
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}
		if csrf != "" {
			req.Header.Set("X-CSRF-Token", csrf)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, e := browser.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		defer resp.Body.Close()
		raw, e := io.ReadAll(resp.Body)
		if e != nil {
			t.Fatal(e)
		}
		out := map[string]any{}
		if len(raw) > 0 && strings.Contains(resp.Header.Get("Content-Type"), "json") {
			if e = json.Unmarshal(raw, &out); e != nil {
				t.Fatal(e)
			}
		}
		return resp, out
	}
	expect := func(resp *http.Response, out map[string]any, status int) {
		t.Helper()
		if resp.StatusCode != status {
			t.Fatalf("want %d got %d %+v", status, resp.StatusCode, out)
		}
	}
	resp, out := call("GET", "/.well-known/oauth-authorization-server", "", "", "")
	expect(resp, out, 200)
	if out["revocation_endpoint"] != srv.URL+"/revoke" {
		t.Fatal("bad OAuth metadata")
	}
	resp, out = call("POST", "/api/auth/login", `{"email":"admin@example.com","password":"secure test password"}`, "application/json", "")
	expect(resp, out, 200)
	csrf = out["csrfToken"].(string)
	verifier := strings.Repeat("a", 43)
	digest := sha256.Sum256([]byte(verifier))
	params := url.Values{"client_id": {id}, "redirect_uri": {"https://rp.example/cb"}, "response_type": {"code"}, "scope": {"openid profile offline_access"}, "prompt": {"consent"}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(digest[:])}}
	resp, out = call("GET", "/authorize?"+params.Encode(), "", "", "")
	expect(resp, out, 302)
	loc, _ := url.Parse(resp.Header.Get("Location"))
	tx := loc.Query().Get("tx")
	if tx == "" {
		t.Fatal("no authorization transaction")
	}
	resp, out = call("POST", "/api/user/authorization/"+tx+"/decision", `{"approve":true,"scopes":["openid","profile","offline_access"]}`, "application/json", "")
	expect(resp, out, 200)
	redirectTo, ok := out["redirectTo"].(string)
	if out["status"] != "complete" || !ok || redirectTo == "" {
		t.Fatalf("consent did not complete: %v", out)
	}
	redirect, err := url.Parse(redirectTo)
	if err != nil {
		t.Fatal(err)
	}
	code := redirect.Query().Get("code")
	form := url.Values{"client_id": {id}, "grant_type": {"authorization_code"}, "redirect_uri": {"https://rp.example/cb"}, "code": {code}, "code_verifier": {verifier}}
	resp, out = call("POST", "/token", form.Encode(), "application/x-www-form-urlencoded", "")
	expect(resp, out, 200)
	refresh, ok := out["refresh_token"].(string)
	if !ok || refresh == "" {
		t.Fatal("missing refresh token")
	}
	form = url.Values{"client_id": {id}, "grant_type": {"refresh_token"}, "refresh_token": {refresh}}
	resp, out = call("POST", "/token", form.Encode(), "application/x-www-form-urlencoded", "")
	expect(resp, out, 200)
	if _, exists := out["id_token"]; exists {
		t.Fatal("refresh unexpectedly minted ID token")
	}
	access := out["access_token"].(string)
	resp, out = call("GET", "/userinfo", "", "", access)
	expect(resp, out, 200)
	resp, out = call("POST", "/token", form.Encode(), "application/x-www-form-urlencoded", "")
	expect(resp, out, 400)
	resp, out = call("GET", "/userinfo", "", "", access)
	expect(resp, out, 401)
	form = url.Values{"client_id": {mid}, "client_secret": {machine["client_secret"].(string)}, "grant_type": {"client_credentials"}}
	resp, out = call("POST", "/token", form.Encode(), "application/x-www-form-urlencoded", "")
	expect(resp, out, 200)
	access = out["access_token"].(string)
	form.Del("grant_type")
	form.Set("token", access)
	resp, out = call("POST", "/introspect", form.Encode(), "application/x-www-form-urlencoded", "")
	expect(resp, out, 200)
	if out["active"] != true || out["sub"] != "client:"+mid {
		t.Fatal("machine introspection failed")
	}
	// Protocol bearer credentials alone cannot authenticate a management session.
	browser.Jar = nil
	csrf = ""
	resp, out = call("GET", "/api/admin/users", "", "", access)
	expect(resp, out, 401)
	resp, out = call("GET", "/api/user/profile", "", "", access)
	expect(resp, out, 401)
	resp, out = call("POST", "/revoke", form.Encode(), "application/x-www-form-urlencoded", "")
	expect(resp, out, 200)
	resp, out = call("POST", "/introspect", form.Encode(), "application/x-www-form-urlencoded", "")
	expect(resp, out, 200)
	if out["active"] != false || len(out) != 1 {
		t.Fatal("revocation not effective")
	}
}
