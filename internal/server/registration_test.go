package server

import (
	"context"
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
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/version"
)

func TestDynamicRegistrationHTTPAuthorizationCodeFlow(t *testing.T) {
	cfg := provisionedOIDCConfig(t)
	cfg.OIDC.RegistrationEnabled = true
	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), Options{UIFS: fstest.MapFS{"ui/dist/index.html": {Data: []byte("SPA")}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = app.identity.Bootstrap(context.Background(), "Admin", "admin@example.com", "secure test password"); err != nil {
		t.Fatal(err)
	}
	// Exercise Secure cookies over TLS, matching the browser security contract.
	srv := httptest.NewTLSServer(app.Handler())
	defer srv.Close()
	// Resolve the test issuer before making any requests. Production uses config.
	app.oidc.Config.Issuer = srv.URL
	jar, _ := cookiejar.New(nil)
	browser := srv.Client()
	browser.Jar = jar
	browser.Timeout = 5 * time.Second
	browser.CheckRedirect = func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	csrf := ""
	request := func(method, path, body, contentType, bearer string) (*http.Response, map[string]any) {
		t.Helper()
		r, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if contentType != "" {
			r.Header.Set("Content-Type", contentType)
		}
		if csrf != "" {
			r.Header.Set("X-CSRF-Token", csrf)
		}
		if bearer != "" {
			r.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := browser.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]any{}
		if resp.StatusCode != 302 && resp.StatusCode != 204 {
			if err = json.Unmarshal(data, &out); err != nil {
				t.Fatalf("non-JSON %d: %s", resp.StatusCode, data)
			}
		}
		return resp, out
	}
	expect := func(resp *http.Response, body map[string]any, status int) {
		t.Helper()
		if resp.StatusCode != status {
			t.Fatalf("want %d got %d: %v", status, resp.StatusCode, body)
		}
	}
	resp, body := request("POST", "/api/auth/login", `{"email":"admin@example.com","password":"secure test password"}`, "application/json", "")
	expect(resp, body, 200)
	csrf = body["csrfToken"].(string)
	resp, body = request("POST", "/api/admin/registration-tokens", `{"label":"Integration"}`, "application/json", "")
	expect(resp, body, 201)
	iat := body["token"].(string)
	resp, body = request("POST", "/register", `{}`, "application/json", "")
	expect(resp, body, 401) // The admin browser cookie cannot register a client.
	resp, body = request("POST", "/register", `{"redirect_uris":["https://rp.example/callback"],"token_endpoint_auth_method":"none","client_name":"Dynamic RP"}`, "application/json", iat)
	expect(resp, body, 201)
	id := body["client_id"].(string)
	rat := body["registration_access_token"].(string)
	if body["client_secret"] != nil {
		t.Fatal("public client received secret")
	}
	if body["registration_client_uri"] != srv.URL+"/register/"+id {
		t.Fatal("wrong configuration URL")
	}
	resp, body = request("GET", "/register/"+id, "", "", rat)
	expect(resp, body, 200)
	resp, body = request("GET", "/api/admin/clients/"+id, "", "", "")
	expect(resp, body, 200)
	if body["registration_origin"] != "dynamic" {
		t.Fatal("provenance missing")
	}
	verifier := strings.Repeat("a", 43)
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])
	params := url.Values{"response_type": {"code"}, "client_id": {id}, "redirect_uri": {"https://rp.example/callback"}, "scope": {"openid profile"}, "nonce": {"test-nonce"}, "state": {"test-state"}, "code_challenge": {challenge}, "code_challenge_method": {"S256"}}
	resp, body = request("GET", "/authorize?"+params.Encode(), "", "", "")
	expect(resp, body, 302)
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	tx := loc.Query().Get("tx")
	if tx == "" {
		t.Fatal("authorization transaction missing")
	}
	resp, body = request("POST", "/api/user/authorization/"+tx+"/decision", `{"approve":true,"scopes":["openid","profile"]}`, "application/json", "")
	expect(resp, body, 200)
	redirectTo, ok := body["redirectTo"].(string)
	if body["status"] != "complete" || !ok || redirectTo == "" {
		t.Fatalf("consent did not complete: %v", body)
	}
	callback, err := url.Parse(redirectTo)
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("state") != "test-state" {
		t.Fatal("state not preserved")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "client_id": {id}, "code": {callback.Query().Get("code")}, "redirect_uri": {"https://rp.example/callback"}, "code_verifier": {verifier}}
	resp, body = request("POST", "/token", form.Encode(), "application/x-www-form-urlencoded", "")
	expect(resp, body, 200)
	access := body["access_token"].(string)
	signed, err := jwt.ParseSigned(body["id_token"].(string), []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	jwks := app.oidc.Keys.PublicJWKS()
	keys := jwks.Key(signed.Headers[0].KeyID)
	if len(keys) != 1 {
		t.Fatal("missing signing key")
	}
	var claims jwt.Claims
	if err = signed.Claims(keys[0].Key, &claims); err != nil {
		t.Fatal(err)
	}
	if err = claims.Validate(jwt.Expected{Issuer: srv.URL, AnyAudience: jwt.Audience{id}, Time: time.Now()}); err != nil {
		t.Fatal(err)
	}
	resp, body = request("GET", "/userinfo", "", "", access)
	expect(resp, body, 200)
	// A RAT is not a user access token, and an access token is not a RAT.
	resp, body = request("GET", "/userinfo", "", "", rat)
	expect(resp, body, 401)
	resp, body = request("GET", "/register/"+id, "", "", access)
	expect(resp, body, 401)
	resp, body = request("PUT", "/register/"+id, `{}`, "application/json", rat)
	expect(resp, body, 405)
	resp, body = request("DELETE", "/register/"+id, "", "", rat)
	expect(resp, body, 405)
	resp, body = request("POST", "/api/admin/clients/"+id+"/registration-token", `{}`, "application/json", "")
	expect(resp, body, 201)
	newRAT := body["token"].(string)
	resp, body = request("GET", "/register/"+id, "", "", rat)
	expect(resp, body, 401)
	resp, body = request("GET", "/userinfo", "", "", access)
	expect(resp, body, 200) // RAT replacement must not revoke grants.
	resp, body = request("GET", "/register/"+id, "", "", newRAT)
	expect(resp, body, 200)
	resp, body = request("DELETE", "/api/admin/clients/"+id+"/registration-token", "", "application/json", "")
	expect(resp, body, 204)
	resp, body = request("GET", "/register/"+id, "", "", newRAT)
	expect(resp, body, 401)
	resp, body = request("GET", "/userinfo", "", "", access)
	expect(resp, body, 200) // Explicit RAT revocation also leaves grants intact.
	resp, body = request("POST", "/api/admin/clients/"+id+"/registration-token", `{}`, "application/json", "")
	expect(resp, body, 201)
	newRAT = body["token"].(string)
	resp, body = request("DELETE", "/api/admin/clients/"+id, "", "application/json", "")
	expect(resp, body, 204)
	resp, body = request("GET", "/register/"+id, "", "", newRAT)
	expect(resp, body, 401)
	resp, body = request("GET", "/userinfo", "", "", access)
	expect(resp, body, 401)
}

func TestRegistrationRoutesNeverFallThrough(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, dev := range []bool{false, true} {
			cfg := config.Default()
			cfg.Storage.DataDir = t.TempDir()
			if enabled {
				cfg = provisionedOIDCConfig(t)
			}
			cfg.UI.DevProxyURL = "http://127.0.0.1:1"
			app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), Options{DevMode: dev, UIFS: fstest.MapFS{"ui/dist/index.html": {Data: []byte("SPA")}}})
			if err != nil {
				t.Fatal(err)
			}
			handler := app.Handler()
			for _, route := range [][2]string{{"POST", "/register"}, {"GET", "/register"}, {"GET", "/register/missing"}, {"DELETE", "/register/missing"}, {"GET", "/register/missing/extra"}} {
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(route[0], route[1], nil))
				if !strings.Contains(w.Header().Get("Content-Type"), "application/json") || w.Code < 400 {
					t.Fatalf("protocol path escaped: %v enabled=%v dev=%v code=%d %s", route, enabled, dev, w.Code, w.Body.String())
				}
			}
		}
	}
}
