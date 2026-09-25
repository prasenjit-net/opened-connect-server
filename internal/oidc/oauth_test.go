package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

const testAudience = "https://api.example.com"

func oauthClient(t *testing.T, f *testFixture, grants []string) (string, string) {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"grant_types": grants, "token_endpoint_auth_method": "client_secret_post"})
	var metadata identity.ClientMetadata
	_ = json.Unmarshal(raw, &metadata)
	view, err := f.idsvc.SaveClient(t.Context(), f.adminHash, "", metadata)
	if err != nil {
		t.Fatal(err)
	}
	return view["client_id"].(string), view["client_secret"].(string)
}
func permitOAuth(t *testing.T, f *testFixture, id string, p identity.OAuthPolicy) {
	t.Helper()
	if err := f.idsvc.SetOAuthPolicy(t.Context(), f.adminHash, id, p, f.svc.Config.Resources); err != nil {
		t.Fatal(err)
	}
}
func oauthCall(f *testFixture, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	switch path {
	case "/token":
		f.svc.TokenHandler(w, r)
	case "/introspect":
		f.svc.IntrospectHandler(w, r)
	case "/revoke":
		f.svc.RevokeHandler(w, r)
	}
	return w
}
func responseToken(t *testing.T, w *httptest.ResponseRecorder) tokenResponse {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("token failed: %d %s", w.Code, w.Body.String())
	}
	var out tokenResponse
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func expectOAuth(t *testing.T, w *httptest.ResponseRecorder, status int, code string) {
	t.Helper()
	if w.Code != status || !strings.Contains(w.Body.String(), `"error":"`+code+`"`) {
		t.Fatalf("want %d %s got %d %s", status, code, w.Code, w.Body.String())
	}
}
func userInfoStatus(f *testFixture, raw string) int {
	r := httptest.NewRequest("GET", "/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+raw)
	w := httptest.NewRecorder()
	f.svc.UserInfoHandler(w, r)
	return w.Code
}
func TestOAuthResourceTokenLifecycleAndAudienceIsolation(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/cb")
	f.svc.Config.Resources = []identity.Resource{{Audience: testAudience, Scopes: []string{"read", "write"}, Enabled: true}, {Audience: "https://other.example", Scopes: []string{"read"}, Enabled: true}}
	id, secret := oauthClient(t, f, []string{"client_credentials"})
	request := url.Values{"client_id": {id}, "client_secret": {secret}, "grant_type": {"client_credentials"}}
	expectOAuth(t, oauthCall(f, "/token", request), 400, "unauthorized_client")
	p := identity.OAuthPolicy{Grants: []string{"client_credentials"}, DefaultResource: testAudience, Resources: map[string]identity.ResourceScopes{testAudience: {Allowed: []string{"read", "write"}, Default: []string{"read"}}}}
	permitOAuth(t, f, id, p)
	token := responseToken(t, oauthCall(f, "/token", request))
	if token.IDToken != "" || token.RefreshToken != "" || token.Scope != "read" {
		t.Fatal("machine token acquired user authority")
	}
	if userInfoStatus(f, token.AccessToken) != 401 {
		t.Fatal("machine token accepted by UserInfo")
	}
	inspector, key := oauthClient(t, f, []string{"client_credentials"})
	inspection := url.Values{"client_id": {inspector}, "client_secret": {key}, "token": {token.AccessToken}, "token_type_hint": {"refresh_token"}}
	expectOAuth(t, oauthCall(f, "/introspect", inspection), 403, "access_denied")
	permitOAuth(t, f, inspector, identity.OAuthPolicy{IntrospectionEnabled: true, IntrospectionAudiences: []string{"https://other.example"}})
	if w := oauthCall(f, "/introspect", inspection); w.Code != 200 || strings.TrimSpace(w.Body.String()) != `{"active":false}` {
		t.Fatalf("foreign audience leak: %s", w.Body.String())
	}
	permitOAuth(t, f, inspector, identity.OAuthPolicy{IntrospectionEnabled: true, IntrospectionAudiences: []string{testAudience}})
	w := oauthCall(f, "/introspect", inspection)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out["active"] != true || out["sub"] != "client:"+id || out["aud"] != testAudience {
		t.Fatalf("bad machine introspection %s", w.Body.String())
	}
	// An unrelated caller cannot revoke the token even if it can introspect it.
	if w = oauthCall(f, "/revoke", inspection); w.Code != 200 || w.Body.Len() != 0 {
		t.Fatal("foreign revocation failed")
	}
	if !strings.Contains(oauthCall(f, "/introspect", inspection).Body.String(), `"active":true`) {
		t.Fatal("foreign revocation changed token")
	}
	request.Set("scope", "openid")
	expectOAuth(t, oauthCall(f, "/token", request), 400, "invalid_scope")
	request.Del("scope")
	request.Set("resource", "https://other.example")
	expectOAuth(t, oauthCall(f, "/token", request), 400, "invalid_target")
	request["resource"] = []string{testAudience, testAudience}
	expectOAuth(t, oauthCall(f, "/token", request), 400, "invalid_target")
	revoke := url.Values{"client_id": {id}, "client_secret": {secret}, "token": {token.AccessToken}, "token_type_hint": {"unknown"}}
	for i := 0; i < 2; i++ {
		if w = oauthCall(f, "/revoke", revoke); w.Code != 200 || w.Body.Len() != 0 {
			t.Fatal("idempotent revoke failed")
		}
	}
	if strings.TrimSpace(oauthCall(f, "/introspect", inspection).Body.String()) != `{"active":false}` {
		t.Fatal("revoked token active")
	}
	inspection.Set("token", "unknown")
	if strings.TrimSpace(oauthCall(f, "/introspect", inspection).Body.String()) != `{"active":false}` {
		t.Fatal("unknown token leaked")
	}
	expectOAuth(t, oauthCall(f, "/introspect", url.Values{"client_id": {f.clientID}, "token": {"unknown"}}), 403, "access_denied")
}
func enableRefresh(t *testing.T, f *testFixture) {
	t.Helper()
	f.svc.Config.RefreshTokensEnabled = true
	f.svc.Config.RefreshMaxTTL = 30 * 24 * time.Hour
	f.svc.Config.RefreshInactivityTTL = 7 * 24 * time.Hour
	raw, _ := json.Marshal(map[string]any{"redirect_uris": []string{f.redirectURI}, "grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none"})
	var m identity.ClientMetadata
	_ = json.Unmarshal(raw, &m)
	if _, err := f.idsvc.SaveClient(t.Context(), f.adminHash, f.clientID, m); err != nil {
		t.Fatal(err)
	}
	permitOAuth(t, f, f.clientID, identity.OAuthPolicy{Grants: []string{"refresh_token"}, RefreshEnabled: true})
}
func offlineCode(t *testing.T, f *testFixture) string {
	t.Helper()
	params := baseAuthorizeParams(f.clientID, f.redirectURI)
	params.Set("scope", "openid profile offline_access")
	params.Set("prompt", "consent")
	rec := doAuthorize(f, params, f.adminToken)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || loc.Query().Get("tx") == "" {
		t.Fatalf("offline authorize %d %s", rec.Code, rec.Header().Get("Location"))
	}
	req := httptest.NewRequest("POST", "/decision", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	result := f.svc.Decide(req, principalFor(t, f, f.adminToken), loc.Query().Get("tx"), true, strings.Fields(params.Get("scope")))
	u, _ := url.Parse(result.RedirectTo)
	if result.Status != "complete" || u.Query().Get("code") == "" {
		t.Fatalf("offline consent %+v", result)
	}
	return u.Query().Get("code")
}
func TestRefreshRotationReplayAndRestart(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/cb")
	enableRefresh(t, f)
	params := baseAuthorizeParams(f.clientID, f.redirectURI)
	params.Set("scope", "openid offline_access")
	if loc := doAuthorize(f, params, f.adminToken).Header().Get("Location"); !strings.Contains(loc, "invalid_scope") {
		t.Fatal("offline granted without explicit prompt")
	}
	code := offlineCode(t, f)
	first := responseToken(t, doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)))
	if first.RefreshToken == "" {
		t.Fatal("no refresh token")
	}
	form := url.Values{"client_id": {f.clientID}, "grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}}
	other, _ := oauthClient(t, f, []string{"client_credentials"})
	form.Set("client_id", other)
	expectOAuth(t, doToken(f, form), 401, "invalid_client")
	form.Set("client_id", f.clientID)
	form.Set("scope", "openid email")
	expectOAuth(t, doToken(f, form), 400, "invalid_scope")
	form.Set("scope", "openid")
	form.Set("resource", "https://evil.example")
	expectOAuth(t, doToken(f, form), 400, "invalid_target")
	form.Del("resource")
	next := responseToken(t, doToken(f, form))
	if next.IDToken != "" || next.RefreshToken == first.RefreshToken || next.Scope != "openid" {
		t.Fatal("incorrect rotation")
	}
	if userInfoStatus(f, next.AccessToken) != 200 {
		t.Fatal("refreshed UserInfo failed")
	}
	form.Set("refresh_token", next.RefreshToken)
	form.Set("scope", "openid profile")
	expectOAuth(t, doToken(f, form), 400, "invalid_scope")
	form.Del("scope")
	// Reopen persisted state, preserving rotation and replay evidence.
	restarted, err := identity.NewFileStore(f.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	f.svc.Store = restarted
	form.Set("refresh_token", first.RefreshToken)
	expectOAuth(t, doToken(f, form), 400, "invalid_grant")
	if userInfoStatus(f, first.AccessToken) != 401 || userInfoStatus(f, next.AccessToken) != 401 {
		t.Fatal("replay did not revoke descendants")
	}
	form.Set("refresh_token", next.RefreshToken)
	expectOAuth(t, doToken(f, form), 400, "invalid_grant")
}
func TestRefreshConcurrentExchangeAndCodeReplay(t *testing.T) {
	for _, attack := range []string{"concurrent", "code"} {
		t.Run(attack, func(t *testing.T) {
			f := newTestFixture(t, "https://rp.example/cb")
			enableRefresh(t, f)
			code := offlineCode(t, f)
			first := responseToken(t, doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)))
			form := url.Values{"client_id": {f.clientID}, "grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}}
			if attack == "code" {
				expectOAuth(t, doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)), 400, "invalid_grant")
				expectOAuth(t, doToken(f, form), 400, "invalid_grant")
			} else {
				var wg sync.WaitGroup
				results := make(chan *httptest.ResponseRecorder, 2)
				for i := 0; i < 2; i++ {
					wg.Add(1)
					go func() { defer wg.Done(); results <- doToken(f, form) }()
				}
				wg.Wait()
				close(results)
				success := 0
				for w := range results {
					if w.Code == 200 {
						success++
						token := responseToken(t, w)
						if userInfoStatus(f, token.AccessToken) != 401 {
							t.Fatal("concurrent replay left winner usable")
						}
					} else {
						expectOAuth(t, w, 400, "invalid_grant")
					}
				}
				if success != 1 {
					t.Fatalf("successes %d", success)
				}
			}
			if userInfoStatus(f, first.AccessToken) != 401 {
				t.Fatal("original token survived family revocation")
			}
		})
	}
}
func TestRefreshExpiryLogoutAndRevocation(t *testing.T) {
	for _, action := range []string{"idle", "absolute", "logout", "access", "refresh", "consent", "password", "wrong-client", "disabled"} {
		t.Run(action, func(t *testing.T) {
			f := newTestFixture(t, "https://rp.example/cb")
			enableRefresh(t, f)
			first := responseToken(t, doToken(f, tokenForm(f.clientID, offlineCode(t, f), f.redirectURI, testPKCEVerifier)))
			form := url.Values{"client_id": {f.clientID}, "grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}}
			succeeds := false
			switch action {
			case "idle":
				f.svc.Now = func() time.Time { return time.Now().Add(8 * 24 * time.Hour) }
			case "absolute":
				f.svc.Now = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
			case "logout":
				if err := f.idsvc.Logout(t.Context(), f.adminHash); err != nil {
					t.Fatal(err)
				}
				succeeds = true
			case "access", "refresh":
				raw := first.AccessToken
				if action == "refresh" {
					raw = first.RefreshToken
				}
				w := oauthCall(f, "/revoke", url.Values{"client_id": {f.clientID}, "token": {raw}})
				if w.Code != 200 {
					t.Fatal(w.Body.String())
				}
				succeeds = action == "access"
			case "consent":
				if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
					c, e := tx.Consent(f.adminID, f.clientID)
					if e != nil {
						return e
					}
					c.Revoked = true
					tx.SaveConsent(c)
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			case "password":
				if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
					u, e := tx.User(f.adminID)
					if e != nil {
						return e
					}
					u.PasswordHash = "changed"
					return tx.SaveUser(u)
				}); err != nil {
					t.Fatal(err)
				}
			case "wrong-client":
				m := identity.ClientMetadata{"redirect_uris": json.RawMessage(`["https://other.example/cb"]`), "token_endpoint_auth_method": json.RawMessage(`"none"`)}
				view, e := f.idsvc.SaveClient(t.Context(), f.adminHash, "", m)
				if e != nil {
					t.Fatal(e)
				}
				form.Set("client_id", view["client_id"].(string))
				expectOAuth(t, doToken(f, form), 400, "invalid_grant")
				form.Set("client_id", f.clientID)
				succeeds = true
			case "disabled":
				f.svc.Config.RefreshTokensEnabled = false
				expectOAuth(t, doToken(f, form), 400, "unsupported_grant_type")
				f.svc.Config.RefreshTokensEnabled = true
				succeeds = true
			}
			if succeeds {
				responseToken(t, doToken(f, form))
			} else {
				expectOAuth(t, doToken(f, form), 400, "invalid_grant")
			}
		})
	}
}
func TestLegacyPasswordRequiresPolicyAndUserEntitlements(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/cb")
	f.svc.Config.Resources = []identity.Resource{{Audience: testAudience, Scopes: []string{"read"}, Enabled: true}}
	id, secret := oauthClient(t, f, []string{"password"})
	form := url.Values{"client_id": {id}, "client_secret": {secret}, "grant_type": {"password"}, "username": {"admin@example.com"}, "password": {testPassword}}
	expectOAuth(t, doToken(f, form), 400, "unsupported_grant_type")
	f.svc.Config.PasswordGrantEnabled = true
	expectOAuth(t, doToken(f, form), 400, "unauthorized_client")
	permitOAuth(t, f, id, identity.OAuthPolicy{Grants: []string{"password"}, PasswordEnabled: true, DefaultResource: testAudience, Resources: map[string]identity.ResourceScopes{testAudience: {Allowed: []string{"read"}, Default: []string{"read"}}}})
	expectOAuth(t, doToken(f, form), 400, "invalid_grant") // Admin role confers no OAuth entitlements.
	if err := f.idsvc.SetOAuthAccess(t.Context(), f.adminHash, f.adminID, identity.OAuthAccess{testAudience: []string{"read"}}, f.svc.Config.Resources); err != nil {
		t.Fatal(err)
	}
	w := doToken(f, form)
	token := responseToken(t, w)
	if len(w.Result().Cookies()) != 0 || token.IDToken != "" || token.RefreshToken != "" {
		t.Fatal("password grant created login authority")
	}
	for _, username := range []string{"missing@example.com", "admin@example.com"} {
		form.Set("username", username)
		form.Set("password", "wrong")
		expectOAuth(t, doToken(f, form), 400, "invalid_grant")
	}
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		u, e := tx.User(f.adminID)
		if e != nil {
			return e
		}
		u.Active = false
		return tx.SaveUser(u)
	}); err != nil {
		t.Fatal(err)
	}
	form.Set("password", testPassword)
	expectOAuth(t, doToken(f, form), 400, "invalid_grant")
	if err := f.store.Read(t.Context(), func(tx identity.ReadTx) error {
		stored, e := tx.AccessToken(hashToken(token.AccessToken))
		if e != nil {
			return e
		}
		active, e := identity.AccessTokenActive(tx, stored, time.Now(), f.svc.Config.Resources)
		if active {
			t.Fatal("disabled user's token still active")
		}
		return e
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshFailedCommitAndRetainedReplayEvidence(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/cb")
	enableRefresh(t, f)
	code := offlineCode(t, f)
	exchange := tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)
	f.svc.Store = failedCommitStore{f.store}
	expectOAuth(t, doToken(f, exchange), 503, "server_error")
	f.svc.Store = f.store
	first := responseToken(t, doToken(f, exchange))
	form := url.Values{"client_id": {f.clientID}, "grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}}
	f.svc.Store = failedCommitStore{f.store}
	w := doToken(f, form)
	expectOAuth(t, w, 503, "server_error")
	if strings.Contains(w.Body.String(), "access_token") {
		t.Fatal("uncommitted credentials escaped")
	}
	f.svc.Store = f.store
	next := responseToken(t, doToken(f, form))
	revoke := url.Values{"client_id": {f.clientID}, "token": {next.RefreshToken}}
	f.svc.Store = failedCommitStore{f.store}
	expectOAuth(t, oauthCall(f, "/revoke", revoke), 503, "server_error")
	f.svc.Store = f.store
	if userInfoStatus(f, next.AccessToken) != 200 {
		t.Fatal("failed revocation partially committed")
	}
	now := time.Now().Add(24 * time.Hour)
	f.svc.Now = func() time.Time { return now }
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error { tx.PruneOIDCState(now); return nil }); err != nil {
		t.Fatal(err)
	}
	form.Set("refresh_token", next.RefreshToken)
	newer := responseToken(t, doToken(f, form))
	expectOAuth(t, doToken(f, exchange), 400, "invalid_grant")
	if userInfoStatus(f, newer.AccessToken) != 401 {
		t.Fatal("pruning destroyed code replay evidence")
	}
}
func TestRefreshInspectionRequiresAudienceAndOwnClient(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/cb")
	enableRefresh(t, f)
	var metadata identity.ClientMetadata
	_ = json.Unmarshal([]byte(`{"redirect_uris":["https://rp.example/cb"],"grant_types":["authorization_code","refresh_token"],"token_endpoint_auth_method":"client_secret_post"}`), &metadata)
	view, err := f.idsvc.SaveClient(t.Context(), f.adminHash, f.clientID, metadata)
	if err != nil {
		t.Fatal(err)
	}
	secret := view["client_secret"].(string)
	p := identity.OAuthPolicy{Grants: []string{"refresh_token"}, RefreshEnabled: true, IntrospectionEnabled: true, RefreshInspection: true, IntrospectionAudiences: []string{"userinfo"}}
	permitOAuth(t, f, f.clientID, p)
	form := tokenForm(f.clientID, offlineCode(t, f), f.redirectURI, testPKCEVerifier)
	form.Set("client_secret", secret)
	first := responseToken(t, doToken(f, form))
	inspect := url.Values{"client_id": {f.clientID}, "client_secret": {secret}, "token": {first.RefreshToken}}
	w := oauthCall(f, "/introspect", inspect)
	if !strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal(w.Body.String())
	}
	other, key := oauthClient(t, f, []string{"client_credentials"})
	permitOAuth(t, f, other, identity.OAuthPolicy{IntrospectionEnabled: true, IntrospectionAudiences: []string{"userinfo"}, RefreshInspection: true})
	inspect.Set("client_id", other)
	inspect.Set("client_secret", key)
	if strings.TrimSpace(oauthCall(f, "/introspect", inspect).Body.String()) != `{"active":false}` {
		t.Fatal("foreign refresh information disclosed")
	}
	form = url.Values{"client_id": {f.clientID}, "client_secret": {secret}, "grant_type": {"refresh_token"}, "refresh_token": {first.RefreshToken}}
	responseToken(t, doToken(f, form))
	inspect.Set("client_id", f.clientID)
	inspect.Set("client_secret", secret)
	if strings.TrimSpace(oauthCall(f, "/introspect", inspect).Body.String()) != `{"active":false}` {
		t.Fatal("consumed refresh token active")
	}
	// Consumed credentials remain valid evidence for idempotent family revocation.
	if w = oauthCall(f, "/revoke", inspect); w.Code != 200 {
		t.Fatal(w.Body.String())
	}
}

type unreadableOAuthStore struct{ identity.Store }

func (s unreadableOAuthStore) Read(context.Context, func(identity.ReadTx) error) error {
	return errors.New("storage unavailable")
}
func TestOAuthInfrastructureFailuresAreNotInactiveOrSuccessful(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/cb")
	f.svc.Config.Resources = []identity.Resource{{Audience: testAudience, Scopes: []string{"read"}, Enabled: true}}
	id, key := oauthClient(t, f, []string{"client_credentials"})
	permitOAuth(t, f, id, identity.OAuthPolicy{Grants: []string{"client_credentials"}, DefaultResource: testAudience, Resources: map[string]identity.ResourceScopes{testAudience: {Allowed: []string{"read"}, Default: []string{"read"}}}, IntrospectionEnabled: true, IntrospectionAudiences: []string{testAudience}})
	form := url.Values{"client_id": {id}, "client_secret": {key}, "grant_type": {"client_credentials"}}
	f.svc.Store = failedCommitStore{f.store}
	expectOAuth(t, doToken(f, form), 503, "server_error")
	f.svc.Store = f.store
	first := responseToken(t, doToken(f, form))
	form.Set("token", first.AccessToken)
	f.svc.Store = unreadableOAuthStore{f.store}
	expectOAuth(t, oauthCall(f, "/introspect", form), 503, "server_error")
	f.svc.Store = failedCommitStore{f.store}
	expectOAuth(t, oauthCall(f, "/revoke", form), 503, "server_error")
	f.svc.Store = f.store
	if w := oauthCall(f, "/introspect", form); !strings.Contains(w.Body.String(), `"active":true`) {
		t.Fatal("failed revocation changed token")
	}
}
