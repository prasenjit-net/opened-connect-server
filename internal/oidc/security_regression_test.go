package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

func probeUserinfo(f *testFixture, token string) int {
	r := httptest.NewRequest("GET", "/userinfo", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	f.svc.UserInfoHandler(w, r)
	return w.Code
}
func TestReviewReplayRevokesAccess(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid")
	form := tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)
	first := doToken(f, form)
	var out tokenResponse
	_ = json.Unmarshal(first.Body.Bytes(), &out)
	replay := doToken(f, form)
	if replay.Code != 400 {
		t.Fatal("replay not rejected")
	}
	if status := probeUserinfo(f, out.AccessToken); status != 401 {
		t.Fatalf("replay rejected but original access token still works: %d", status)
	}
}
func TestReviewDeletedClientRevokesAccess(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid")
	first := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier))
	var out tokenResponse
	_ = json.Unmarshal(first.Body.Bytes(), &out)
	if err := f.idsvc.DeleteClient(context.Background(), f.adminHash, f.clientID); err != nil {
		t.Fatal(err)
	}
	if status := probeUserinfo(f, out.AccessToken); status != 401 {
		t.Fatalf("access token works after client deletion: %d", status)
	}
}
func probeTransaction(t *testing.T, f *testFixture, prompt string) (string, *http.Request) {
	p := baseAuthorizeParams(f.clientID, f.redirectURI)
	if prompt != "" {
		p.Set("prompt", prompt)
	}
	w := doAuthorize(f, p, f.adminToken)
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Path == "/login" {
		u, _ = url.Parse(u.Query().Get("redirect"))
	}
	r := httptest.NewRequest("POST", "/api/user/authorization/x/decision", nil)
	for _, c := range w.Result().Cookies() {
		if c.Name == authzBindingCookieName {
			r.AddCookie(c)
		}
	}
	return u.Query().Get("tx"), r
}
func TestReviewPromptLoginNeedsFreshSession(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	id, r := probeTransaction(t, f, "login")
	out := f.svc.Decide(r, principalFor(t, f, f.adminToken), id, true, []string{"openid"})
	if out.Status == "complete" {
		t.Fatalf("prompt=login completed using preexisting principal without new login")
	}
}
func TestReviewDuplicateTokenParameter(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid")
	form := tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)
	form.Add("code", "different-code")
	if w := doToken(f, form); w.Code == 200 {
		t.Fatal("duplicate code parameter accepted")
	}
}
func TestReviewConcurrentConsentSingleCode(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	id, r := probeTransaction(t, f, "")
	p := principalFor(t, f, f.adminToken)

	var wg sync.WaitGroup
	ch := make(chan string, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out := f.svc.Decide(r, p, id, true, []string{"openid"})
			u, _ := url.Parse(out.RedirectTo)
			ch <- u.Query().Get("code")
		}()
	}
	wg.Wait()
	close(ch)
	codes := map[string]bool{}
	for c := range ch {
		if c != "" {
			codes[c] = true
		}
	}
	if len(codes) != 1 {
		t.Fatalf("same consent transaction minted %d distinct codes", len(codes))
	}
}
func TestReviewRejectsUnsupportedRequestObject(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	p := baseAuthorizeParams(f.clientID, f.redirectURI)
	p.Set("request", "invalid.jwt.value")
	w := doAuthorize(f, p, f.adminToken)
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Query().Get("error") != "request_not_supported" {
		t.Fatalf("unsupported request object ignored, continued to %s", u.Path)
	}
}
func TestReviewSignedUserInfoCompatibility(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	var m identity.ClientMetadata
	_ = json.Unmarshal([]byte(`{"redirect_uris":["https://rp.example.com/cb"],"token_endpoint_auth_method":"none","userinfo_signed_response_alg":"RS256"}`), &m)
	if _, err := f.idsvc.SaveClient(context.Background(), f.adminHash, f.clientID, m); err != nil {
		t.Fatal(err)
	}
	c, err := f.idsvc.ProtocolClient(context.Background(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	if c.Compatible {
		t.Fatal("signed UserInfo client accepted though handler always returns unsigned JSON")
	}
}
func TestReviewSuccessfulAuthLimit(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	r := httptest.NewRequest("POST", "/token", nil)
	v := url.Values{"client_id": {f.clientID}}
	for i := 0; i < 31; i++ {
		if _, err := f.svc.authenticateClient(r, v); err != nil {
			t.Fatalf("valid client authentication %d fails: %v", i+1, err)
		}
	}
}

// Simulate a failure after the callback has prepared every mutation, before
// commit. The real store must roll back all of those writes.
type failedCommitStore struct{ identity.Store }

func (s failedCommitStore) Write(ctx context.Context, fn func(identity.Tx) error) error {
	return s.Store.Write(ctx, func(tx identity.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return errors.New("injected commit failure")
	})
}

func TestIssuanceFailureLeavesCodeUsable(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	for _, failure := range []string{"signing", "commit"} {
		t.Run(failure, func(t *testing.T) {
			code := obtainCode(t, f, "openid")
			form := tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)
			keys := f.svc.Keys
			if failure == "signing" {
				f.svc.Keys = &KeyStore{}
			} else {
				f.svc.Store = failedCommitStore{f.store}
			}
			failed := doToken(f, form)
			if failed.Code != 503 {
				t.Fatalf("expected server_error, got %d %s", failed.Code, failed.Body.String())
			}
			f.svc.Keys = keys
			f.svc.Store = f.store
			if retry := doToken(f, form); retry.Code != 200 {
				t.Fatalf("retry after failed issuance: %d %s", retry.Code, retry.Body.String())
			}
		})
	}
}
func TestFailedConsentCommitCanBeRetried(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	id, r := probeTransaction(t, f, "")
	p := principalFor(t, f, f.adminToken)
	f.svc.Store = failedCommitStore{f.store}
	if out := f.svc.Decide(r, p, id, true, []string{"openid"}); out.Status != "error" {
		t.Fatalf("uncommitted code escaped: %+v", out)
	}
	f.svc.Store = f.store
	if out := f.svc.Decide(r, p, id, true, []string{"openid"}); out.Status != "complete" {
		t.Fatalf("retry: %+v", out)
	}
}
func TestReplayEvidenceOutlivesCodeAndRequiresProof(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid")
	form := tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)
	first := doToken(f, form)
	var out tokenResponse
	if err := json.Unmarshal(first.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if first.Code != 200 {
		t.Fatal(first.Body.String())
	}
	wrong := tokenForm(f.clientID, code, f.redirectURI, strings.Repeat("b", 43))
	if w := doToken(f, wrong); w.Code != 400 {
		t.Fatal("bad proof accepted")
	}
	if probeUserinfo(f, out.AccessToken) != 200 {
		t.Fatal("wrong proof revoked valid access")
	}
	now := time.Now().Add(2 * f.svc.Config.CodeTTL)
	f.svc.Now = func() time.Time { return now }
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error { tx.PruneOIDCState(now); return nil }); err != nil {
		t.Fatal(err)
	}
	if w := doToken(f, form); w.Code != 400 {
		t.Fatal("replay accepted")
	}
	if probeUserinfo(f, out.AccessToken) != 401 {
		t.Fatal("expired code tombstone did not revoke access")
	}
}
func TestExpiredUnusedCodeRejected(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid")
	now := time.Now().Add(2 * f.svc.Config.CodeTTL)
	f.svc.Now = func() time.Time { return now }
	if w := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)); w.Code != 400 {
		t.Fatal("expired code accepted")
	}
}
func TestFreshLoginSatisfiesReauthentication(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	id, r := probeTransaction(t, f, "login")
	login, err := f.idsvc.Login(t.Context(), "admin@example.com", testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if out := f.svc.Decide(r, login.Principal, id, true, []string{"openid"}); out.Status != "complete" {
		t.Fatalf("fresh login rejected: %+v", out)
	}
}
func TestDefaultMaxAgeZeroAndLargeMaxAge(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		c, err := tx.Client(f.clientID)
		if err != nil {
			return err
		}
		c.Metadata["default_max_age"] = json.RawMessage(`0`)
		tx.SaveClient(c)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := baseAuthorizeParams(f.clientID, f.redirectURI)
	w := doAuthorize(f, p, f.adminToken)
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Path != "/login" {
		t.Fatalf("zero default did not force login: %s", u)
	}
	p.Set("max_age", "9223372036854775807")
	w = doAuthorize(f, p, f.adminToken)
	u, _ = url.Parse(w.Header().Get("Location"))
	if u.Path != "/oidc/continue" {
		t.Fatalf("max_age overflow: %s", u)
	}
}
func TestSecurityChangesInvalidateAllGrants(t *testing.T) {
	for _, mutation := range []string{"password", "email", "role", "active", "client_metadata", "client_secret", "client_delete"} {
		t.Run(mutation, func(t *testing.T) {
			f := newTestFixture(t, "https://rp.example.com/cb")
			firstCode := obtainCode(t, f, "openid")
			first := doToken(f, tokenForm(f.clientID, firstCode, f.redirectURI, testPKCEVerifier))
			var out tokenResponse
			_ = json.Unmarshal(first.Body.Bytes(), &out)
			code := obtainCode(t, f, "openid")
			id, r := probeTransaction(t, f, "")
			principal := principalFor(t, f, f.adminToken)
			if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
				if strings.HasPrefix(mutation, "client_") {
					c, err := tx.Client(f.clientID)
					if err != nil {
						return err
					}
					switch mutation {
					case "client_delete":
						tx.DeleteClient(c.ID)
					case "client_metadata":
						c.Metadata["client_name"] = json.RawMessage(`"Changed"`)
						tx.SaveClient(c)
					case "client_secret":
						c.Secret = "changed"
						tx.SaveClient(c)
					}
				} else {
					u, err := tx.User(f.adminID)
					if err != nil {
						return err
					}
					switch mutation {
					case "password":
						u.PasswordHash += "changed"
					case "email":
						u.Email = "changed@example.com"
					case "role":
						u.Role = identity.RoleUser
					case "active":
						u.Active = false
					}
					return tx.SaveUser(u)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if probeUserinfo(f, out.AccessToken) != 401 {
				t.Fatal("token survived security mutation")
			}
			if w := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)); w.Code == 200 {
				t.Fatal("code survived security mutation")
			}
			if view := f.svc.Decide(r, principal, id, true, []string{"openid"}); view.Status == "complete" {
				t.Fatal("transaction survived security mutation")
			}
			if err := f.store.Read(t.Context(), func(tx identity.ReadTx) error {
				_, err := tx.Consent(f.adminID, f.clientID)
				if !errors.Is(err, identity.ErrNotFound) {
					t.Fatal("consent survived mutation")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestProtocolParameterValidation(t *testing.T) {
	for _, tc := range []struct{ method, target, body string }{
		{"GET", "/authorize?client_id=ok&bad=%zz", ""},
		{"GET", "/authorize?scope=a&scope=b", ""},
		{"POST", "/token?code=query", "code=body"},
		{"POST", "/token", "code=%zz"},
		{"POST", "/token", "code=" + strings.Repeat("a", maxProtocolRequestBytes)},
	} {
		r := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := parseProtocolForm(r); err == nil {
			t.Errorf("invalid input accepted: %s", tc.target)
		}
	}
}
func TestClientAuthenticationParsing(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	r.SetBasicAuth(url.QueryEscape("client:with spaces"), url.QueryEscape("secret+%: value"))
	auth, err := extractClientAuth(r, url.Values{})
	if err != nil || auth.clientID != "client:with spaces" || auth.secret != "secret+%: value" {
		t.Fatalf("OAuth Basic decoding: %+v %v", auth, err)
	}
	for _, form := range []url.Values{{"client_id": {"other"}}, {"client_secret": {""}}, {"client_id": {"a", "b"}}} {
		if _, err := extractClientAuth(r, form); err == nil {
			t.Fatal("conflicting credentials accepted")
		}
	}
	r.Header.Set("Authorization", "Bearer ignored")
	if _, err := extractClientAuth(r, url.Values{"client_id": {"public"}}); err == nil {
		t.Fatal("malformed authentication ignored")
	}
}
func TestAuthenticationFailuresAreSourceScoped(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	bad := httptest.NewRequest("POST", "/token", nil)
	bad.RemoteAddr = "192.0.2.1:123"
	form := url.Values{"client_id": {f.clientID}, "client_secret": {"wrong"}}
	for i := 0; i < 30; i++ {
		_, _ = f.svc.authenticateClient(bad, form)
	}
	if _, err := f.svc.authenticateClient(bad, form); !errors.Is(err, ErrClientAuthLimited) {
		t.Fatalf("failed credentials not limited: %v", err)
	}
	other := httptest.NewRequest("POST", "/token", nil)
	other.RemoteAddr = "192.0.2.2:456"
	if _, err := f.svc.authenticateClient(other, url.Values{"client_id": {f.clientID}}); err != nil {
		t.Fatalf("other source locked out: %v", err)
	}
}
func TestCertificateLifetimeAndIssuerConsistency(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	svc := New(f.idsvc, f.store, f.svc.Keys, Config{Issuer: "https://issuer.example.com/", IDTokenTTL: time.Minute})
	client, err := f.idsvc.ProtocolClient(t.Context(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := svc.signIDToken(client, f.adminID, "", time.Now(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	var claims jwt.Claims
	if err := token.Claims(f.svc.Keys.PublicJWKS().Keys[0].Key, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != svc.discoveryDocument().Issuer {
		t.Fatal("discovery/JWT issuer mismatch")
	}
	expires := f.svc.Keys.active.cert.NotAfter
	for _, now := range []time.Time{expires.Add(-30 * time.Second), expires, expires.Add(time.Second), f.svc.Keys.active.cert.NotBefore.Add(-time.Second)} {
		if _, err := svc.signIDToken(client, f.adminID, "", now, now); err == nil {
			t.Fatalf("certificate boundary accepted: %s", now)
		}
	}
}
func TestBrowserOriginPolicyAndTrafficLimits(t *testing.T) {
	svc := New(nil, nil, nil, Config{AllowedOrigins: []string{"https://rp.example.com"}})
	for _, origin := range []string{"https://rp.example.com", "https://evil.example.com", "null"} {
		r := httptest.NewRequest("OPTIONS", "/token", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		svc.CORSPreflight(w, r)
		if origin == "https://rp.example.com" {
			if w.Code != 204 || w.Header().Get("Access-Control-Allow-Origin") != origin {
				t.Fatal("configured origin rejected")
			}
		} else if w.Code != 403 || w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Fatal("unconfigured origin accepted")
		}
		if w.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatal("credentialed CORS enabled")
		}
	}
	r := httptest.NewRequest("GET", "/authorize", nil)
	for i := 0; i < 240; i++ {
		if !svc.allowTraffic(httptest.NewRecorder(), r, "authorize") {
			t.Fatal("early limit")
		}
	}
	w := httptest.NewRecorder()
	if svc.allowTraffic(w, r, "authorize") || w.Code != 429 {
		t.Fatal("traffic not bounded")
	}
}
func TestConcurrentBrowserTabsKeepBinding(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	firstID, binding := startTransaction(t, f, f.adminToken)
	p := baseAuthorizeParams(f.clientID, f.redirectURI)
	r := httptest.NewRequest("GET", "/authorize?"+p.Encode(), nil)
	r.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: f.adminToken})
	r.AddCookie(&http.Cookie{Name: authzBindingCookieName, Value: binding})
	w := httptest.NewRecorder()
	f.svc.AuthorizeHandler(w, r)
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == authzBindingCookieName && cookie.Value != binding {
			t.Fatal("second tab replaced binding")
		}
	}
	if out := f.svc.Decide(statusRequest(f, f.adminToken, binding), principalFor(t, f, f.adminToken), firstID, true, []string{"openid"}); out.Status != "complete" {
		t.Fatalf("first tab invalidated: %+v", out)
	}
}

func TestMaxAgeReauthenticationCannotUseStalePrincipal(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	// Stale, but unexpired, sessions still authenticate to management APIs.
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		session, err := tx.Session(f.adminHash)
		if err != nil {
			return err
		}
		session.AuthTime = time.Now().Add(-5 * time.Minute)
		tx.SaveSession(session)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	p := baseAuthorizeParams(f.clientID, f.redirectURI)
	p.Set("max_age", "60")
	w := doAuthorize(f, p, f.adminToken)
	u, _ := url.Parse(w.Header().Get("Location"))
	if u.Path != "/login" {
		t.Fatalf("stale session skipped login: %s", u)
	}
	continuation, _ := url.Parse(u.Query().Get("redirect"))
	r := httptest.NewRequest("POST", "/api/user/authorization/x/decision", nil)
	for _, cookie := range w.Result().Cookies() {
		if cookie.Name == authzBindingCookieName {
			r.AddCookie(cookie)
		}
	}
	if out := f.svc.Decide(r, principalFor(t, f, f.adminToken), continuation.Query().Get("tx"), true, []string{"openid"}); out.Status != "error" {
		t.Fatalf("max_age bypass: %+v", out)
	}
	login, err := f.idsvc.Login(t.Context(), "admin@example.com", testPassword, "")
	if err != nil {
		t.Fatal(err)
	}
	if out := f.svc.Decide(r, login.Principal, continuation.Query().Get("tx"), true, []string{"openid"}); out.Status != "complete" {
		t.Fatalf("fresh max_age session rejected: %+v", out)
	}
}
func TestAutomaticAndExplicitConsentShareConsumption(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	_ = obtainCode(t, f, "openid profile") // covering consent
	id, r := probeTransaction(t, f, "")
	p := principalFor(t, f, f.adminToken)
	// A second store instance exercises the filesystem transaction boundary,
	// rather than relying on one Service's in-memory mutex.
	otherStore, err := identity.NewFileStore(f.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	other := New(f.idsvc, otherStore, f.svc.Keys, f.svc.Config)
	results := make(chan TransactionView, 2)
	start := make(chan struct{})
	go func() { <-start; results <- f.svc.Status(r, p, id) }()
	go func() { <-start; results <- other.Decide(r, p, id, true, []string{"openid", "profile"}) }()
	close(start)
	completed := 0
	for i := 0; i < 2; i++ {
		view := <-results
		if view.Status == "complete" {
			u, _ := url.Parse(view.RedirectTo)
			if u.Query().Get("code") != "" {
				completed++
			}
		}
	}
	if completed != 1 {
		t.Fatalf("concurrent automatic/explicit completion issued %d codes", completed)
	}
}
func TestUnsupportedAuthorizationModesFailExplicitly(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	for _, tc := range []struct{ key, value, code string }{{"request_uri", "https://rp.example.com/request.jwt", "request_uri_not_supported"}, {"response_mode", "fragment", "invalid_request"}, {"claims", `{"id_token":{"acr":{"essential":true}}}`, "invalid_request"}} {
		p := baseAuthorizeParams(f.clientID, f.redirectURI)
		p.Set(tc.key, tc.value)
		w := doAuthorize(f, p, f.adminToken)
		u, _ := url.Parse(w.Header().Get("Location"))
		if u.Query().Get("error") != tc.code {
			t.Errorf("%s: %s", tc.key, u)
		}
	}
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		c, err := tx.Client(f.clientID)
		if err != nil {
			return err
		}
		c.Metadata["request_object_signing_alg"] = json.RawMessage(`"RS256"`)
		tx.SaveClient(c)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	client, err := f.idsvc.ProtocolClient(t.Context(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	if client.Compatible {
		t.Fatal("required request signing silently ignored")
	}
}
