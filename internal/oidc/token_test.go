package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

// obtainCode drives /authorize -> /oidc/continue-style Decide(approve) to
// mint a real authorization code, exactly as an independent relying party
// would experience it, and returns it.
func obtainCode(t *testing.T, f *testFixture, scopes string) string {
	t.Helper()
	params := baseAuthorizeParams(f.clientID, f.redirectURI)
	if scopes != "" {
		params.Set("scope", scopes)
	}
	rec := doAuthorize(f, params, f.adminToken)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected /authorize to redirect, got %d: %s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	txnID := loc.Query().Get("tx")
	var binding string
	for _, c := range rec.Result().Cookies() {
		if c.Name == authzBindingCookieName {
			binding = c.Value
		}
	}
	principal := principalFor(t, f, f.adminToken)
	decideReq := httptest.NewRequest(http.MethodPost, "/api/user/authorization/x/decision", nil)
	decideReq.AddCookie(&http.Cookie{Name: authzBindingCookieName, Value: binding})
	decided := f.svc.Decide(decideReq, principal, txnID, true, strings.Fields(params.Get("scope")))
	if decided.Status != "complete" {
		t.Fatalf("expected consent to complete, got %+v", decided)
	}
	redirectTo, err := url.Parse(decided.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	code := redirectTo.Query().Get("code")
	if code == "" {
		t.Fatalf("expected an authorization code, got %s", decided.RedirectTo)
	}
	return code
}

func tokenForm(clientID, code, redirectURI, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {clientID},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"code_verifier": {verifier},
	}
}

func doToken(f *testFixture, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.svc.TokenHandler(rec, req)
	return rec
}

func TestTokenExchangeEndToEndWithSignatureVerification(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid profile")

	rec := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp tokenResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.AccessToken == "" || resp.IDToken == "" || resp.TokenType != "Bearer" {
		t.Fatalf("incomplete token response: %+v", resp)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("expected Cache-Control: no-store on the token response")
	}

	// An independent relying party validates the ID token against the
	// provider's published JWKS.
	jwks := f.svc.Keys.PublicJWKS()
	parsed, err := jwt.ParseSigned(resp.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatal(err)
	}
	kid := parsed.Headers[0].KeyID
	matching := jwks.Key(kid)
	if len(matching) != 1 {
		t.Fatalf("no published JWK for kid %s", kid)
	}
	var claims jwt.Claims
	if err := parsed.Claims(matching[0].Key, &claims); err != nil {
		t.Fatalf("ID token signature did not verify: %v", err)
	}
	if claims.Issuer != f.svc.Config.Issuer {
		t.Fatalf("unexpected issuer: %s", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != f.clientID {
		t.Fatalf("unexpected audience: %v", claims.Audience)
	}
	if claims.Subject != f.adminID {
		t.Fatalf("unexpected subject: %s", claims.Subject)
	}

	// UserInfo with the access token.
	uiReq := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	uiReq.Header.Set("Authorization", "Bearer "+resp.AccessToken)
	uiRec := httptest.NewRecorder()
	f.svc.UserInfoHandler(uiRec, uiReq)
	if uiRec.Code != http.StatusOK {
		t.Fatalf("expected 200 from /userinfo, got %d: %s", uiRec.Code, uiRec.Body.String())
	}
	if !strings.Contains(uiRec.Body.String(), `"sub"`) {
		t.Fatalf("expected sub claim in userinfo response: %s", uiRec.Body.String())
	}
}

func TestTokenRejectsExpiredOrReusedCode(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid profile")

	first := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier))
	if first.Code != http.StatusOK {
		t.Fatalf("expected the first exchange to succeed, got %d: %s", first.Code, first.Body.String())
	}
	second := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier))
	if second.Code != http.StatusBadRequest || !strings.Contains(second.Body.String(), "invalid_grant") {
		t.Fatalf("expected a reused code to fail with invalid_grant, got %d: %s", second.Code, second.Body.String())
	}
}

func TestTokenRejectsWrongPKCEVerifier(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid profile")
	rec := doToken(f, tokenForm(f.clientID, code, f.redirectURI, "wrong-verifier-wrong-verifier-wrong-verifier"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid_grant for a wrong PKCE verifier, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenRejectsMismatchedRedirectURI(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid profile")
	rec := doToken(f, tokenForm(f.clientID, code, "https://different.example.com/cb", testPKCEVerifier))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid_grant for a mismatched redirect_uri, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenRejectsWrongClient(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid profile")
	form := tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)
	form.Set("client_id", "not-the-real-client")
	rec := doToken(f, form)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected client authentication to fail for an unregistered client, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenRejectsJSONContentType(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(`{"grant_type":"authorization_code"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	f.svc.TokenHandler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected JSON bodies to be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestTokenSessionCookieAloneCannotAuthenticate(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid profile")
	form := tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)
	form.Del("client_id") // a public/none client still must self-identify; a cookie is not a substitute
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: f.adminToken})
	rec := httptest.NewRecorder()
	f.svc.TokenHandler(rec, req)
	if rec.Code == http.StatusOK {
		t.Fatal("a browser session cookie alone must never authorize token issuance")
	}
}

func TestConcurrentCodeExchangeYieldsExactlyOneSuccess(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	code := obtainCode(t, f, "openid profile")

	otherStore, err := identity.NewFileStore(f.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	otherIdentity, err := identity.NewService(otherStore, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	otherSvc := New(otherIdentity, otherStore, f.svc.Keys, f.svc.Config)

	var wg sync.WaitGroup
	results := make(chan int, 2)
	for _, svc := range []*Service{f.svc, otherSvc} {
		wg.Add(1)
		go func(svc *Service) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier).Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			svc.TokenHandler(rec, req)
			results <- rec.Code
		}(svc)
	}
	wg.Wait()
	close(results)
	success, failed := 0, 0
	for code := range results {
		if code == http.StatusOK {
			success++
		} else {
			failed++
		}
	}
	if success != 1 || failed != 1 {
		t.Fatalf("expected exactly one success and one failure, got success=%d failed=%d", success, failed)
	}
}
