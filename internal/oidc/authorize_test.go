package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

const testPKCEVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

func testCodeChallenge() string {
	// SHA-256("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") base64url, no
	// padding — the canonical RFC 7636 appendix B example pair.
	return "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
}

func baseAuthorizeParams(clientID, redirectURI string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid profile"},
		"state":                 {"xyz"},
		"code_challenge":        {testCodeChallenge()},
		"code_challenge_method": {"S256"},
	}
}

func doAuthorize(f *testFixture, params url.Values, sessionToken string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/authorize?"+params.Encode(), nil)
	if sessionToken != "" {
		req.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: sessionToken})
	}
	rec := httptest.NewRecorder()
	f.svc.AuthorizeHandler(rec, req)
	return rec
}

func TestAuthorizeRejectsUnknownClientWithoutRedirect(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	params := baseAuthorizeParams("does-not-exist", "https://rp.example.com/cb")
	rec := doAuthorize(f, params, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("unknown client must never receive a redirect")
	}
	if !strings.Contains(rec.Body.String(), "not registered") {
		t.Fatalf("expected an explanatory error page, got: %s", rec.Body.String())
	}
}

func TestAuthorizeRejectsUnregisteredRedirectURI(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	params := baseAuthorizeParams(f.clientID, "https://evil.example.com/cb")
	rec := doAuthorize(f, params, "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if rec.Header().Get("Location") != "" {
		t.Fatal("an unregistered redirect_uri must never receive a redirect")
	}
}

func TestAuthorizeRejectsDuplicateSecurityCriticalParam(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	params := baseAuthorizeParams(f.clientID, "https://rp.example.com/cb")
	params.Add("client_id", "second-value")
	rec := doAuthorize(f, params, "")
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Location") != "" {
		t.Fatalf("expected a rendered error for duplicate parameters, got %d Location=%q", rec.Code, rec.Header().Get("Location"))
	}
}

func TestAuthorizeRedirectsToLoginWhenNoSession(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	params := baseAuthorizeParams(f.clientID, "https://rp.example.com/cb")
	rec := doAuthorize(f, params, "")
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?redirect=") {
		t.Fatalf("expected redirect to /login, got %q", loc)
	}
	if !strings.Contains(loc, url.QueryEscape("/oidc/continue?tx=")) {
		t.Fatalf("expected the login redirect to point back at /oidc/continue, got %q", loc)
	}
	var bindingCookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == "ocs_authz_binding" {
			bindingCookie = c
		}
	}
	if bindingCookie == nil || bindingCookie.Value == "" {
		t.Fatal("expected an authorization binding cookie to be set")
	}
}

func TestAuthorizeAdminCanAuthorize(t *testing.T) {
	// Both regular users and admins may authorize clients.
	f := newTestFixture(t, "https://rp.example.com/cb")
	params := baseAuthorizeParams(f.clientID, "https://rp.example.com/cb")
	rec := doAuthorize(f, params, f.adminToken)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.HasPrefix(loc, "/oidc/continue?tx=") {
		t.Fatalf("expected an authenticated request to proceed straight to the continuation page, got %q", loc)
	}
}

func TestAuthorizePromptNoneWithoutSessionFailsSilently(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	params := baseAuthorizeParams(f.clientID, "https://rp.example.com/cb")
	params.Set("prompt", "none")
	rec := doAuthorize(f, params, "")
	if rec.Code != http.StatusFound {
		t.Fatalf("expected a redirect carrying the error, got %d body=%s", rec.Code, rec.Body.String())
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("error") != "login_required" {
		t.Fatalf("expected error=login_required, got %q", loc.Query().Get("error"))
	}
	if strings.Contains(rec.Body.String(), "<html") {
		t.Fatal("a silent request must never render HTML")
	}
}

func TestAuthorizePromptNoneWithoutConsentReturnsConsentRequired(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	params := baseAuthorizeParams(f.clientID, "https://rp.example.com/cb")
	params.Set("prompt", "none")
	rec := doAuthorize(f, params, f.adminToken)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("error") != "consent_required" {
		t.Fatalf("expected error=consent_required, got %q (full: %s)", loc.Query().Get("error"), loc)
	}
}

func TestAuthorizePromptNoneWithConsentMintsCode(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	policyRevision := mustClientUpdatedAt(t, f)
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		tx.SaveConsent(identity.Consent{UserID: f.adminID, ClientID: f.clientID, Scopes: []string{"openid", "profile"}, PolicyRevision: policyRevision})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	params := baseAuthorizeParams(f.clientID, "https://rp.example.com/cb")
	params.Set("prompt", "none")
	rec := doAuthorize(f, params, f.adminToken)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("code") == "" {
		t.Fatalf("expected a code to be minted, got %s", loc)
	}
	if loc.Query().Get("state") != "xyz" {
		t.Fatal("expected the original state to be preserved")
	}
}

func TestAuthorizeFormPostDeliversCodeAndState(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb?from=registered")
	policyRevision := mustClientUpdatedAt(t, f)
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		tx.SaveConsent(identity.Consent{UserID: f.adminID, ClientID: f.clientID, Scopes: []string{"openid", "profile"}, PolicyRevision: policyRevision})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	params := baseAuthorizeParams(f.clientID, f.redirectURI)
	params.Set("prompt", "none")
	params.Set("response_mode", "form_post")
	rec := doAuthorize(f, params, f.adminToken)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), `method="post"`) || !strings.Contains(rec.Body.String(), `action="https://rp.example.com/cb?from=registered"`) {
		t.Fatalf("expected uncached form post, got code=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `name="code"`) || !strings.Contains(rec.Body.String(), `name="state" value="xyz"`) {
		t.Fatalf("form did not contain authorization response: %s", rec.Body.String())
	}
}

func TestAuthorizeRejectsMissingPKCE(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	params := baseAuthorizeParams(f.clientID, "https://rp.example.com/cb")
	params.Del("code_challenge")
	params.Del("code_challenge_method")
	rec := doAuthorize(f, params, "")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("expected invalid_request for missing PKCE, got %s", loc)
	}
}

func TestAuthorizeRejectsPlainPKCEMethod(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	params := baseAuthorizeParams(f.clientID, "https://rp.example.com/cb")
	params.Set("code_challenge_method", "plain")
	rec := doAuthorize(f, params, "")
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Get("error") != "invalid_request" {
		t.Fatalf("expected invalid_request rejecting plain PKCE, got %s", loc)
	}
}

func mustClientUpdatedAt(t *testing.T, f *testFixture) int64 {
	t.Helper()
	client, err := f.idsvc.ProtocolClient(t.Context(), f.clientID)
	if err != nil {
		t.Fatal(err)
	}
	return client.UpdatedAt
}
