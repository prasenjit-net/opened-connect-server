package oidc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

// startTransaction drives /authorize far enough to persist an
// AuthzTransaction and returns its ID plus the binding-cookie value the
// browser received, for use as an /oidc/continue-style test fixture.
func startTransaction(t *testing.T, f *testFixture, sessionToken string) (txnID, binding string) {
	t.Helper()
	params := baseAuthorizeParams(f.clientID, f.redirectURI)
	rec := doAuthorize(f, params, sessionToken)
	if rec.Code != http.StatusFound {
		t.Fatalf("expected /authorize to redirect, got %d: %s", rec.Code, rec.Body.String())
	}
	loc := rec.Header().Get("Location")
	if sessionToken != "" {
		// Authenticated requests go straight to /oidc/continue.
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		txnID = u.Query().Get("tx")
	} else {
		// Unauthenticated requests bounce through /login first.
		u, err := url.Parse(loc)
		if err != nil {
			t.Fatal(err)
		}
		redirectParam, err := url.QueryUnescape(u.Query().Get("redirect"))
		if err != nil {
			t.Fatal(err)
		}
		cont, err := url.Parse(redirectParam)
		if err != nil {
			t.Fatal(err)
		}
		txnID = cont.Query().Get("tx")
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == authzBindingCookieName {
			binding = c.Value
		}
	}
	if txnID == "" || binding == "" {
		t.Fatalf("failed to extract transaction id/binding from %q", loc)
	}
	return txnID, binding
}

func statusRequest(f *testFixture, sessionToken, binding string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/user/authorization/x", nil)
	if sessionToken != "" {
		req.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: sessionToken})
	}
	if binding != "" {
		req.AddCookie(&http.Cookie{Name: authzBindingCookieName, Value: binding})
	}
	return req
}

func principalFor(t *testing.T, f *testFixture, sessionToken string) identity.Principal {
	t.Helper()
	p, err := f.idsvc.Authenticate(t.Context(), identity.SessionHash(sessionToken))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestInteractionStatusRequiresConsentThenDecideMintsCode(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	txnID, binding := startTransaction(t, f, f.adminToken)
	principal := principalFor(t, f, f.adminToken)

	view := f.svc.Status(statusRequest(f, f.adminToken, binding), principal, txnID)
	if view.Status != "consent_required" {
		t.Fatalf("expected consent_required, got %+v", view)
	}
	if len(view.Scopes) == 0 {
		t.Fatal("expected requested scopes to be described")
	}

	decideReq := httptest.NewRequest(http.MethodPost, "/api/user/authorization/x/decision", nil)
	decideReq.AddCookie(&http.Cookie{Name: authzBindingCookieName, Value: binding})
	decided := f.svc.Decide(decideReq, principal, txnID, true, []string{"openid", "profile"})
	if decided.Status != "complete" || decided.RedirectTo == "" {
		t.Fatalf("expected a completed redirect, got %+v", decided)
	}
	u, err := url.Parse(decided.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("code") == "" {
		t.Fatalf("expected an authorization code, got %s", decided.RedirectTo)
	}
	if u.Query().Get("state") != "xyz" {
		t.Fatal("expected the original state to be preserved")
	}

	// The transaction is single-use: a second status check must fail.
	again := f.svc.Status(statusRequest(f, f.adminToken, binding), principal, txnID)
	if again.Status != "error" {
		t.Fatalf("expected a consumed transaction to be rejected, got %+v", again)
	}
}

func TestDecideDenialStillRedirectsWithError(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	txnID, binding := startTransaction(t, f, f.adminToken)
	principal := principalFor(t, f, f.adminToken)

	decideReq := httptest.NewRequest(http.MethodPost, "/api/user/authorization/x/decision", nil)
	decideReq.AddCookie(&http.Cookie{Name: authzBindingCookieName, Value: binding})
	decided := f.svc.Decide(decideReq, principal, txnID, false, nil)
	if decided.Status != "complete" {
		t.Fatalf("expected denial to still complete with a callback, got %+v", decided)
	}
	u, err := url.Parse(decided.RedirectTo)
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("error") != "access_denied" {
		t.Fatalf("expected error=access_denied, got %s", decided.RedirectTo)
	}
}

func TestDecideCannotExpandScopesBeyondWhatWasRequested(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	txnID, binding := startTransaction(t, f, f.adminToken) // requested: openid profile
	principal := principalFor(t, f, f.adminToken)

	decideReq := httptest.NewRequest(http.MethodPost, "/api/user/authorization/x/decision", nil)
	decideReq.AddCookie(&http.Cookie{Name: authzBindingCookieName, Value: binding})
	// Attempt to approve scopes that were never requested.
	f.svc.Decide(decideReq, principal, txnID, true, []string{"openid", "profile", "address", "phone"})

	var consent identity.Consent
	if err := f.store.Read(t.Context(), func(tx identity.ReadTx) error {
		var err error
		consent, err = tx.Consent(f.adminID, f.clientID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, sc := range consent.Scopes {
		if sc != "openid" && sc != "profile" {
			t.Fatalf("consent recorded an unrequested scope: %v", consent.Scopes)
		}
	}
}

func TestCrossBrowserConsentReplayFails(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	txnID, _ := startTransaction(t, f, f.adminToken)
	principal := principalFor(t, f, f.adminToken)

	// A different browser (no binding cookie at all, or a forged one) must
	// never be able to resolve or decide this transaction.
	forged := httptest.NewRequest(http.MethodGet, "/api/user/authorization/x", nil)
	forged.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: f.adminToken})
	forged.AddCookie(&http.Cookie{Name: authzBindingCookieName, Value: "forged-binding-value"})

	view := f.svc.Status(forged, principal, txnID)
	if view.Status != "error" {
		t.Fatalf("expected a forged binding cookie to be rejected, got %+v", view)
	}

	noCookie := httptest.NewRequest(http.MethodGet, "/api/user/authorization/x", nil)
	view = f.svc.Status(noCookie, principal, txnID)
	if view.Status != "error" {
		t.Fatalf("expected a missing binding cookie to be rejected, got %+v", view)
	}
}

func TestConsentOnFileIsReusedWithoutReprompting(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	txnID, binding := startTransaction(t, f, f.adminToken)
	principal := principalFor(t, f, f.adminToken)

	policyRevision := mustClientUpdatedAt(t, f)
	if err := f.store.Write(t.Context(), func(tx identity.Tx) error {
		tx.SaveConsent(identity.Consent{UserID: f.adminID, ClientID: f.clientID, Scopes: []string{"openid", "profile"}, PolicyRevision: policyRevision})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	view := f.svc.Status(statusRequest(f, f.adminToken, binding), principal, txnID)
	if view.Status != "complete" {
		t.Fatalf("expected a covering consent to skip the consent screen, got %+v", view)
	}
}
