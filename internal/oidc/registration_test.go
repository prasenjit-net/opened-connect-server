package oidc

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func registrationRequest(s *Service, method, path, token, body string) *httptest.ResponseRecorder {
	router := chi.NewRouter()
	router.Post("/register", s.WithCORS(s.RegistrationHandler))
	router.Get("/register/{clientID}", s.WithCORS(s.RegistrationReadHandler))
	router.Options("/register", s.CORSPreflight)
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	r.Header.Set("Origin", "https://rp.example.com")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}
func TestRegistrationHTTPValidationAndReads(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	s := f.svc
	s.Config.RegistrationEnabled = true
	s.Config.AllowedOrigins = []string{"https://rp.example.com"}
	_, iat, err := f.idsvc.IssueInitialToken(context.Background(), f.adminHash, identity.InitialTokenInput{Label: "HTTP", MaxUses: 10})
	if err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{`null`, `[]`, `{} {}`, `{"client_name":"first","client_name":"second"}`, `{"extension":{"x":1,"x":2}}`, `{"extension":` + strings.Repeat("[", 20) + `0` + strings.Repeat("]", 20) + `}`} {
		if w := registrationRequest(s, "POST", "/register", iat, body); w.Code != 400 {
			t.Fatalf("invalid JSON accepted: %d", w.Code)
		}
	}
	body := `{"redirect_uris":["https://rp.example.com/cb"],"client_name":"Registered"}`
	if w := registrationRequest(s, "POST", "/register", "", body); w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("missing credential challenge")
	}
	if w := registrationRequest(s, "POST", "/register", iat, strings.Repeat("x", 17000)); w.Code != 413 {
		t.Fatal("oversized body accepted")
	}
	w := registrationRequest(s, "POST", "/register", iat, body)
	if w.Code != 201 {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Access-Control-Allow-Origin") != "https://rp.example.com" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatal("unsafe response headers")
	}
	var created map[string]any
	if err = json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := created["client_id"].(string)
	rat := created["registration_access_token"].(string)
	if created["registration_client_uri"] != s.Config.Issuer+"/register/"+id {
		t.Fatal("incorrect registration URI")
	}
	for _, credential := range []string{iat, f.adminToken, created["client_secret"].(string), ""} {
		if w := registrationRequest(s, "GET", "/register/"+id, credential, ""); w.Code != 401 {
			t.Fatal("wrong credential accepted")
		}
	}
	if w := registrationRequest(s, "GET", "/register/unknown", rat, ""); w.Code != 401 {
		t.Fatal("unknown client existence leaked")
	}
	s.Config.RegistrationEnabled = false
	if w := registrationRequest(s, "POST", "/register", iat, body); w.Code != 404 {
		t.Fatal("disabled registration accepted")
	}
	w = registrationRequest(s, "GET", "/register/"+id, rat, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), rat) || !strings.Contains(w.Body.String(), created["client_secret"].(string)) {
		t.Fatal("incorrect authenticated read")
	}
	if w := registrationRequest(s, "OPTIONS", "/register", "", ""); w.Code != 204 {
		t.Fatal("CORS preflight failed")
	}
	s.Config.AllowedOrigins = nil
	if w := registrationRequest(s, "OPTIONS", "/register", "", ""); w.Code != 403 {
		t.Fatal("unlisted CORS origin allowed")
	}
	if s.discoveryDocument().RegistrationEndpoint != "" {
		t.Fatal("disabled endpoint advertised")
	}
	s.Config.RegistrationEnabled = true
	if s.discoveryDocument().RegistrationEndpoint != s.Config.Issuer+"/register" {
		t.Fatal("enabled endpoint omitted")
	}
	for range 125 {
		w = registrationRequest(s, "GET", "/register/"+id, rat, "")
	}
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal("missing credential rate limit")
	}
}

func TestRegistrationRejectsAmbiguousCredentialsAndMediaType(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	f.svc.Config.RegistrationEnabled = true
	_, iat, err := f.idsvc.IssueInitialToken(context.Background(), f.adminHash, identity.InitialTokenInput{Label: "Parser"})
	if err != nil {
		t.Fatal(err)
	}
	for _, headers := range [][]string{{"Bearer " + iat, "Bearer " + iat}, {"Basic " + iat}, {"Bearer " + iat + ", Bearer " + iat}} {
		r := httptest.NewRequest("POST", "/register", strings.NewReader(`{}`))
		for _, h := range headers {
			r.Header.Add("Authorization", h)
		}
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.svc.RegistrationHandler(w, r)
		if w.Code != 401 {
			t.Fatal("ambiguous authorization accepted")
		}
	}
	r := httptest.NewRequest("POST", "/register", strings.NewReader(`{}`))
	r.Header.Set("Authorization", "Bearer "+iat)
	r.Header.Set("Content-Type", "text/plain")
	w := httptest.NewRecorder()
	f.svc.RegistrationHandler(w, r)
	if w.Code != 415 {
		t.Fatal("incorrect media type accepted")
	}
	w = registrationRequest(f.svc, "POST", "/register", iat, `{"redirect_uris":["https://rp.example.com/cb#fragment"]}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), `"error":"invalid_redirect_uri"`) {
		t.Fatal("incorrect redirect error classification")
	}
	if err = validateRegistrationJSON([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
}

func TestRegistrationReadRetainsTransportPolicyWhenCreationDisabled(t *testing.T) {
	f := newTestFixture(t, "https://rp.example.com/cb")
	f.svc.Config.Issuer = "http://insecure.example.com"
	f.svc.Config.RegistrationAllowHTTP = true
	if w := registrationRequest(f.svc, "GET", "/register/client", "rat_example", ""); w.Code != 404 {
		t.Fatal("configuration read allowed over an insecure non-loopback issuer")
	}
}
