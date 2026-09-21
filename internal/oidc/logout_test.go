package oidc

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func TestLogoutEndsBoundCodeAndOnlineToken(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/callback")
	code := obtainCode(t, f, "openid")
	response := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier))
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	var tokens tokenResponse
	_ = json.Unmarshal(response.Body.Bytes(), &tokens)
	parsed, e := jwt.ParseSigned(tokens.IDToken, []jose.SignatureAlgorithm{jose.RS256})
	if e != nil {
		t.Fatal(e)
	}
	var claims struct {
		SID string `json:"sid"`
	}
	if e = parsed.Claims(f.svc.Keys.PublicJWKS().Keys[0].Key, &claims); e != nil || claims.SID == "" {
		t.Fatal("missing signed sid", e)
	}
	// Another code issued before logout must not be redeemable afterwards.
	c, _ := f.idsvc.ProtocolClient(t.Context(), f.clientID)
	p := principalFor(t, f, f.adminToken)
	redirect := f.svc.mintCode(t.Context(), finishParams{client: c, redirectURI: f.redirectURI, userID: f.adminID, authTime: p.Session.AuthTime, sessionHash: p.Session.Hash, scopes: []string{"openid"}, codeChallenge: testCodeChallenge(), codeChallengeMethod: "S256"})
	u, _ := url.Parse(redirect)
	if e = f.idsvc.Logout(t.Context(), f.adminHash); e != nil {
		t.Fatal(e)
	}
	denied := doToken(f, tokenForm(f.clientID, u.Query().Get("code"), f.redirectURI, testPKCEVerifier))
	if denied.Code != 400 {
		t.Fatal("pending code survived", denied.Body.String())
	}
	_ = f.store.Read(t.Context(), func(tx identity.ReadTx) error {
		token, _ := tx.AccessToken(hashToken(tokens.AccessToken))
		active, e := identity.AccessTokenActive(tx, token, time.Now(), nil)
		if e != nil || active {
			t.Fatal("online token survived logout")
		}
		return nil
	})
}

func TestLogoutConfirmationBindingAndReturnValidation(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/callback")
	router := chi.NewRouter()
	router.Get("/logout", f.svc.LogoutHandler)
	router.Get("/logout/interaction/{id}", f.svc.LogoutInteractionHandler)
	router.Post("/logout/interaction/{id}", f.svc.LogoutInteractionHandler)
	bad := httptest.NewRecorder()
	router.ServeHTTP(bad, httptest.NewRequest("GET", "/logout?post_logout_redirect_uri=https://attacker.example", nil))
	if bad.Code != 400 || bad.Header().Get("Location") != "" {
		t.Fatal("unregistered redirect accepted")
	}
	req := httptest.NewRequest("GET", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: f.adminToken})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != 303 {
		t.Fatal(rec.Code, rec.Body.String())
	}
	path := rec.Header().Get("Location")
	var binding *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == logoutBindingCookie {
			binding = c
		}
	}
	if binding == nil {
		t.Fatal("missing browser binding")
	}
	unbound := httptest.NewRecorder()
	router.ServeHTTP(unbound, httptest.NewRequest("GET", path, nil))
	if unbound.Code != 400 {
		t.Fatal("interaction leaked without binding")
	}
	get := httptest.NewRequest("GET", path, nil)
	get.AddCookie(binding)
	get.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: f.adminToken})
	page := httptest.NewRecorder()
	router.ServeHTTP(page, get)
	if !strings.Contains(page.Body.String(), "Confirm") && !strings.Contains(page.Body.String(), "connected apps") {
		t.Fatal(page.Body.String())
	}
	var interaction identity.LogoutInteraction
	_ = f.store.Read(t.Context(), func(tx identity.ReadTx) error {
		interaction, _ = tx.LogoutInteraction(strings.TrimPrefix(path, "/logout/interaction/"))
		return nil
	})
	submit := func(csrf string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(url.Values{"csrf": {csrf}, "decision": {"logout"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(binding)
		r.AddCookie(&http.Cookie{Name: identity.SessionCookieName, Value: f.adminToken})
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)
		return w
	}
	if submit("wrong").Code != 403 {
		t.Fatal("CSRF accepted")
	}
	if _, e := f.idsvc.Authenticate(t.Context(), f.adminHash); e != nil {
		t.Fatal("GET or invalid CSRF terminated session")
	}
	if w := submit(interaction.CSRF); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, e := f.idsvc.Authenticate(t.Context(), f.adminHash); e == nil {
		t.Fatal("session survived confirmed logout")
	}
	if submit(interaction.CSRF).Code != 400 {
		t.Fatal("confirmation replay accepted")
	}
}

func TestBackchannelSignedDeliveryRetryAndSSRF(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/callback")
	f.svc.Config.RegistrationAllowHTTP = true
	attempts := 0
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if r.Method != "POST" {
			t.Error("wrong method")
		}
		_ = r.ParseForm()
		parsed, e := jwt.ParseSigned(r.Form.Get("logout_token"), []jose.SignatureAlgorithm{jose.RS256})
		if e != nil {
			t.Error(e)
			w.WriteHeader(400)
			return
		}
		claims := map[string]any{}
		if e = parsed.Claims(f.svc.Keys.PublicJWKS().Keys[0].Key, &claims); e != nil {
			t.Error(e)
		}
		if claims["iss"] != f.svc.Config.Issuer || claims["sid"] != "app" || claims["aud"] != f.clientID || claims["nonce"] != nil || claims["exp"] == nil || claims["events"] == nil {
			t.Errorf("invalid logout claims: %v", claims)
		}
		if parsed.Headers[0].ExtraHeaders["typ"] != "logout+jwt" {
			t.Error("wrong logout type")
		}
		if attempts == 1 {
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(200)
	}))
	defer rp.Close()
	p := principalFor(t, f, f.adminToken)
	now := time.Now().UTC()
	_ = f.store.Write(t.Context(), func(tx identity.Tx) error {
		c, _ := tx.Client(f.clientID)
		raw, _ := json.Marshal(rp.URL)
		c.Metadata["backchannel_logout_uri"] = raw
		tx.SaveClient(c)
		tx.SaveAppSession(identity.AppSession{ID: "app", OPSessionID: p.Session.ID, ClientID: f.clientID, UserID: f.adminID, Subject: f.adminID, CreatedAt: now})
		tx.EndSession(p.Session.ID, f.adminID, "test", now)
		return nil
	})
	if e := f.svc.ProcessLogoutDeliveries(t.Context()); e != nil {
		t.Fatal(e)
	}
	f.svc.Now = func() time.Time { return now.Add(10 * time.Second) }
	if e := f.svc.ProcessLogoutDeliveries(t.Context()); e != nil {
		t.Fatal(e)
	}
	_ = f.store.Read(t.Context(), func(tx identity.ReadTx) error {
		for _, d := range tx.ListLogoutDeliveries() {
			if d.Channel == "backchannel" && (d.Status != "acknowledged" || d.Attempts != 2) {
				t.Fatalf("retry failed: %+v", d)
			}
		}
		return nil
	})
	f.svc.Config.RegistrationAllowHTTP = false
	if conn, e := f.svc.logoutDial(t.Context(), "tcp", "127.0.0.1:80"); e == nil {
		conn.Close()
		t.Fatal("loopback accepted in production")
	}
	for _, address := range []string{"169.254.169.254:80", "10.1.2.3:80", "[::1]:80"} {
		if conn, e := f.svc.logoutDial(t.Context(), "tcp", address); e == nil {
			conn.Close()
			t.Fatal("private address accepted", address)
		}
	}
}

func TestFrontchannelCompletionTargetsOnlyBoundBrowser(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/callback")
	p := principalFor(t, f, f.adminToken)
	_ = f.store.Write(t.Context(), func(tx identity.Tx) error {
		c, _ := tx.Client(f.clientID)
		raw, _ := json.Marshal("https://rp.example/front?registered=keep")
		c.Metadata["frontchannel_logout_uri"] = raw
		tx.SaveClient(c)
		for _, pair := range [][2]string{{"here", p.Session.ID}, {"remote", "remote-op"}} {
			tx.SaveAppSession(identity.AppSession{ID: pair[0], OPSessionID: pair[1], ClientID: f.clientID, UserID: f.adminID})
			tx.EndAppSession(pair[0], f.adminID, "test", time.Now())
		}
		return nil
	})
	prepare := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/auth/logout/prepare", nil)
	path, e := f.svc.PrepareAppLogout(prepare, req, p, "here")
	if e != nil {
		t.Fatal(e)
	}
	router := chi.NewRouter()
	router.Get("/logout/interaction/{id}", f.svc.LogoutInteractionHandler)
	get := httptest.NewRequest("GET", path, nil)
	for _, c := range prepare.Result().Cookies() {
		get.AddCookie(c)
	}
	result := httptest.NewRecorder()
	router.ServeHTTP(result, get)
	if result.Code != 200 || !strings.Contains(result.Body.String(), "sid=here") || strings.Contains(result.Body.String(), "sid=remote") || !strings.Contains(result.Body.String(), "registered=keep") {
		t.Fatal(result.Body.String())
	}
	if result.Header().Get("Referrer-Policy") != "no-referrer" || result.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("unsafe completion headers")
	}
	if _, e = f.idsvc.Authenticate(t.Context(), f.adminHash); e != nil {
		t.Fatal("app-only logout ended OP", e)
	}
	_ = f.store.Read(t.Context(), func(tx identity.ReadTx) error {
		for _, d := range tx.ListLogoutDeliveries() {
			if d.AppSessionID == "here" && d.Status != "unconfirmed" {
				t.Fatal("iframe incorrectly acknowledged")
			}
			if d.AppSessionID == "remote" && d.Status != "browser_unavailable" {
				t.Fatal("remote browser delivery claimed")
			}
		}
		return nil
	})
}

func TestLogoutHintExpiredBindingAndTokenType(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/callback")
	code := obtainCode(t, f, "openid")
	response := doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier))
	var tokens tokenResponse
	_ = json.Unmarshal(response.Body.Bytes(), &tokens)
	if _, e := f.svc.logoutHint(t.Context(), tokens.IDToken, f.clientID); e != nil {
		t.Fatal(e)
	}
	if _, e := f.svc.logoutHint(t.Context(), tokens.IDToken, "different-client"); e == nil {
		t.Fatal("mismatched client accepted")
	}
	now := time.Now()
	f.svc.Now = func() time.Time { return now.Add(10 * time.Minute) }
	if _, e := f.svc.logoutHint(t.Context(), tokens.IDToken, f.clientID); e != nil {
		t.Fatal("recent expired ID token should remain a hint", e)
	}
	logoutToken, e := f.svc.Keys.signTypedAt(now, "logout+jwt", map[string]any{"iss": f.svc.Config.Issuer, "aud": f.clientID, "sub": f.adminID, "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = f.svc.logoutHint(t.Context(), logoutToken, f.clientID); e == nil {
		t.Fatal("logout token accepted as ID token")
	}
}

func TestConcurrentCodeExchangeAndLogoutCannotLeaveOnlineAccess(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/callback")
	code := obtainCode(t, f, "openid")
	start := make(chan struct{})
	responses := make(chan *httptest.ResponseRecorder, 1)
	ended := make(chan error, 1)
	go func() { <-start; responses <- doToken(f, tokenForm(f.clientID, code, f.redirectURI, testPKCEVerifier)) }()
	go func() { <-start; ended <- f.idsvc.Logout(t.Context(), f.adminHash) }()
	close(start)
	response := <-responses
	if e := <-ended; e != nil {
		t.Fatal(e)
	}
	if response.Code != 200 && response.Code != 400 {
		t.Fatal(response.Code, response.Body.String())
	}
	_ = f.store.Read(t.Context(), func(tx identity.ReadTx) error {
		for _, token := range tx.ListAccessTokens() {
			active, e := identity.AccessTokenActive(tx, token, time.Now(), nil)
			if e != nil || active {
				t.Fatal("exchange escaped logout")
			}
		}
		return nil
	})
}

func TestWorkerLeasePreventsConcurrentDelivery(t *testing.T) {
	f := newTestFixture(t, "https://rp.example/callback")
	f.svc.Config.RegistrationAllowHTTP = true
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	rp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { arrived <- struct{}{}; <-release; w.WriteHeader(200) }))
	defer rp.Close()
	_ = f.store.Write(t.Context(), func(tx identity.Tx) error {
		tx.SaveLogoutDelivery(identity.LogoutDelivery{ID: "leased", Channel: "backchannel", Status: "pending", Endpoint: rp.URL, CreatedAt: time.Now(), AppSessionID: "app", ClientID: "deleted-client"})
		return nil
	})
	done := make(chan error, 1)
	go func() { done <- f.svc.ProcessLogoutDeliveries(t.Context()) }()
	select {
	case <-arrived:
	case <-time.After(3 * time.Second):
		t.Fatal("delivery did not start")
	}
	if e := f.svc.ProcessLogoutDeliveries(t.Context()); e != nil {
		t.Error(e)
	}
	select {
	case <-arrived:
		t.Error("second worker delivered a leased job")
	default:
	}
	close(release)
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	_ = f.store.Read(t.Context(), func(tx identity.ReadTx) error {
		for _, d := range tx.ListLogoutDeliveries() {
			if d.ID == "leased" && (d.Attempts != 1 || d.Status != "acknowledged" || len(d.History) != 1) {
				t.Fatalf("bad lease completion: %+v", d)
			}
		}
		return nil
	})
}
