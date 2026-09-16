package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"github.com/prasenjit-net/opened-connect-server/internal/version"
)

const testPassword = "correct horse battery staple"

type browserSession struct {
	cookie *http.Cookie
	csrf   string
}
type authRig struct {
	handler http.Handler
	service *identity.Service
	dir     string
}

func newAuthRig(t *testing.T) authRig {
	t.Helper()
	dir := t.TempDir()
	store, err := identity.NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(store, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Bootstrap(context.Background(), "Admin", "admin@example.com", testPassword); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Storage.DataDir = dir
	return authRig{NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), service, nil), service, dir}
}
func (rig authRig) request(t *testing.T, method, path string, body any, session browserSession) *httptest.ResponseRecorder {
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
	res := httptest.NewRecorder()
	rig.handler.ServeHTTP(res, req)
	return res
}
func expectStatus(t *testing.T, res *httptest.ResponseRecorder, status int) {
	t.Helper()
	if res.Code != status {
		t.Fatalf("expected %d, got %d: %s", status, res.Code, res.Body.String())
	}
}
func (rig authRig) login(t *testing.T, email, password string) browserSession {
	t.Helper()
	res := rig.request(t, "POST", "/auth/login", map[string]string{"email": email, "password": password}, browserSession{})
	expectStatus(t, res, 200)
	var body struct {
		CSRF string `json:"csrfToken"`
	}
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	cookies := res.Result().Cookies()
	if len(cookies) != 1 || body.CSRF == "" {
		t.Fatal("missing session or CSRF")
	}
	return browserSession{cookies[0], body.CSRF}
}
func profileFrom(t *testing.T, res *httptest.ResponseRecorder) identity.Profile {
	t.Helper()
	var u identity.Profile
	if err := json.Unmarshal(res.Body.Bytes(), &u); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestAuthenticationAndAuthorization(t *testing.T) {
	rig := newAuthRig(t)
	none := browserSession{}
	for _, path := range []string{"/auth/session", "/user/profile", "/admin/users"} {
		expectStatus(t, rig.request(t, "GET", path, nil, none), 401)
	}
	expectStatus(t, rig.request(t, "POST", "/auth/login", map[string]string{"email": "admin@example.com", "password": "wrong"}, none), 401)
	admin := rig.login(t, "ADMIN@example.com", testPassword)
	if !admin.cookie.HttpOnly || admin.cookie.SameSite != http.SameSiteLaxMode || admin.cookie.Path != "/" || admin.cookie.MaxAge <= 0 {
		t.Fatal("unsafe session cookie")
	}
	create := map[string]any{"name": "Alice", "email": "alice@example.com", "password": testPassword, "role": "user"}
	expectStatus(t, rig.request(t, "POST", "/admin/users", create, browserSession{cookie: admin.cookie}), 403)
	res := rig.request(t, "POST", "/admin/users", create, admin)
	expectStatus(t, res, 201)
	user := profileFrom(t, res)
	if strings.Contains(res.Body.String(), "password") || strings.Contains(res.Body.String(), "Hash") {
		t.Fatal("credentials leaked")
	}
	expectStatus(t, rig.request(t, "POST", "/admin/users", create, admin), 409)
	res = rig.request(t, "GET", "/admin/users?q=ALICE&role=user&pageSize=20", nil, admin)
	expectStatus(t, res, 200)
	var list identity.UserList
	if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 1 || list.Users[0].ID != user.ID {
		t.Fatal("search or role filter failed")
	}
	alice := rig.login(t, "alice@example.com", testPassword)
	expectStatus(t, rig.request(t, "GET", "/admin/users", nil, alice), 403)
	input := identity.UserInput{Name: "Alice", Email: user.Email, Role: identity.RoleAdmin, Active: true}
	expectStatus(t, rig.request(t, "PUT", "/admin/users/"+user.ID, input, alice), 403)
	expectStatus(t, rig.request(t, "PUT", "/user/profile", map[string]string{"name": "Alice", "role": "admin"}, alice), 400)
	res = rig.request(t, "PUT", "/user/profile", map[string]string{"name": "Alice Updated"}, alice)
	expectStatus(t, res, 200)
	if profileFrom(t, res).Name != "Alice Updated" {
		t.Fatal("profile not updated")
	}
	expectStatus(t, rig.request(t, "PUT", "/admin/users/"+user.ID, input, admin), 200)
	expectStatus(t, rig.request(t, "GET", "/auth/session", nil, alice), 401)
	alice = rig.login(t, "alice@example.com", testPassword)
	expectStatus(t, rig.request(t, "GET", "/admin/users", nil, alice), 200)
	input.Role = identity.RoleUser
	input.Active = false
	expectStatus(t, rig.request(t, "PUT", "/admin/users/"+user.ID, input, admin), 200)
	expectStatus(t, rig.request(t, "GET", "/user/profile", nil, alice), 401)
	expectStatus(t, rig.request(t, "POST", "/auth/login", map[string]string{"email": user.Email, "password": testPassword}, none), 401)
	input.Active = true
	expectStatus(t, rig.request(t, "PUT", "/admin/users/"+user.ID, input, admin), 200)
	alice = rig.login(t, "alice@example.com", testPassword)
	expectStatus(t, rig.request(t, "DELETE", "/admin/users/"+user.ID, nil, admin), 204)
	expectStatus(t, rig.request(t, "GET", "/user/profile", nil, alice), 401)
	p, err := rig.service.Authenticate(context.Background(), identity.SessionHash(admin.cookie.Value))
	if err != nil {
		t.Fatal(err)
	}
	expectStatus(t, rig.request(t, "PUT", "/admin/users/"+p.User.ID, identity.UserInput{Name: p.User.Name, Email: p.User.Email, Role: identity.RoleUser, Active: true}, admin), 409)
	expectStatus(t, rig.request(t, "DELETE", "/admin/users/"+p.User.ID, nil, admin), 409)
	expectStatus(t, rig.request(t, "POST", "/auth/logout", nil, admin), 204)
	expectStatus(t, rig.request(t, "GET", "/auth/session", nil, admin), 401)
}

func TestPasswordChangeRevokesAllSessionsAndPersists(t *testing.T) {
	rig := newAuthRig(t)
	first := rig.login(t, "admin@example.com", testPassword)
	second := rig.login(t, "admin@example.com", testPassword)
	expectStatus(t, rig.request(t, "POST", "/user/profile/password", map[string]string{"currentPassword": "wrong", "newPassword": "a different long password"}, first), 400)
	res := rig.request(t, "POST", "/user/profile/password", map[string]string{"currentPassword": testPassword, "newPassword": "a different long password"}, first)
	expectStatus(t, res, 204)
	if res.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal("cookie not expired")
	}
	for _, session := range []browserSession{first, second} {
		expectStatus(t, rig.request(t, "GET", "/user/profile", nil, session), 401)
	}
	expectStatus(t, rig.request(t, "POST", "/auth/login", map[string]string{"email": "admin@example.com", "password": testPassword}, browserSession{}), 401)
	newSession := rig.login(t, "admin@example.com", "a different long password")
	store, err := identity.NewFileStore(rig.dir)
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := identity.NewService(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.Authenticate(context.Background(), identity.SessionHash(newSession.cookie.Value)); err != nil {
		t.Fatal("session did not survive restart", err)
	}
	content, err := os.ReadFile(filepath.Join(rig.dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{testPassword, "a different long password", newSession.cookie.Value} {
		if bytes.Contains(content, []byte(secret)) {
			t.Fatal("plaintext secret stored on disk")
		}
	}
	if !bytes.Contains(content, []byte("$argon2id$")) {
		t.Fatal("passwords must be hashed")
	}
}

func TestCSRFAndLoginThrottle(t *testing.T) {
	rig := newAuthRig(t)
	for _, test := range []struct {
		origin, content string
		status          int
	}{{"https://evil.example", "application/json", 403}, {"null", "application/json", 403}, {"", "application/x-www-form-urlencoded", 415}} {
		req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"wrong"}`))
		req.Header.Set("Origin", test.origin)
		req.Header.Set("Content-Type", test.content)
		res := httptest.NewRecorder()
		rig.handler.ServeHTTP(res, req)
		expectStatus(t, res, test.status)
	}
	for i := 0; i < 11; i++ {
		res := rig.request(t, "POST", "/auth/login", map[string]string{"email": "missing@example.com", "password": "wrong"}, browserSession{})
		want := 401
		if i == 10 {
			want = 429
		}
		expectStatus(t, res, want)
	}
}

func TestSecureCookieAndSessionRotation(t *testing.T) {
	rig := newAuthRig(t)
	cfg := config.Default()
	cfg.Auth.CookieSecure = true
	rig.handler = NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), rig.service, nil)
	first := rig.login(t, "admin@example.com", testPassword)
	if !first.cookie.Secure {
		t.Fatal("HTTPS cookie must be Secure")
	}
	res := rig.request(t, "POST", "/auth/login", map[string]string{"email": "admin@example.com", "password": testPassword}, first)
	expectStatus(t, res, 200)
	if res.Result().Cookies()[0].Value == first.cookie.Value {
		t.Fatal("session token was reused")
	}
	expectStatus(t, rig.request(t, "GET", "/auth/session", nil, first), 401)
}

func TestDevelopmentOriginAndProductionRejection(t *testing.T) {
	rig := newAuthRig(t)
	request := func() *http.Request {
		r := httptest.NewRequest("POST", "/auth/login", strings.NewReader(`{"email":"admin@example.com","password":"correct horse battery staple"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "http://localhost:5173")
		return r
	}
	res := httptest.NewRecorder()
	rig.handler.ServeHTTP(res, request())
	expectStatus(t, res, 200)
	cfg := config.Default()
	cfg.App.Env = "production"
	cfg.App.URL = "https://identity.example.com"
	cfg.Auth.CookieSecure = true
	rig.handler = NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), rig.service, nil)
	res = httptest.NewRecorder()
	rig.handler.ServeHTTP(res, request())
	expectStatus(t, res, 403)
}

func TestUserDetailAuthorizationAndPagination(t *testing.T) {
	rig := newAuthRig(t)
	admin := rig.login(t, "admin@example.com", testPassword)
	var target identity.Profile
	for i := 0; i < 10; i++ {
		res := rig.request(t, "POST", "/admin/users", map[string]any{"name": "User", "email": fmt.Sprintf("user%d@example.com", i), "password": testPassword, "role": "user", "active": true}, admin)
		expectStatus(t, res, 201)
		target = profileFrom(t, res)
	}
	path := "/admin/users/" + target.ID
	res := rig.request(t, "GET", path, nil, admin)
	expectStatus(t, res, 200)
	if profileFrom(t, res).ID != target.ID || strings.Contains(strings.ToLower(res.Body.String()), "password") {
		t.Fatal("invalid public profile response")
	}
	expectStatus(t, rig.request(t, "GET", path, nil, browserSession{}), 401)
	user := rig.login(t, target.Email, testPassword)
	expectStatus(t, rig.request(t, "GET", path, nil, user), 403)
	expectStatus(t, rig.request(t, "GET", "/admin/users/missing", nil, admin), 404)
	first := rig.request(t, "GET", "/admin/users", nil, admin)
	expectStatus(t, first, 200)
	var page identity.UserList
	if err := json.Unmarshal(first.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.PageSize != 10 || len(page.Users) != 10 || page.Total != 11 {
		t.Fatalf("unexpected first page: %+v", page)
	}
	second := rig.request(t, "GET", "/admin/users?page=2", nil, admin)
	expectStatus(t, second, 200)
	if err := json.Unmarshal(second.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Page != 2 || len(page.Users) != 1 {
		t.Fatalf("unexpected second page: %+v", page)
	}
}

func TestExtendedProfilesAndEntitlements(t *testing.T) {
	rig := newAuthRig(t)
	admin := rig.login(t, "admin@example.com", testPassword)
	create := map[string]any{"name": "Alice", "email": "alice@example.com", "role": "user", "active": true, "password": testPassword, "given_name": "Alice", "phone_number": "+12025550123", "email_verified": true, "phone_number_verified": true, "custom_attributes": map[string]any{"department": "Engineering", "levels": []any{1, true}}}
	res := rig.request(t, "POST", "/admin/users", create, admin)
	expectStatus(t, res, 201)
	aliceProfile := profileFrom(t, res)
	alice := rig.login(t, "alice@example.com", testPassword)
	path := "/admin/users/" + aliceProfile.ID
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		expectStatus(t, rig.request(t, method, path, create, alice), 403)
		expectStatus(t, rig.request(t, method, path, create, browserSession{}), 401)
	}
	expectStatus(t, rig.request(t, "POST", "/admin/users", create, alice), 403)
	for _, field := range []string{"role", "active", "id", "sub", "updated_at", "email_verified", "phone_number_verified"} {
		expectStatus(t, rig.request(t, "PUT", "/user/profile", map[string]any{"name": "Alice", field: true}, alice), 400)
	}
	input := map[string]any{"name": "Alice Updated", "email": "newalice@example.com", "given_name": "Alice", "family_name": "Example", "birthdate": "0000-02-29", "zoneinfo": "America/Los_Angeles", "locale": "en-US", "phone_number": "+12025550124", "address": map[string]any{"street_address": "123 Main St", "locality": "Example", "country": "US"}, "custom_attributes": map[string]any{"department": "Research", "preferences": map[string]any{"news": true}}}
	expectStatus(t, rig.request(t, "PUT", "/user/profile", input, browserSession{cookie: alice.cookie}), 403)
	res = rig.request(t, "PUT", "/user/profile", input, alice)
	expectStatus(t, res, 200)
	saved := profileFrom(t, res)
	if saved.ID != aliceProfile.ID || saved.Sub != saved.ID || saved.Role != identity.RoleUser || saved.EmailVerified || saved.PhoneNumberVerified || saved.FamilyName != "Example" || saved.Address.Locality != "Example" || saved.ClaimUpdatedAt == 0 {
		t.Fatalf("bad profile: %+v", saved)
	}
	res = rig.request(t, "GET", path, nil, admin)
	expectStatus(t, res, 200)
	if profileFrom(t, res).CustomAttributes["department"] == nil {
		t.Fatal("custom attributes not persisted")
	}
	expectStatus(t, rig.request(t, "PUT", "/user/profile", map[string]any{"name": "Admin Updated", "nickname": "Boss"}, admin), 200)
	// An admin can edit another user's profile and retain normal self-service access.
	edit := map[string]any{"name": "Alice Admin Edited", "email": saved.Email, "role": "user", "active": true, "given_name": "Changed", "custom_attributes": map[string]any{"department": "Operations"}}
	expectStatus(t, rig.request(t, "PUT", path, edit, admin), 200)
	expectStatus(t, rig.request(t, "GET", "/user/profile", nil, admin), 200)
	for _, bad := range []map[string]any{
		{"name": "Alice", "picture": "javascript:alert(1)"},
		{"name": "Alice", "birthdate": "2025-02-30"},
		{"name": "Alice", "custom_attributes": map[string]any{"role": "admin"}},
		{"name": "Alice", "custom_attributes": []any{1}},
	} {
		expectStatus(t, rig.request(t, "PUT", "/user/profile", bad, alice), 400)
	}
	expectStatus(t, rig.request(t, "GET", "/admin/users", nil, alice), 403)
}
