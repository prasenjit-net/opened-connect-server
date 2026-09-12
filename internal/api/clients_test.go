package api

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func clientBody(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestClientManagementAndAuthorization(t *testing.T) {
	rig := newAuthRig(t)
	admin := rig.login(t, "admin@example.com", testPassword)
	res := rig.request(t, "POST", "/admin/users", map[string]any{"name": "User", "email": "user@example.com", "password": testPassword, "role": "user"}, admin)
	expectStatus(t, res, 201)
	user := rig.login(t, "user@example.com", testPassword)
	input := map[string]any{"client_name": "Portal", "redirect_uris": []string{"https://app.example.com/callback"}, "client_name#fr": "Portail", "default_max_age": 0, "require_auth_time": true, "contacts": []string{"owner@example.com"}}
	for _, test := range []struct{ method, path string }{
		{"GET", "/admin/clients"}, {"POST", "/admin/clients"}, {"GET", "/admin/clients/unknown"}, {"PUT", "/admin/clients/unknown"}, {"DELETE", "/admin/clients/unknown"}, {"POST", "/admin/clients/unknown/secret"},
	} {
		expectStatus(t, rig.request(t, test.method, test.path, input, browserSession{}), 401)
		expectStatus(t, rig.request(t, test.method, test.path, input, user), 403)
		if test.method != "GET" {
			expectStatus(t, rig.request(t, test.method, test.path, input, browserSession{cookie: admin.cookie}), 403)
		}
	}
	expectStatus(t, rig.request(t, "GET", "/admin/clients/missing", nil, admin), 404)
	res = rig.request(t, "POST", "/admin/clients", input, admin)
	expectStatus(t, res, 201)
	created := clientBody(t, res.Body.Bytes())
	id := created["client_id"].(string)
	secret := created["client_secret"].(string)
	if len(id) < 32 || len(secret) < 64 || created["token_endpoint_auth_method"] != "client_secret_basic" || created["client_secret_expires_at"] != float64(0) {
		t.Fatalf("unexpected client defaults: %v", created)
	}
	for _, path := range []string{"/admin/clients/" + id, "/admin/clients?q=portal", "/admin/clients?q=" + id} {
		res = rig.request(t, "GET", path, nil, admin)
		expectStatus(t, res, 200)
		if strings.Contains(res.Body.String(), secret) || strings.Contains(res.Body.String(), `"client_secret":`) {
			t.Fatal("secret exposed on read")
		}
		if !strings.Contains(res.Body.String(), id) {
			t.Fatal("client not found by search")
		}
	}
	disk, err := os.ReadFile(filepath.Join(rig.dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disk), secret) {
		t.Fatal("plaintext secret persisted")
	}
	key, err := os.Stat(filepath.Join(rig.dir, "client-secrets.key"))
	if err != nil {
		t.Fatal(err)
	}
	if key.Mode().Perm() != 0600 {
		t.Fatal("insecure encryption key permissions")
	}
	restartedStore, err := identity.NewFileStore(rig.dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := restartedStore.Read(context.Background(), func(tx identity.ReadTx) error {
		stored, err := tx.Client(id)
		if err != nil {
			return err
		}
		if stored.Secret != secret {
			t.Fatal("secret failed encrypted storage round-trip")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	restarted, err := identity.NewService(restartedStore, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.GetClient(context.Background(), identity.SessionHash(admin.cookie.Value), id); err != nil {
		t.Fatal("client did not survive restart", err)
	}
	input["client_name"] = "Updated Portal"
	res = rig.request(t, "PUT", "/admin/clients/"+id, input, admin)
	expectStatus(t, res, 200)
	updated := clientBody(t, res.Body.Bytes())
	if updated["client_id"] != id || updated["client_name"] != "Updated Portal" || updated["client_secret"] != nil || updated["client_name#fr"] != "Portail" {
		t.Fatal("update changed identity or lost metadata")
	}
	res = rig.request(t, "POST", "/admin/clients/"+id+"/secret", map[string]any{}, admin)
	expectStatus(t, res, 200)
	rotated := clientBody(t, res.Body.Bytes())["client_secret"].(string)
	if rotated == secret {
		t.Fatal("rotation reused secret")
	}
	input["token_endpoint_auth_method"] = "none"
	res = rig.request(t, "PUT", "/admin/clients/"+id, input, admin)
	expectStatus(t, res, 200)
	if clientBody(t, res.Body.Bytes())["has_client_secret"] != false {
		t.Fatal("public client retained secret")
	}
	expectStatus(t, rig.request(t, "POST", "/admin/clients/"+id+"/secret", map[string]any{}, admin), 400)
	input["token_endpoint_auth_method"] = "client_secret_post"
	res = rig.request(t, "PUT", "/admin/clients/"+id, input, admin)
	expectStatus(t, res, 200)
	if clientBody(t, res.Body.Bytes())["client_secret"] == nil {
		t.Fatal("secret not issued after authentication change")
	}
	input["client_id"] = "attacker"
	expectStatus(t, rig.request(t, "PUT", "/admin/clients/"+id, input, admin), 400)
	delete(input, "client_id")
	// Force several pages without involving user/password creation.
	for i := 0; i < 10; i++ {
		input["client_name"] = fmt.Sprintf("Page client %d", i)
		input["token_endpoint_auth_method"] = "none"
		expectStatus(t, rig.request(t, "POST", "/admin/clients", input, admin), 201)
	}
	res = rig.request(t, "GET", "/admin/clients", nil, admin)
	expectStatus(t, res, 200)
	var list struct {
		Clients               []map[string]any
		Total, Page, PageSize int
	}
	if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Clients) != 10 || list.Total != 11 || list.PageSize != 10 {
		t.Fatal("incorrect pagination")
	}
	res = rig.request(t, "GET", "/admin/clients?page=2", nil, admin)
	if err := json.Unmarshal(res.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Clients) != 1 || list.Page != 2 {
		t.Fatal("incorrect second page")
	}
	expectStatus(t, rig.request(t, "DELETE", "/admin/clients/"+id, nil, admin), 204)
	expectStatus(t, rig.request(t, "GET", "/admin/clients/"+id, nil, admin), 404)
}
