package api

import (
	"strings"
	"testing"
)

func TestRegistrationAdministrationAuthorization(t *testing.T) {
	rig := newAuthRig(t)
	admin := rig.login(t, "admin@example.com", testPassword)
	expectStatus(t, rig.request(t, "POST", "/admin/users", map[string]any{"name": "User", "email": "user@example.com", "password": testPassword, "role": "user"}, admin), 201)
	user := rig.login(t, "user@example.com", testPassword)
	for _, route := range [][2]string{{"GET", "/admin/registration"}, {"GET", "/admin/registration-tokens"}, {"POST", "/admin/registration-tokens"}, {"POST", "/admin/registration-tokens/missing/revoke"}, {"POST", "/admin/clients/missing/registration-token"}, {"DELETE", "/admin/clients/missing/registration-token"}} {
		expectStatus(t, rig.request(t, route[0], route[1], map[string]any{}, browserSession{}), 401)
		expectStatus(t, rig.request(t, route[0], route[1], map[string]any{}, user), 403)
		if route[0] != "GET" {
			expectStatus(t, rig.request(t, route[0], route[1], map[string]any{}, browserSession{cookie: admin.cookie}), 403)
		}
	}
	res := rig.request(t, "POST", "/admin/registration-tokens", map[string]any{"label": "Developer"}, admin)
	expectStatus(t, res, 201)
	body := clientBody(t, res.Body.Bytes())
	token := body["token"].(string)
	id := body["credential"].(map[string]any)["id"].(string)
	res = rig.request(t, "GET", "/admin/registration-tokens?q=Developer", nil, admin)
	expectStatus(t, res, 200)
	list := clientBody(t, res.Body.Bytes())
	if list["total"] != float64(1) || list["pageSize"] != float64(10) {
		t.Fatal("incorrect list")
	}
	if strings.Contains(res.Body.String(), token) {
		t.Fatal("token leaked on list")
	}
	expectStatus(t, rig.request(t, "POST", "/admin/registration-tokens/"+id+"/revoke", map[string]any{}, admin), 204)
	expectStatus(t, rig.request(t, "POST", "/admin/registration-tokens/"+id+"/revoke", map[string]any{}, admin), 409)
}
