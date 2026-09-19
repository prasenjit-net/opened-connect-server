package api

import (
	"encoding/json"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"testing"
)

func TestOAuthAdministrationBoundaries(t *testing.T) {
	rig := newAuthRig(t)
	admin := rig.login(t, "admin@example.com", testPassword)
	created := rig.request(t, "POST", "/admin/users", map[string]any{"name": "User", "email": "user@example.com", "role": "user", "active": true, "password": testPassword}, admin)
	expectStatus(t, created, 201)
	var user identity.Profile
	_ = json.Unmarshal(created.Body.Bytes(), &user)
	regular := rig.login(t, "user@example.com", testPassword)
	created = rig.request(t, "POST", "/admin/clients", map[string]any{"grant_types": []string{"client_credentials"}}, admin)
	expectStatus(t, created, 201)
	var client map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &client)
	id := client["client_id"].(string)
	for _, path := range []string{"/admin/oauth", "/admin/clients/" + id + "/oauth-policy", "/admin/users/" + user.ID + "/oauth-access"} {
		expectStatus(t, rig.request(t, "GET", path, nil, browserSession{}), 401)
		expectStatus(t, rig.request(t, "GET", path, nil, regular), 403)
		expectStatus(t, rig.request(t, "GET", path, nil, admin), 200)
	}
	path := "/admin/clients/" + id + "/oauth-policy"
	policy := map[string]any{"grants": []string{"client_credentials"}}
	expectStatus(t, rig.request(t, "PUT", path, policy, regular), 403)
	expectStatus(t, rig.request(t, "PUT", path, policy, browserSession{cookie: admin.cookie}), 403)
	expectStatus(t, rig.request(t, "PUT", path, policy, admin), 200)
	expectStatus(t, rig.request(t, "PUT", path, map[string]any{"grants": []string{"password"}}, admin), 400)
	expectStatus(t, rig.request(t, "PUT", "/admin/users/"+user.ID+"/oauth-access", map[string]any{"https://unknown.example": []string{"read"}}, admin), 400)
	expectStatus(t, rig.request(t, "PUT", "/user/profile", map[string]any{"name": "User", "email": "user@example.com", "oauthAccess": map[string]any{"all": []string{"*"}}}, regular), 400)
}
