package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func TestSessionActivityOwnershipAdminAndCSRF(t *testing.T) {
	rig := newAuthRig(t)
	admin := rig.login(t, "admin@example.com", testPassword)
	expectStatus(t, rig.request(t, "POST", "/admin/users", map[string]any{"name": "User", "email": "user@example.com", "role": "user", "active": true, "password": testPassword}, admin), 201)
	user := rig.login(t, "user@example.com", testPassword)
	expectStatus(t, rig.request(t, "POST", "/user/sessions/logout", map[string]any{"scope": "all", "password": "wrong"}, user), 403)
	expectStatus(t, rig.request(t, "GET", "/auth/session", nil, user), 200)
	all := rig.request(t, "GET", "/admin/activity/op-sessions", nil, admin)
	expectStatus(t, all, 200)
	var list identity.SessionActivityList
	_ = json.Unmarshal(all.Body.Bytes(), &list)
	if list.Total != 2 {
		t.Fatalf("admin should see both sessions: %s", all.Body.String())
	}
	own := rig.request(t, "GET", "/user/sessions", nil, user)
	expectStatus(t, own, 200)
	_ = json.Unmarshal(own.Body.Bytes(), &list)
	if list.Total != 1 || !list.Records[0].Current {
		t.Fatal(own.Body.String())
	}
	if strings.Contains(own.Body.String(), "csrf") || strings.Contains(own.Body.String(), "hash") || strings.Contains(own.Body.String(), "Admin") {
		t.Fatal("private fields exposed")
	}
	expectStatus(t, rig.request(t, "GET", "/admin/activity/op-sessions", nil, user), 403)
	id := list.Records[0].ID
	expectStatus(t, rig.request(t, "POST", "/user/sessions/"+id+"/logout", map[string]any{}, admin), 404)
	noCSRF := user
	noCSRF.csrf = ""
	expectStatus(t, rig.request(t, "POST", "/user/sessions/"+id+"/logout", map[string]any{}, noCSRF), 403)
	expectStatus(t, rig.request(t, "POST", "/admin/sessions/"+id+"/logout", map[string]any{}, admin), 200)
	expectStatus(t, rig.request(t, "GET", "/auth/session", nil, user), 401)
	expectStatus(t, rig.request(t, "GET", "/auth/session", nil, admin), 200)
}
