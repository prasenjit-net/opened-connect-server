package api

import "testing"

func TestAPIGroupBoundaries(t *testing.T) {
	rig := newAuthRig(t)
	admin := rig.login(t, "admin@example.com", testPassword)
	expectStatus(t, rig.request(t, "POST", "/admin/users", map[string]any{"name": "User", "email": "user@example.com", "password": testPassword, "role": "user"}, admin), 201)
	user := rig.login(t, "user@example.com", testPassword)
	for _, session := range []browserSession{{}, user, admin} {
		for _, path := range []string{"/public/config", "/public/health"} {
			expectStatus(t, rig.request(t, "GET", path, nil, session), 200)
		}
	}
	for _, path := range []string{"/admin/users", "/admin/clients"} {
		expectStatus(t, rig.request(t, "GET", path, nil, browserSession{}), 401)
		expectStatus(t, rig.request(t, "GET", path, nil, user), 403)
		expectStatus(t, rig.request(t, "GET", path, nil, admin), 200)
	}
	for _, session := range []browserSession{user, admin} {
		expectStatus(t, rig.request(t, "GET", "/user/profile", nil, session), 200)
		expectStatus(t, rig.request(t, "PUT", "/user/profile", map[string]string{"name": "Updated"}, session), 200)
		expectStatus(t, rig.request(t, "POST", "/user/profile/password", map[string]string{"currentPassword": "wrong", "newPassword": "a new secure password"}, session), 400)
		expectStatus(t, rig.request(t, "PUT", "/user/profile", map[string]string{"name": "Updated"}, browserSession{cookie: session.cookie}), 403)
	}
	expectStatus(t, rig.request(t, "GET", "/user/profile", nil, browserSession{}), 401)
	expectStatus(t, rig.request(t, "POST", "/user/profile/password", map[string]any{}, browserSession{}), 401)
	// Old ungrouped routes must not remain as authorization bypasses or aliases.
	for _, path := range []string{"/users", "/users/missing", "/clients", "/clients/missing", "/clients/missing/secret", "/profile", "/profile/password", "/health", "/config"} {
		for _, method := range []string{"GET", "POST", "PUT", "DELETE"} {
			expectStatus(t, rig.request(t, method, path, map[string]any{}, admin), 404)
		}
	}
}
