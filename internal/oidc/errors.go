package oidc

import (
	"encoding/json"
	"html"
	"net/http"
	"net/url"
)

// writeOAuthError writes a JSON OAuth 2.0 error response (RFC 6749 section
// 5.2), used by /token and /userinfo. It never uses internal/api's JSON/CSRF
// management error envelope.
func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}

// errorRedirectURL builds an OAuth authorization error response (RFC 6749
// section 4.1.2.1) against an already-validated redirect URI. Callers must
// only ever pass a redirectURI that was matched exactly against the
// client's registered list; by the time this is called that match has
// already happened, so a parse failure here should be unreachable.
func errorRedirectURL(redirectURI, code, description, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	q.Set("error", code)
	if description != "" {
		q.Set("error_description", description)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// redirectWithError sends a 302 back to an already-validated client
// redirect URI with an OAuth authorization error response.
func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, code, description, state string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, errorRedirectURL(redirectURI, code, description, state), http.StatusFound)
}

// writeAuthorizeErrorPage renders a minimal HTML error page for failures
// that occur before the client and redirect URI have been validated — the
// request itself is untrusted at that point, so it must never be redirected
// anywhere.
func writeAuthorizeErrorPage(w http.ResponseWriter, description string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>Sign-in request error</title></head><body><h1>This sign-in request cannot be completed</h1><p>` + html.EscapeString(description) + `</p></body></html>`))
}
