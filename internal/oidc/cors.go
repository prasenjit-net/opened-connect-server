package oidc

import "net/http"

// WithCORS wraps /token and /userinfo with narrow, non-credentialed CORS.
// These endpoints never trust cookies for authentication (only client
// credentials and bearer tokens), so allowing a cross-origin browser public
// client to read the response doesn't weaken anything — credentialed
// access (Access-Control-Allow-Credentials) is never enabled here, and
// global management API CORS is a separate, unrelated concern this does
// not touch.
func WithCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setCORSHeaders(w, r)
		next(w, r)
	}
}

// CORSPreflight answers a browser's CORS preflight OPTIONS request for
// /token or /userinfo.
func CORSPreflight(w http.ResponseWriter, r *http.Request) {
	setCORSHeaders(w, r)
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}

func setCORSHeaders(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
	}
}
