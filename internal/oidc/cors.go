package oidc

import (
	"net/http"
	"slices"
)

// Browser token access is explicitly configured and never credentialed.
// This is a response-sharing policy, not a replacement for client authentication.
func (s *Service) WithCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { s.setCORSHeaders(w, r); next(w, r) }
}
func (s *Service) CORSPreflight(w http.ResponseWriter, r *http.Request) {
	if !s.setCORSHeaders(w, r) {
		writeOAuthError(w, http.StatusForbidden, "invalid_request", "Origin is not allowed.")
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "600")
	w.WriteHeader(http.StatusNoContent)
}
func (s *Service) setCORSHeaders(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Add("Vary", "Origin")
	origin := r.Header.Get("Origin")
	if origin != "" && slices.Contains(s.Config.AllowedOrigins, origin) {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		return true
	}
	return false
}
