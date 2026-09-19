package oidc

import (
	"net"
	"net/http"
	"time"
)

// Use the peer address, never attacker-controlled forwarding headers. Deployments
// behind a proxy should also apply per-source limits at their trusted edge.
func requestSource(r *http.Request) string {
	source, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return source
}
func (s *Service) allowTraffic(w http.ResponseWriter, r *http.Request, endpoint string) bool {
	if s.trafficLimiter.take(endpoint+"|"+requestSource(r), 240, time.Minute) {
		return true
	}
	w.Header().Set("Retry-After", "60")
	writeOAuthError(w, http.StatusTooManyRequests, "temporarily_unavailable", "Too many requests. Try again later.")
	return false
}
