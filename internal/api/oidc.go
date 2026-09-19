package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// authorizationStatus resolves a pending /authorize transaction for the
// signed-in browser: whether it can complete immediately, needs a consent
// decision, or has failed. It reuses the standard authenticated-GET
// middleware (no CSRF token required for a read).
func (h *authHandler) authorizationStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	view := h.oidc.Status(r, current(r), chi.URLParam(r, "id"))
	respondJSON(w, http.StatusOK, view)
}

// authorizationDecision records a consent decision for a pending
// transaction. It is a normal authenticated write, so the existing
// X-CSRF-Token middleware protects it exactly like any other mutation.
func (h *authHandler) authorizationDecision(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Approve bool     `json:"approve"`
		Scopes  []string `json:"scopes"`
	}
	if !decode(w, r, &in) {
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	view := h.oidc.Decide(r, current(r), chi.URLParam(r, "id"), in.Approve, in.Scopes)
	respondJSON(w, http.StatusOK, view)
}
