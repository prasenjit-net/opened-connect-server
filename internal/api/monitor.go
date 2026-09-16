package api

import (
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"net/http"
	"strconv"
)

func (h *authHandler) activity(w http.ResponseWriter, r *http.Request) {
	page := 1
	if raw := r.URL.Query().Get("page"); raw != "" {
		var err error
		page, err = strconv.Atoi(raw)
		if err != nil || page < 1 {
			respondError(w, 400, "VALIDATION_ERROR", "Page must be a positive integer.")
			return
		}
	}
	if len(r.URL.Query().Get("q")) > 254 {
		respondError(w, 400, "VALIDATION_ERROR", "Search is too long.")
		return
	}
	result, err := h.service.Activity(r.Context(), current(r).Session.Hash, chi.URLParam(r, "kind"), identity.ActivityOptions{Query: r.URL.Query().Get("q"), Status: r.URL.Query().Get("status"), Page: page})
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 200, result)
}
func (h *authHandler) overview(w http.ResponseWriter, r *http.Request) {
	result, err := h.service.ActivityOverview(r.Context(), current(r).Session.Hash)
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 200, struct {
		identity.ActivityOverview
		ProtocolEnabled bool `json:"protocolEnabled"`
	}{result, h.cfg.OIDC.Enabled})
}
func (h *authHandler) revokeActivity(w http.ResponseWriter, r *http.Request) {
	var in struct{}
	if !decode(w, r, &in) {
		return
	}
	if err := h.service.RevokeActivity(r.Context(), current(r).Session.Hash, chi.URLParam(r, "kind"), chi.URLParam(r, "id")); err != nil {
		if errors.Is(err, identity.ErrActivityNotActive) {
			respondError(w, http.StatusConflict, "ACTIVITY_NOT_ACTIVE", err.Error())
			return
		}
		h.failure(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
