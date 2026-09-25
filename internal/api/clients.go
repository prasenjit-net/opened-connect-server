package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

func (h *authHandler) clientFailure(w http.ResponseWriter, err error) {
	if errors.Is(err, identity.ErrNotFound) {
		respondError(w, 404, "NOT_FOUND", "Client not found.")
		return
	}
	h.failure(w, err)
}
func (h *authHandler) clients(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	result, err := h.service.ListClients(r.Context(), current(r).Session.Hash, r.URL.Query().Get("q"), page)
	if err != nil {
		h.clientFailure(w, err)
		return
	}
	respondJSON(w, 200, result)
}
func (h *authHandler) client(w http.ResponseWriter, r *http.Request) {
	result, err := h.service.GetClient(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id"))
	if err != nil {
		h.clientFailure(w, err)
		return
	}
	respondJSON(w, 200, result)
}
func (h *authHandler) saveClient(w http.ResponseWriter, r *http.Request) {
	var input identity.ClientMetadata
	if !decode(w, r, &input) {
		return
	}
	result, err := h.service.SaveClient(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id"), input)
	if err != nil {
		h.clientFailure(w, err)
		return
	}
	status := 200
	if r.Method == "POST" {
		status = 201
	}
	respondJSON(w, status, result)
}
func (h *authHandler) deleteClient(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DeleteClient(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id")); err != nil {
		h.clientFailure(w, err)
		return
	}
	w.WriteHeader(204)
}
func (h *authHandler) rotateClientSecret(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decode(w, r, &input) {
		return
	}
	result, err := h.service.RotateClientSecret(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id"))
	if err != nil {
		h.clientFailure(w, err)
		return
	}
	respondJSON(w, 200, result)
}
