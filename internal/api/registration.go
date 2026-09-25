package api

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

func (h *authHandler) registrationSettings(w http.ResponseWriter, r *http.Request) {
	endpoint := ""
	if h.oidc != nil {
		endpoint = h.oidc.Config.Issuer + "/register"
	}
	respondJSON(w, 200, map[string]any{"enabled": h.oidc != nil && h.oidc.Config.RegistrationEnabled, "endpoint": endpoint})
}
func (h *authHandler) registrationTokens(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	out, err := h.service.ListInitialTokens(r.Context(), current(r).Session.Hash, r.URL.Query().Get("q"), page)
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 200, out)
}
func (h *authHandler) issueRegistrationToken(w http.ResponseWriter, r *http.Request) {
	var input identity.InitialTokenInput
	if !decode(w, r, &input) {
		return
	}
	view, token, err := h.service.IssueInitialToken(r.Context(), current(r).Session.Hash, input)
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 201, map[string]any{"credential": view, "token": token})
}
func (h *authHandler) revokeRegistrationToken(w http.ResponseWriter, r *http.Request) {
	var input struct{}
	if !decode(w, r, &input) {
		return
	}
	err := h.service.RevokeInitialToken(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id"))
	if errors.Is(err, identity.ErrRegistrationInactive) {
		respondError(w, 409, "REGISTRATION_NOT_ACTIVE", "This token is no longer active.")
		return
	}
	if err != nil {
		h.clientFailure(w, err)
		return
	}
	w.WriteHeader(204)
}
func (h *authHandler) clientRegistrationToken(w http.ResponseWriter, r *http.Request) {
	issue := r.Method == http.MethodPost
	if issue {
		var input struct{}
		if !decode(w, r, &input) {
			return
		}
	}
	token, err := h.service.ManageRegistrationToken(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id"), issue)
	if err != nil {
		h.clientFailure(w, err)
		return
	}
	if !issue {
		w.WriteHeader(204)
		return
	}
	respondJSON(w, 201, map[string]string{"token": token})
}
