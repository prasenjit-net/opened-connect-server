package api

import (
	"github.com/go-chi/chi/v5"
	"github.com/prasenjit-net/openid-connect-server/internal/identity"
	"net/http"
)

func (h *authHandler) oauthSettings(w http.ResponseWriter, r *http.Request) {
	resources := h.cfg.OAuth.Resources
	if resources == nil {
		resources = []identity.Resource{}
	}
	respondJSON(w, 200, map[string]any{"resources": resources, "passwordGrantEnabled": h.cfg.OAuth.PasswordGrantEnabled, "refreshTokensEnabled": h.cfg.OAuth.RefreshTokensEnabled, "protocolEnabled": h.cfg.OIDC.Enabled})
}
func (h *authHandler) oauthPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	hash := current(r).Session.Hash
	if r.Method == http.MethodPut {
		var p identity.OAuthPolicy
		if !decode(w, r, &p) {
			return
		}
		if err := h.service.SetOAuthPolicy(r.Context(), hash, id, p, h.cfg.OAuth.Resources); err != nil {
			h.failure(w, err)
			return
		}
	}
	p, err := h.service.GetOAuthPolicy(r.Context(), hash, id)
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 200, p)
}
func (h *authHandler) oauthAccess(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	hash := current(r).Session.Hash
	if r.Method == http.MethodPut {
		var a identity.OAuthAccess
		if !decode(w, r, &a) {
			return
		}
		if err := h.service.SetOAuthAccess(r.Context(), hash, id, a, h.cfg.OAuth.Resources); err != nil {
			h.failure(w, err)
			return
		}
	}
	a, err := h.service.GetOAuthAccess(r.Context(), hash, id)
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 200, a)
}
