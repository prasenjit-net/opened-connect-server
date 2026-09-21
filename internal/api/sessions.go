package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

func (h *authHandler) sessionActivity(w http.ResponseWriter, r *http.Request) {
	page := 1
	var e error
	if raw := r.URL.Query().Get("page"); raw != "" {
		page, e = strconv.Atoi(raw)
	}
	if e != nil || page < 1 || len(r.URL.Query().Get("q")) > 254 {
		respondError(w, 400, "VALIDATION_ERROR", "Invalid filters.")
		return
	}
	kind := chi.URLParam(r, "kind")
	if kind == "" {
		kind = "op-sessions"
		if strings.HasSuffix(r.URL.Path, "app-sessions") {
			kind = "app-sessions"
		}
	}
	admin := strings.Contains(r.URL.Path, "/admin/")
	result, e := h.service.SessionActivity(r.Context(), current(r).Session.Hash, kind, admin, identity.ActivityOptions{Query: r.URL.Query().Get("q"), Status: r.URL.Query().Get("status"), Page: page})
	if e != nil {
		h.failure(w, e)
		return
	}
	respondJSON(w, 200, result)
}
func (h *authHandler) endSession(w http.ResponseWriter, r *http.Request) {
	var in identity.SessionLogoutRequest
	if !decode(w, r, &in) {
		return
	}
	if !h.limiter.allow("session-logout:"+current(r).User.ID, current(r).User.ID) {
		respondError(w, 429, "RATE_LIMITED", "Too many logout attempts. Try again later.")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		respondError(w, 429, "RATE_LIMITED", "Please try again shortly.")
		return
	}
	kind := chi.URLParam(r, "kind")
	if kind == "" {
		kind = "op-sessions"
		if strings.Contains(r.URL.Path, "/app-sessions/") {
			kind = "app-sessions"
		}
		if strings.Contains(r.URL.Path, "/users/") {
			kind = "user-sessions"
		}
		if strings.Contains(r.URL.Path, "/clients/") {
			kind = "client-access"
		}
	}
	admin := strings.Contains(r.URL.Path, "/admin/")
	operationID, e := h.service.EndSessionsResult(r.Context(), current(r).Session.Hash, kind, chi.URLParam(r, "id"), admin, in)
	if e != nil {
		if errors.Is(e, identity.ErrCredentials) {
			respondError(w, 403, "INVALID_PASSWORD", "The confirmation password is incorrect.")
			return
		}
		h.failure(w, e)
		return
	}
	next := ""
	p := current(r)
	if ((kind == "op-sessions" && (chi.URLParam(r, "id") == p.Session.ID || (chi.URLParam(r, "id") == "" && in.Scope == "all"))) || (kind == "user-sessions" && chi.URLParam(r, "id") == p.User.ID)) && h.oidc != nil {
		var e error
		next, e = h.oidc.PrepareLogout(w, r, p, true)
		if e != nil {
			next = ""
		}
	}
	if kind == "app-sessions" && h.oidc != nil {
		var e error
		next, e = h.oidc.PrepareAppLogout(w, r, p, chi.URLParam(r, "id"))
		if e != nil {
			next = ""
		}
	}
	respondJSON(w, 200, map[string]any{"operationId": operationID, "localOutcome": "ended", "deliveryStatus": "pending_or_unconfirmed", "continueTo": next})
}
func (h *authHandler) prepareLogout(w http.ResponseWriter, r *http.Request) {
	if h.oidc == nil {
		respondJSON(w, 200, map[string]string{"continueTo": ""})
		return
	}
	next, e := h.oidc.PrepareLogout(w, r, current(r), false)
	if e != nil {
		h.failure(w, e)
		return
	}
	respondJSON(w, 200, map[string]string{"continueTo": next})
}

func (h *authHandler) logoutOperation(w http.ResponseWriter, r *http.Request) {
	result, e := h.service.LogoutOperationDetail(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id"))
	if e != nil {
		h.failure(w, e)
		return
	}
	respondJSON(w, 200, result)
}
func (h *authHandler) retryLogoutDelivery(w http.ResponseWriter, r *http.Request) {
	var in identity.SessionLogoutRequest
	if !decode(w, r, &in) {
		return
	}
	id, e := h.service.EndSessionsResult(r.Context(), current(r).Session.Hash, "logout-events", chi.URLParam(r, "id"), true, in)
	if e != nil {
		h.failure(w, e)
		return
	}
	respondJSON(w, 200, map[string]string{"operationId": id, "deliveryStatus": "pending"})
}
