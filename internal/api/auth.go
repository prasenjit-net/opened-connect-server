package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prasenjit-net/openid-connect-server/internal/config"
	"github.com/prasenjit-net/openid-connect-server/internal/identity"
	"github.com/prasenjit-net/openid-connect-server/internal/oidc"
)

type principalKey struct{}
type authHandler struct {
	service *identity.Service
	oidc    *oidc.Service
	cfg     config.Config
	logger  *slog.Logger
	limiter *loginLimiter
	slots   chan struct{}
}

const cookieName = identity.SessionCookieName

func (h *authHandler) cookie(w http.ResponseWriter, token string, expires time.Time) {
	age := int(time.Until(expires).Seconds())
	if token == "" {
		age = -1
		expires = time.Unix(1, 0)
	}
	http.SetCookie(w, &http.Cookie{ // NOSONAR: config.Load forces Secure for HTTPS and non-development/test environments; HTTP development is intentional.
		Name: cookieName, Value: token, Path: "/", HttpOnly: true, Secure: h.cfg.Auth.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: age, Expires: expires})
}
func requestHash(r *http.Request) string {
	c, err := r.Cookie(cookieName)
	if err != nil || len(c.Value) != 43 {
		return ""
	}
	return identity.SessionHash(c.Value)
}
func current(r *http.Request) identity.Principal {
	return r.Context().Value(principalKey{}).(identity.Principal)
}
func (h *authHandler) failure(w http.ResponseWriter, err error) {
	var validation identity.ValidationError
	switch {
	case errors.Is(err, identity.ErrUnauthorized):
		respondError(w, 401, "UNAUTHORIZED", "Sign in to continue.")
	case errors.Is(err, identity.ErrCredentials):
		respondError(w, 401, "INVALID_CREDENTIALS", "Invalid email or password.")
	case errors.Is(err, identity.ErrForbidden):
		respondError(w, 403, "FORBIDDEN", "Administrator access is required.")
	case errors.Is(err, identity.ErrNotFound):
		respondError(w, 404, "NOT_FOUND", "User not found.")
	case errors.Is(err, identity.ErrConflict), errors.Is(err, identity.ErrLastAdmin):
		respondError(w, 409, "CONFLICT", err.Error())
	case errors.As(err, &validation):
		respondError(w, 400, "VALIDATION", validation.Error())
	default:
		h.logger.Error("identity operation failed", "error", err)
		respondError(w, 500, "INTERNAL", "Unable to complete the request.")
	}
}
func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		respondError(w, 400, "BAD_REQUEST", "Invalid request body.")
		return false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		respondError(w, 400, "BAD_REQUEST", "Expected one JSON object.")
		return false
	}
	return true
}
func (h *authHandler) safety(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS" {
			media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
			if err != nil || media != "application/json" {
				respondError(w, 415, "UNSUPPORTED_MEDIA_TYPE", "Use application/json.")
				return
			}
			origin := r.Header.Get("Origin")
			// Browser login CSRF is blocked by same-origin checks plus JSON-only requests.
			// Authenticated writes additionally require the per-session CSRF token.
			if origin != "" {
				parsed, err := url.Parse(origin)
				configured, _ := url.Parse(h.cfg.App.URL)
				sameRequest := err == nil && parsed.Host == r.Host && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Path == ""
				sameConfigured := err == nil && configured != nil && parsed.Scheme == configured.Scheme && parsed.Host == configured.Host && parsed.Path == ""
				sameDev := false
				if h.cfg.App.Env == "development" {
					devURL, devErr := url.Parse(h.cfg.UI.DevProxyURL)
					sameDev = err == nil && devErr == nil && parsed.Scheme == devURL.Scheme && parsed.Host == devURL.Host && parsed.Path == ""
				}
				if !sameRequest && !sameConfigured && !sameDev {
					respondError(w, 403, "CSRF", "Request origin is not allowed.")
					return
				}
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				respondError(w, 403, "CSRF", "Cross-site requests are not allowed.")
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
func (h *authHandler) authenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, err := h.service.Authenticate(r.Context(), requestHash(r))
		if err != nil {
			h.failure(w, err)
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" {
			if subtle.ConstantTimeCompare([]byte(p.Session.CSRF), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
				respondError(w, 403, "CSRF", "Invalid security token. Refresh the page and try again.")
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalKey{}, p)))
	})
}
func (h *authHandler) admin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if current(r).User.Role != identity.RoleAdmin {
			h.failure(w, identity.ErrForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
func sessionResponse(p identity.Principal) any {
	return map[string]any{"user": p.User, "csrfToken": p.Session.CSRF, "expiresAt": p.Session.ExpiresAt}
}
func (h *authHandler) login(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	if !h.limiter.allow(ip, strings.ToLower(strings.TrimSpace(input.Email))) {
		w.Header().Set("Retry-After", "900")
		respondError(w, 429, "RATE_LIMITED", "Too many sign-in attempts. Try again in 15 minutes.")
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		respondError(w, 429, "RATE_LIMITED", "Sign-in is busy. Try again shortly.")
		return
	}
	result, err := h.service.Login(r.Context(), input.Email, input.Password, requestHash(r))
	if err != nil {
		h.failure(w, err)
		return
	}
	_ = h.service.ObserveSession(r.Context(), result.Session.Hash, r.UserAgent())
	h.cookie(w, result.Token, result.Session.ExpiresAt)
	respondJSON(w, 200, sessionResponse(result.Principal))
}
func (h *authHandler) session(w http.ResponseWriter, r *http.Request) {
	if time.Since(current(r).Session.LastSeenAt) > time.Minute {
		_ = h.service.ObserveSession(r.Context(), current(r).Session.Hash, r.UserAgent())
	}
	respondJSON(w, 200, sessionResponse(current(r)))
}
func (h *authHandler) logout(w http.ResponseWriter, r *http.Request) {
	if err := h.service.Logout(r.Context(), current(r).Session.Hash); err != nil {
		h.failure(w, err)
		return
	}
	h.cookie(w, "", time.Time{})
	w.WriteHeader(204)
}
func (h *authHandler) profile(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, 200, current(r).User)
}
func (h *authHandler) updateProfile(w http.ResponseWriter, r *http.Request) {
	var in identity.ProfileInput
	if !decode(w, r, &in) {
		return
	}
	user, err := h.service.UpdateProfile(r.Context(), current(r).Session.Hash, in)
	if err != nil {
		h.failure(w, err)
		return
	}
	if user.Email != current(r).User.Email {
		h.cookie(w, "", time.Time{})
	}
	respondJSON(w, 200, user)
}
func (h *authHandler) password(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"currentPassword"`
		New     string `json:"newPassword"`
	}
	if !decode(w, r, &in) {
		return
	}
	if err := h.service.ChangePassword(r.Context(), current(r).Session.Hash, in.Current, in.New); err != nil {
		h.failure(w, err)
		return
	}
	h.cookie(w, "", time.Time{})
	w.WriteHeader(204)
}
func (h *authHandler) users(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("pageSize"))
	result, err := h.service.ListUsers(r.Context(), current(r).Session.Hash, identity.ListOptions{Query: q.Get("q"), Role: identity.Role(q.Get("role")), Status: q.Get("status"), Page: page, PageSize: size})
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 200, result)
}
func (h *authHandler) user(w http.ResponseWriter, r *http.Request) {
	user, err := h.service.GetUser(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id"))
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 200, user)
}
func (h *authHandler) createUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		identity.UserInput
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	user, err := h.service.CreateUser(r.Context(), current(r).Session.Hash, in.UserInput, in.Password)
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 201, user)
}
func (h *authHandler) updateUser(w http.ResponseWriter, r *http.Request) {
	var in identity.UserInput
	if !decode(w, r, &in) {
		return
	}
	user, err := h.service.UpdateUser(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id"), in)
	if err != nil {
		h.failure(w, err)
		return
	}
	respondJSON(w, 200, user)
}
func (h *authHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
	if err := h.service.DeleteUser(r.Context(), current(r).Session.Hash, chi.URLParam(r, "id")); err != nil {
		h.failure(w, err)
		return
	}
	w.WriteHeader(204)
}

type limitEntry struct {
	count   int
	expires time.Time
}
type loginLimiter struct {
	mu      sync.Mutex
	entries map[string]limitEntry
}

func (l *loginLimiter) allow(ip, email string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	for key, e := range l.entries {
		if !e.expires.After(now) {
			delete(l.entries, key)
		}
	}
	keys := []string{"ip:" + ip, "email:" + identity.SessionHash(email)}
	for i, key := range keys {
		limit := 30
		if i == 1 {
			limit = 10
		}
		if l.entries[key].count >= limit {
			return false
		}
		if _, ok := l.entries[key]; !ok && len(l.entries) >= 10000 {
			return false
		}
	}
	for _, key := range keys {
		entry := l.entries[key]
		if entry.count == 0 {
			entry.expires = now.Add(15 * time.Minute)
		}
		entry.count++
		l.entries[key] = entry
	}
	return true
}
