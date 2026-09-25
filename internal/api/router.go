package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/prasenjit-net/openid-connect-server/internal/config"
	"github.com/prasenjit-net/openid-connect-server/internal/identity"
	"github.com/prasenjit-net/openid-connect-server/internal/oidc"
	"github.com/prasenjit-net/openid-connect-server/internal/version"
)

func NewRouter(cfg config.Config, logger *slog.Logger, build version.Info, service *identity.Service, oidcService *oidc.Service) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Timeout(30 * time.Second))

	h := NewHandler(cfg, build)
	auth := &authHandler{service: service, oidc: oidcService, cfg: cfg, logger: logger, limiter: &loginLimiter{entries: map[string]limitEntry{}}, slots: make(chan struct{}, 4)}
	r.Use(auth.safety)
	// Each API group owns its authorization boundary.
	r.Route("/public", func(r chi.Router) {
		r.Get("/health", h.Health)
		r.Get("/config", h.Config)
	})
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login", auth.login)
		r.Group(func(r chi.Router) {
			r.Use(auth.authenticated)
			r.Get("/session", auth.session)
			r.Post("/logout", auth.logout)
			r.Post("/logout/prepare", auth.prepareLogout)
		})
	})
	r.Route("/user", func(r chi.Router) {
		r.Use(auth.authenticated)
		r.Get("/sessions", auth.sessionActivity)
		r.Get("/app-sessions", auth.sessionActivity)
		r.Get("/session-activity/{kind}", auth.sessionActivity)
		r.Post("/sessions/logout", auth.endSession)
		r.Post("/sessions/{id}/logout", auth.endSession)
		r.Post("/app-sessions/{id}/logout", auth.endSession)
		r.Post("/clients/{id}/revoke-access", auth.endSession)
		r.Get("/profile", auth.profile)
		r.Put("/profile", auth.updateProfile)
		r.Post("/profile/password", auth.password)
		if oidcService != nil {
			r.Get("/authorization/{id}", auth.authorizationStatus)
			r.Post("/authorization/{id}/decision", auth.authorizationDecision)
		}
	})
	r.Route("/admin", func(r chi.Router) {
		r.Use(auth.authenticated, auth.admin)
		r.Get("/oauth", auth.oauthSettings)
		r.Get("/clients/{id}/oauth-policy", auth.oauthPolicy)
		r.Put("/clients/{id}/oauth-policy", auth.oauthPolicy)
		r.Get("/users/{id}/oauth-access", auth.oauthAccess)
		r.Put("/users/{id}/oauth-access", auth.oauthAccess)
		r.Get("/logout-operations/{id}", auth.logoutOperation)
		r.Post("/logout-deliveries/{id}/retry", auth.retryLogoutDelivery)
		r.Get("/activity/overview", auth.overview)
		r.Get("/activity/{kind}", auth.activity)
		r.Post("/session-activity/{kind}/{id}/logout", auth.endSession)
		r.Post("/sessions/{id}/logout", auth.endSession)
		r.Post("/app-sessions/{id}/logout", auth.endSession)
		r.Post("/activity/{kind}/{id}/revoke", auth.revokeActivity)
		r.Get("/registration", auth.registrationSettings)
		r.Get("/registration-tokens", auth.registrationTokens)
		r.Post("/registration-tokens", auth.issueRegistrationToken)
		r.Post("/registration-tokens/{id}/revoke", auth.revokeRegistrationToken)
		r.Post("/clients/{id}/registration-token", auth.clientRegistrationToken)
		r.Delete("/clients/{id}/registration-token", auth.clientRegistrationToken)
		r.Get("/clients", auth.clients)
		r.Post("/clients", auth.saveClient)
		r.Get("/clients/{id}", auth.client)
		r.Put("/clients/{id}", auth.saveClient)
		r.Delete("/clients/{id}", auth.deleteClient)
		r.Post("/clients/{id}/secret", auth.rotateClientSecret)
		r.Post("/users/{id}/sessions/logout", auth.endSession)
		r.Get("/users", auth.users)
		r.Post("/users", auth.createUser)
		r.Get("/users/{id}", auth.user)
		r.Put("/users/{id}", auth.updateUser)
		r.Delete("/users/{id}", auth.deleteUser)
	})
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "API endpoint not found")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		respondError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	})

	logger.Debug("api router initialized")
	return r
}
