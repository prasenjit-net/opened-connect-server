package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"github.com/prasenjit-net/opened-connect-server/internal/version"
)

func NewRouter(cfg config.Config, logger *slog.Logger, build version.Info, service *identity.Service) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Timeout(30 * time.Second))

	h := NewHandler(cfg, build)
	auth := &authHandler{service: service, cfg: cfg, logger: logger, limiter: &loginLimiter{entries: map[string]limitEntry{}}, slots: make(chan struct{}, 4)}
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
		})
	})
	r.Route("/user", func(r chi.Router) {
		r.Use(auth.authenticated)
		r.Get("/profile", auth.profile)
		r.Put("/profile", auth.updateProfile)
		r.Post("/profile/password", auth.password)
	})
	r.Route("/admin", func(r chi.Router) {
		r.Use(auth.authenticated, auth.admin)
		r.Get("/clients", auth.clients)
		r.Post("/clients", auth.saveClient)
		r.Get("/clients/{id}", auth.client)
		r.Put("/clients/{id}", auth.saveClient)
		r.Delete("/clients/{id}", auth.deleteClient)
		r.Post("/clients/{id}/secret", auth.rotateClientSecret)
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
