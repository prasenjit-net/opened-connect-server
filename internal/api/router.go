package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/version"
)

func NewRouter(cfg config.Config, logger *slog.Logger, build version.Info) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Timeout(30 * time.Second))

	h := NewHandler(cfg, build)
	r.Get("/health", h.Health)
	r.Get("/config", h.Config)
	r.NotFound(func(w http.ResponseWriter, r *http.Request) {
		respondError(w, http.StatusNotFound, "NOT_FOUND", "API endpoint not found")
	})
	r.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		respondError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	})

	logger.Debug("api router initialized")
	return r
}
