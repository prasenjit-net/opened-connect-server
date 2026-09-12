package api

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/your-org/go-app-template/internal/config"
	"github.com/your-org/go-app-template/internal/version"
)

func NewRouter(cfg config.Config, logger *slog.Logger, build version.Info) http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Timeout(30 * time.Second))

	h := NewHandler(cfg, build)
	r.Get("/health", h.Health)
	r.Get("/example", h.Example)
	r.Get("/meta", h.Meta)
	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		respondJSON(w, http.StatusOK, map[string]any{
			"service": cfg.App.Name,
			"message": "API ready",
			"routes":  []string{"/api/health", "/api/example", "/api/meta"},
		})
	})

	logger.Debug("api router initialized")
	return r
}
