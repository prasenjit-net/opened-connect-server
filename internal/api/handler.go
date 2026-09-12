package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/version"
)

type Handler struct {
	config    config.Config
	version   version.Info
	startedAt time.Time
}

type uiConfigResponse struct {
	AppName      string `json:"appName"`
	Tagline      string `json:"tagline"`
	DefaultTheme string `json:"defaultTheme"`
	RepoURL      string `json:"repoUrl"`
}

type configResponse struct {
	UI          uiConfigResponse `json:"ui"`
	Version     string           `json:"version"`
	StartedAtMS int64            `json:"startedAtMs"`
}

func NewHandler(cfg config.Config, build version.Info) *Handler {
	return &Handler{config: cfg, version: build, startedAt: time.Now()}
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]string{"status": "ok", "version": h.version.Version})
}

func (h *Handler) Config(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, configResponse{
		UI: uiConfigResponse{
			AppName:      h.config.App.Name,
			Tagline:      h.config.App.Description,
			DefaultTheme: h.config.UI.DefaultTheme,
			RepoURL:      h.config.UI.RepoURL,
		},
		Version:     h.version.Version,
		StartedAtMS: h.startedAt.UnixMilli(),
	})
}

func respondError(w http.ResponseWriter, status int, code, message string) {
	respondJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
