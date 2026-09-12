package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/your-org/go-app-template/internal/config"
	"github.com/your-org/go-app-template/internal/version"
)

type Handler struct {
	config  config.Config
	version version.Info
}

type healthResponse struct {
	Status    string       `json:"status"`
	Service   string       `json:"service"`
	Env       string       `json:"env"`
	Time      time.Time    `json:"time"`
	Version   version.Info `json:"version"`
	Documents []string     `json:"documents"`
}

type exampleResponse struct {
	Title       string   `json:"title"`
	Summary     string   `json:"summary"`
	Features    []string `json:"features"`
	Quickstart  []string `json:"quickstart"`
	Repository  string   `json:"repository"`
	FrontendDir string   `json:"frontendDir"`
}

type metaResponse struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Environment string       `json:"environment"`
	URL         string       `json:"url"`
	UIProxy     string       `json:"uiProxy"`
	Version     version.Info `json:"version"`
}

func NewHandler(cfg config.Config, build version.Info) *Handler {
	return &Handler{config: cfg, version: build}
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, healthResponse{
		Status:  "ok",
		Service: h.config.App.Name,
		Env:     h.config.App.Env,
		Time:    time.Now().UTC(),
		Version: h.version,
		Documents: []string{
			"README.md",
			"config.yaml",
			"ui/src/pages",
		},
	})
}

func (h *Handler) Example(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, exampleResponse{
		Title:       "Go + React starter template",
		Summary:     "Embed a Vite-generated React application directly into the Go binary with one production build.",
		Features:    []string{"Cobra CLI commands", "Viper config + .env support", "Chi API router", "Embedded SPA serving", "React Query + Tailwind UI"},
		Quickstart:  []string{"make install-deps", "make dev-all", "make build", "./build/<binary> serve"},
		Repository:  "Template repository",
		FrontendDir: "ui",
	})
}

func (h *Handler) Meta(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, metaResponse{
		Name:        h.config.App.Name,
		Description: h.config.App.Description,
		Environment: h.config.App.Env,
		URL:         h.config.App.URL,
		UIProxy:     h.config.UI.DevProxyURL,
		Version:     h.version,
	})
}

func respondJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
