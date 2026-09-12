package server

import (
	"bytes"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/prasenjit-net/opened-connect-server/internal/api"
	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/version"
)

type Options struct {
	DevMode bool
	UIFS    fs.FS
}

type App struct {
	cfg     config.Config
	logger  *slog.Logger
	build   version.Info
	options Options
}

func New(cfg config.Config, logger *slog.Logger, build version.Info, options Options) (*App, error) {
	return &App{cfg: cfg, logger: logger, build: build, options: options}, nil
}

func (a *App) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/livez"))
	r.Use(requestLogger(a.logger))

	r.Mount("/api", api.NewRouter(a.cfg, a.logger, a.build))

	if a.options.DevMode && strings.TrimSpace(a.cfg.UI.DevProxyURL) != "" {
		r.Handle("/*", newDevProxy(a.cfg.UI.DevProxyURL, a.logger))
		return r
	}

	distFS, err := fs.Sub(a.options.UIFS, "ui/dist")
	if err != nil {
		a.logger.Error("embedded ui not available", "error", err)
		r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "embedded UI missing; run `make build-ui` before building the binary", http.StatusServiceUnavailable)
		})
		return r
	}

	spa := newSPAHandler(distFS, a.cfg.UI.DefaultTheme)
	r.Handle("/*", spa)

	return r
}

func newDevProxy(rawURL string, logger *slog.Logger) http.Handler {
	target, err := url.Parse(rawURL)
	if err != nil {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, fmt.Sprintf("invalid UI dev proxy URL: %v", err), http.StatusInternalServerError)
		})
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, proxyErr error) {
		logger.Error("vite proxy error", "error", proxyErr)
		http.Error(w, "Vite dev server is unavailable. Start it with `make dev-ui` or `make dev-all`.", http.StatusBadGateway)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})
}

type spaHandler struct {
	fsys         fs.FS
	fileServer   http.Handler
	defaultTheme string
}

func newSPAHandler(fsys fs.FS, defaultTheme string) http.Handler {
	return &spaHandler{
		fsys:         fsys,
		fileServer:   http.FileServer(http.FS(fsys)),
		defaultTheme: defaultTheme,
	}
}

func (h *spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cleanPath := strings.TrimPrefix(path.Clean(r.URL.Path), "/")
	if cleanPath == "." || cleanPath == "" {
		cleanPath = "index.html"
	}

	if cleanPath != "index.html" && fileExists(h.fsys, cleanPath) {
		h.fileServer.ServeHTTP(w, r)
		return
	}

	index, err := fs.ReadFile(h.fsys, "index.html")
	if err != nil {
		http.Error(w, "embedded UI missing; run `make build-ui` before building the binary", http.StatusServiceUnavailable)
		return
	}
	// Render the initial theme before React loads, preserving the requested URL.
	theme := h.defaultTheme
	if theme != "light" && theme != "dark" {
		theme = "auto"
	}
	index = bytes.ReplaceAll(index, []byte("__DEFAULT_THEME__"), []byte(theme))
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, bytes.NewReader(index))
}

func fileExists(fsys fs.FS, name string) bool {
	file, err := fsys.Open(name)
	if err != nil {
		return false
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return false
	}

	return !info.IsDir()
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			logger.Info("request complete",
				"method", r.Method,
				"path", r.URL.Path,
				"status", ww.Status(),
				"bytes", ww.BytesWritten(),
				"duration", time.Since(start).String(),
				"request_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}
