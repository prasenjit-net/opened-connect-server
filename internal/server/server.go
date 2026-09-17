package server

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/prasenjit-net/opened-connect-server/internal/api"
	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"github.com/prasenjit-net/opened-connect-server/internal/oidc"
	"github.com/prasenjit-net/opened-connect-server/internal/version"
)

type Options struct {
	Store   identity.Store
	DevMode bool
	UIFS    fs.FS
}

type App struct {
	identity *identity.Service
	oidc     *oidc.Service
	cfg      config.Config
	logger   *slog.Logger
	build    version.Info
	options  Options
}

func New(cfg config.Config, logger *slog.Logger, build version.Info, options Options) (*App, error) {
	store := options.Store
	if store == nil {
		var err error
		store, err = identity.NewFileStore(cfg.Storage.DataDir)
		if err != nil {
			return nil, err
		}
	}
	auth, err := identity.NewService(store, cfg.Auth.SessionTTL)
	if err != nil {
		return nil, err
	}
	app := &App{cfg: cfg, logger: logger, build: build, options: options, identity: auth}
	if cfg.OIDC.Enabled {
		keys, err := oidc.NewFileKeyStore(filepath.Join(cfg.Storage.DataDir, "signing-keys"))
		if err != nil {
			return nil, fmt.Errorf("prepare signing key directory: %w", err)
		}
		// Load never generates a key: with OIDC enabled, startup must fail
		// closed on missing/invalid/expired signing material rather than run
		// with an ephemeral key. Run `init` or `keys rotate` to fix this.
		if _, err := keys.Load(context.Background()); err != nil {
			return nil, fmt.Errorf("load signing keys: %w", err)
		}
		app.oidc = oidc.New(auth, store, keys, oidc.Config{
			RegistrationEnabled:   cfg.OIDC.RegistrationEnabled,
			RegistrationAllowHTTP: cfg.App.Env == "development" || cfg.App.Env == "test",
			Issuer:                cfg.OIDC.Issuer,
			AllowedOrigins:        cfg.OIDC.AllowedOrigins,
			TransactionTTL:        cfg.OIDC.TransactionTTL,
			CodeTTL:               cfg.OIDC.CodeTTL,
			AccessTokenTTL:        cfg.OIDC.AccessTokenTTL,
			IDTokenTTL:            cfg.OIDC.IDTokenTTL,
			CookieSecure:          cfg.Auth.CookieSecure,
		})
	}
	return app, nil
}

func (a *App) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(securityHeaders)
	if a.cfg.Auth.CookieSecure {
		r.Use(func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Strict-Transport-Security", "max-age=31536000")
				next.ServeHTTP(w, r)
			})
		})
	}
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Heartbeat("/livez"))
	r.Use(requestLogger(a.logger))

	r.Mount("/api", api.NewRouter(a.cfg, a.logger, a.build, a.identity, a.oidc))

	// Protocol routes are registered directly on the top-level router (not a
	// wildcard sub-mount) so they take priority over the SPA/dev-proxy
	// catch-all below, in both hosting modes, without shadowing unrelated
	// paths. They deliberately sit outside /api's JSON/CSRF middleware.
	// Reserve protocol paths even for wrong methods, disabled OIDC, or trailing
	// segments so an OAuth request can never fall through to SPA HTML.
	for endpoint, methods := range map[string]string{"/.well-known/openid-configuration": "GET", "/jwks": "GET", "/authorize": "GET, POST", "/token": "POST, OPTIONS", "/userinfo": "GET, POST, OPTIONS", "/register": "POST, OPTIONS", "/register/{clientID}": "GET, OPTIONS"} {
		r.Handle(endpoint, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			if a.oidc == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"Endpoint is disabled."}`))
				return
			}
			w.Header().Set("Allow", methods)
			w.WriteHeader(http.StatusMethodNotAllowed)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"Unsupported HTTP method."}`))
		}))
		r.Handle(endpoint+"/*", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"Unknown protocol endpoint."}`))
		}))
	}
	if a.oidc != nil {
		r.Get("/.well-known/openid-configuration", a.oidc.DiscoveryHandler)
		r.Get("/jwks", a.oidc.JWKSHandler)
		r.Get("/authorize", a.oidc.AuthorizeHandler)
		r.Post("/authorize", a.oidc.AuthorizeHandler)
		r.Post("/token", a.oidc.WithCORS(a.oidc.TokenHandler))
		r.Get("/userinfo", a.oidc.WithCORS(a.oidc.UserInfoHandler))
		r.Post("/userinfo", a.oidc.WithCORS(a.oidc.UserInfoHandler))
		r.Post("/register", a.oidc.WithCORS(a.oidc.RegistrationHandler))
		r.Get("/register/{clientID}", a.oidc.WithCORS(a.oidc.RegistrationReadHandler))
		r.Options("/register", a.oidc.CORSPreflight)
		r.Options("/register/{clientID}", a.oidc.CORSPreflight)
		r.Options("/token", a.oidc.CORSPreflight)
		r.Options("/userinfo", a.oidc.CORSPreflight)
	}

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

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
