package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/prasenjit-net/openid-connect-server/internal/config"
	"github.com/prasenjit-net/openid-connect-server/internal/oidc"
	"github.com/prasenjit-net/openid-connect-server/internal/version"
)

func TestSPARefreshPreservesRoute(t *testing.T) {
	const index = "<!doctype html><html><body>App</body></html>"
	cfg := config.Default()
	cfg.Storage.DataDir = t.TempDir()
	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), Options{
		UIFS: fstest.MapFS{
			"ui/dist/index.html":    {Data: []byte(index)},
			"ui/dist/assets/app.js": {Data: []byte("console.log('app')")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	for _, target := range []string{"/", "/dashboard", "/settings", "/examples?view=raw", "/settings/", "/nested/route?tab=details"} {
		t.Run(target, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, target, nil)
			originalURL := req.URL.String()
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			if res.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d (Location: %q)", res.Code, res.Header().Get("Location"))
			}
			if location := res.Header().Get("Location"); location != "" {
				t.Fatalf("unexpected redirect to %q", location)
			}
			if res.Body.String() != index {
				t.Fatalf("expected SPA HTML, got %q", res.Body.String())
			}
			if req.URL.String() != originalURL {
				t.Fatalf("request URL changed from %q to %q", originalURL, req.URL.String())
			}
		})
	}
	t.Run("static assets", func(t *testing.T) {
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/assets/app.js", nil))
		if res.Code != http.StatusOK || res.Body.String() != "console.log('app')" {
			t.Fatalf("unexpected asset response: %d %q", res.Code, res.Body.String())
		}
	})
	t.Run("API routes do not fall back to SPA", func(t *testing.T) {
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/api/missing", nil))
		if res.Code != http.StatusNotFound {
			t.Fatalf("expected 404, got %d", res.Code)
		}
	})
}

func provisionedOIDCConfig(t *testing.T) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.DataDir = t.TempDir()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "http://localhost:8080"
	keys, err := oidc.NewFileKeyStore(filepath.Join(cfg.Storage.DataDir, "signing-keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Provision(context.Background()); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestOIDCRoutesTakePriorityOverEmbeddedSPA(t *testing.T) {
	const index = "<!doctype html><html><body>App</body></html>"
	cfg := provisionedOIDCConfig(t)
	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), Options{
		UIFS: fstest.MapFS{"ui/dist/index.html": {Data: []byte(index)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	for _, target := range []string{"/.well-known/openid-configuration", "/jwks"} {
		t.Run(target, func(t *testing.T) {
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, target, nil))
			if res.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", res.Code)
			}
			if res.Body.String() == index {
				t.Fatal("protocol route fell through to the SPA")
			}
			var payload map[string]any
			if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
				t.Fatalf("expected JSON response: %v", err)
			}
		})
	}
}

func TestOIDCRoutesTakePriorityOverDevProxy(t *testing.T) {
	cfg := provisionedOIDCConfig(t)
	cfg.UI.DevProxyURL = "http://127.0.0.1:1" // deliberately unreachable
	app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), Options{DevMode: true})
	if err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	for _, target := range []string{"/.well-known/openid-configuration", "/jwks"} {
		t.Run(target, func(t *testing.T) {
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, httptest.NewRequest(http.MethodGet, target, nil))
			// A 502 here would mean the request reached the (unreachable) dev
			// proxy instead of being handled as a protocol route.
			if res.Code != http.StatusOK {
				t.Fatalf("expected 200 (protocol route handled before the dev proxy), got %d", res.Code)
			}
		})
	}
}

func TestServerFailsClosedWithoutSigningKeys(t *testing.T) {
	cfg := config.Default()
	cfg.Storage.DataDir = t.TempDir()
	cfg.OIDC.Enabled = true
	cfg.OIDC.Issuer = "http://localhost:8080"
	// Deliberately skip provisioning: no signing-keys directory exists.
	if _, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), Options{}); err == nil {
		t.Fatal("expected server startup to fail closed without provisioned signing keys")
	}
}

func TestSPAInitialTheme(t *testing.T) {
	files := fstest.MapFS{"index.html": {Data: []byte(`<meta name="default-theme" content="__DEFAULT_THEME__">`)}}
	for _, theme := range []string{"light", "dark", "auto"} {
		for _, route := range []string{"/", "/settings", "/nested/missing", "/index.html"} {
			t.Run(theme+route, func(t *testing.T) {
				res := httptest.NewRecorder()
				newSPAHandler(files, theme).ServeHTTP(res, httptest.NewRequest(http.MethodGet, route, nil))
				if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), `content="`+theme+`"`) {
					t.Fatalf("theme missing on SPA route: %d %s", res.Code, res.Body.String())
				}
				if res.Header().Get("Location") != "" {
					t.Fatal("SPA route redirected")
				}
			})
		}
	}
}

func TestProtocolErrorsNeverFallThroughToSPA(t *testing.T) {
	cfg := provisionedOIDCConfig(t)
	for _, dev := range []bool{false, true} {
		cfg.UI.DevProxyURL = "http://127.0.0.1:1"
		app, err := New(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), Options{DevMode: dev, UIFS: fstest.MapFS{"ui/dist/index.html": {Data: []byte("SPA")}}})
		if err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			method, path string
			status       int
		}{
			{"GET", "/token", 405}, {"DELETE", "/authorize", 405}, {"POST", "/jwks", 405}, {"PUT", "/userinfo", 405}, {"GET", "/token/", 404}, {"GET", "/authorize/missing", 404}, {"GET", "/userinfo/missing", 404},
		} {
			w := httptest.NewRecorder()
			app.Handler().ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.status || !strings.Contains(w.Header().Get("Content-Type"), "application/json") {
				t.Errorf("dev=%v %s %s: %d %s", dev, tc.method, tc.path, w.Code, w.Body.String())
			}
		}
	}
}
