package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/version"
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
