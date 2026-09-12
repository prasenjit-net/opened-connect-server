package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"github.com/prasenjit-net/opened-connect-server/internal/version"
)

func TestHealthEndpoint(t *testing.T) {
	router := NewRouter(config.Default(), slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), testIdentity(t))
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	res := httptest.NewRecorder()

	router.ServeHTTP(res, req)

	if res.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", res.Code)
	}
	if !strings.Contains(res.Body.String(), `"status":"ok"`) {
		t.Fatalf("expected ok payload, got %s", res.Body.String())
	}
}

func TestConfigEndpoint(t *testing.T) {
	cfg := config.Default()
	cfg.App.Name = "Test Server"
	cfg.UI.DefaultTheme = "dark"
	before := time.Now().UnixMilli()
	router := NewRouter(cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), version.Info{Version: "1.2.3"}, testIdentity(t))
	res := httptest.NewRecorder()
	router.ServeHTTP(res, httptest.NewRequest(http.MethodGet, "/config", nil))
	var payload configResponse
	if err := json.Unmarshal(res.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if res.Code != http.StatusOK || payload.UI.AppName != cfg.App.Name || payload.UI.DefaultTheme != "dark" || payload.Version != "1.2.3" {
		t.Fatalf("unexpected config response: %d %s", res.Code, res.Body.String())
	}
	if payload.StartedAtMS < before || payload.StartedAtMS > time.Now().UnixMilli() {
		t.Fatal("invalid start time")
	}
	if payload.UI.RepoURL != cfg.UI.RepoURL || payload.UI.Tagline != cfg.App.Description {
		t.Fatal("branding configuration was not preserved")
	}
}

func TestRemovedAndUnknownEndpoints(t *testing.T) {
	router := NewRouter(config.Default(), slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current(), testIdentity(t))
	for _, path := range []string{"/", "/example", "/meta", "/certificates", "/tasks", "/missing"} {
		t.Run(path, func(t *testing.T) {
			res := httptest.NewRecorder()
			router.ServeHTTP(res, httptest.NewRequest(http.MethodGet, path, nil))
			if res.Code != http.StatusNotFound || !strings.Contains(res.Body.String(), `"code":"NOT_FOUND"`) {
				t.Fatalf("expected JSON 404, got %d %s", res.Code, res.Body.String())
			}
		})
	}
}

func testIdentity(t *testing.T) *identity.Service {
	t.Helper()
	store, err := identity.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(store, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return service
}
