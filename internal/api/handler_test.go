package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/your-org/go-app-template/internal/config"
	"github.com/your-org/go-app-template/internal/version"
)

func TestHealthEndpoint(t *testing.T) {
	router := NewRouter(config.Default(), slog.New(slog.NewTextHandler(io.Discard, nil)), version.Current())
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
