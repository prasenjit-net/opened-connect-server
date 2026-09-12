package config

import (
	"testing"
	"time"

	"github.com/spf13/viper"
)

func TestLoadFromViper(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	v.Set("app.name", "Template")
	v.Set("server.port", 9090)
	v.Set("server.readTimeout", "30s")

	cfg, err := Load(v)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.App.Name != "Template" {
		t.Fatalf("expected app name override, got %q", cfg.App.Name)
	}
	if cfg.Server.Port != 9090 {
		t.Fatalf("expected port 9090, got %d", cfg.Server.Port)
	}
	if cfg.Server.ReadTimeout != 30*time.Second {
		t.Fatalf("expected duration decode, got %s", cfg.Server.ReadTimeout)
	}
}

func TestProductionRequiresHTTPSAndSecureCookies(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	v.Set("app.env", "production")
	if _, err := Load(v); err == nil {
		t.Fatal("production HTTP config accepted")
	}
	v.Set("app.url", "https://identity.example.com")
	v.Set("auth.cookieSecure", false)
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Auth.CookieSecure {
		t.Fatal("production cookie is not secure")
	}
	v.Set("auth.sessionTTL", "0s")
	if _, err = Load(v); err == nil {
		t.Fatal("invalid session lifetime accepted")
	}
}
