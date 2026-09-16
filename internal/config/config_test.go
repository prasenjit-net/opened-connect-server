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

func TestOIDCIssuerDefaultsToAppURL(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	v.Set("oidc.enabled", true)
	v.Set("app.url", "http://localhost:8080")
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Issuer != "http://localhost:8080" {
		t.Fatalf("expected issuer to default to app.url, got %q", cfg.OIDC.Issuer)
	}
}

func TestOIDCRejectsPathPrefixedIssuer(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	v.Set("oidc.enabled", true)
	v.Set("oidc.issuer", "https://identity.example.com/issuer")
	if _, err := Load(v); err == nil {
		t.Fatal("path-prefixed issuer accepted")
	}
}

func TestOIDCRequiresHTTPSOutsideDevelopment(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	v.Set("app.env", "production")
	v.Set("app.url", "https://identity.example.com")
	v.Set("oidc.enabled", true)
	v.Set("oidc.issuer", "http://identity.example.com")
	if _, err := Load(v); err == nil {
		t.Fatal("HTTP issuer accepted outside development")
	}
}

func TestOIDCRejectsNonPositiveTTLs(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	v.Set("oidc.enabled", true)
	v.Set("oidc.codeTTL", "0s")
	if _, err := Load(v); err == nil {
		t.Fatal("non-positive code TTL accepted")
	}
}

func TestOIDCDisabledSkipsIssuerValidation(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	// oidc.enabled defaults to false and oidc.issuer is empty; this must not
	// fail even though an empty issuer would otherwise be invalid.
	if _, err := Load(v); err != nil {
		t.Fatalf("disabled OIDC config should not require an issuer: %v", err)
	}
}
