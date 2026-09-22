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

func TestOIDCIssuerNormalizationAndForbiddenComponents(t *testing.T) {
	for _, issuer := range []string{"https://user@identity.example.com", "https://identity.example.com?x=1", "https://identity.example.com?", "https://identity.example.com/%2f", "https://identity.example.com/%2F", "https://identity.example.com#fragment", "https://identity.example.com#"} {
		v := viper.New()
		SetDefaults(v)
		v.Set("oidc.enabled", true)
		v.Set("oidc.issuer", issuer)
		if _, err := Load(v); err == nil {
			t.Errorf("invalid issuer accepted: %s", issuer)
		}
	}
	v := viper.New()
	SetDefaults(v)
	v.Set("oidc.enabled", true)
	v.Set("oidc.issuer", "https://identity.example.com/")
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.OIDC.Issuer != "https://identity.example.com" {
		t.Fatalf("issuer not normalized: %s", cfg.OIDC.Issuer)
	}
}
func TestOIDCAllowedOriginsValidation(t *testing.T) {
	for _, origin := range []string{"*", "null", "https://rp.example.com/", "https://rp.example.com/path", "https://user@rp.example.com", "https://rp.example.com?x=1", "https://rp.example.com#"} {
		v := viper.New()
		SetDefaults(v)
		v.Set("oidc.enabled", true)
		v.Set("oidc.allowedOrigins", []string{origin})
		if _, err := Load(v); err == nil {
			t.Errorf("invalid origin accepted: %s", origin)
		}
	}
	v := viper.New()
	SetDefaults(v)
	v.Set("oidc.enabled", true)
	v.Set("oidc.allowedOrigins", []string{"https://rp.example.com"})
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.OIDC.AllowedOrigins) != 1 {
		t.Fatal("allowed origins not loaded")
	}
}

func TestDynamicRegistrationConfiguration(t *testing.T) {
	v := viper.New()
	SetDefaults(v)
	cfg, err := Load(v)
	if err != nil || cfg.OIDC.RegistrationEnabled {
		t.Fatal("registration should default to disabled")
	}
	v.Set("oidc.registrationEnabled", true)
	if _, err = Load(v); err == nil {
		t.Fatal("registration enabled without provider")
	}
	v.Set("oidc.enabled", true)
	if _, err = Load(v); err != nil {
		t.Fatal("loopback development registration rejected", err)
	}
	v.Set("oidc.issuer", "http://insecure.example.com")
	if _, err = Load(v); err == nil {
		t.Fatal("insecure non-loopback registration accepted")
	}
	v.Set("oidc.issuer", "https://issuer.example.com")
	cfg, err = Load(v)
	if err != nil || !cfg.OIDC.RegistrationEnabled {
		t.Fatal("HTTPS registration rejected", err)
	}
}

func TestOAuthConfigurationValidation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		key   string
		value any
	}{
		{"HTTP audience", "oauth.resources", []map[string]any{{"audience": "http://api.example", "scopes": []string{"read"}, "enabled": true}}},
		{"OIDC scope", "oauth.resources", []map[string]any{{"audience": "https://api.example", "scopes": []string{"openid"}, "enabled": true}}},
		{"oversized idle", "oidc.refreshInactivityTTL", "800h"},
		{"zero maximum", "oidc.refreshMaxTTL", "0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			SetDefaults(v)
			v.Set("oidc.enabled", true)
			v.Set(tc.key, tc.value)
			if _, err := Load(v); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
	v := viper.New()
	SetDefaults(v)
	v.Set("oauth.refreshTokensEnabled", true)
	if _, err := Load(v); err == nil {
		t.Fatal("refresh enabled without protocol")
	}
	v.Set("oidc.enabled", true)
	v.Set("oauth.resources", []map[string]any{{"audience": "https://api.example", "scopes": []string{"read"}, "enabled": true}})
	cfg, err := Load(v)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.OAuth.Resources) != 1 || !cfg.OAuth.RefreshTokensEnabled || cfg.OAuth.PasswordGrantEnabled {
		t.Fatal("incorrect defaults or decoding")
	}
}

func TestStorageBackendConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*viper.Viper)
		ok   bool
	}{
		{"json default", func(v *viper.Viper) {}, true},
		{"unknown", func(v *viper.Viper) { v.Set("storage.backend", "sqlite") }, false},
		{"postgres missing dsn", func(v *viper.Viper) { v.Set("storage.backend", "postgres") }, false},
		{"postgres valid", func(v *viper.Viper) {
			v.Set("storage.backend", "postgres")
			v.Set("storage.postgres.dsn", "postgres://user:secret@db.example/opened")
		}, true},
		{"mongo missing uri", func(v *viper.Viper) { v.Set("storage.backend", "mongodb") }, false},
		{"mongo valid", func(v *viper.Viper) {
			v.Set("storage.backend", "mongodb")
			v.Set("storage.mongodb.uri", "mongodb://user:secret@db.example/?replicaSet=rs0")
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			SetDefaults(v)
			tc.set(v)
			_, err := Load(v)
			if (err == nil) != tc.ok {
				t.Fatalf("Load error=%v, expected success=%t", err, tc.ok)
			}
		})
	}
}
