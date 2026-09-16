package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type Config struct {
	Storage StorageConfig `mapstructure:"storage" yaml:"storage"`
	Auth    AuthConfig    `mapstructure:"auth" yaml:"auth"`
	App     AppConfig     `mapstructure:"app" yaml:"app"`
	Server  ServerConfig  `mapstructure:"server" yaml:"server"`
	Logging LoggingConfig `mapstructure:"logging" yaml:"logging"`
	UI      UIConfig      `mapstructure:"ui" yaml:"ui"`
	OIDC    OIDCConfig    `mapstructure:"oidc" yaml:"oidc"`
}

type StorageConfig struct {
	DataDir string `mapstructure:"dataDir" yaml:"dataDir"`
}
type AuthConfig struct {
	SessionTTL   time.Duration `mapstructure:"sessionTTL" yaml:"sessionTTL"`
	CookieSecure bool          `mapstructure:"cookieSecure" yaml:"cookieSecure"`
}

type AppConfig struct {
	Name        string `mapstructure:"name" yaml:"name"`
	Env         string `mapstructure:"env" yaml:"env"`
	URL         string `mapstructure:"url" yaml:"url"`
	Description string `mapstructure:"description" yaml:"description"`
}

type ServerConfig struct {
	Host            string        `mapstructure:"host" yaml:"host"`
	Port            int           `mapstructure:"port" yaml:"port"`
	ReadTimeout     time.Duration `mapstructure:"readTimeout" yaml:"readTimeout"`
	WriteTimeout    time.Duration `mapstructure:"writeTimeout" yaml:"writeTimeout"`
	IdleTimeout     time.Duration `mapstructure:"idleTimeout" yaml:"idleTimeout"`
	ShutdownTimeout time.Duration `mapstructure:"shutdownTimeout" yaml:"shutdownTimeout"`
}

type LoggingConfig struct {
	Level  string `mapstructure:"level" yaml:"level"`
	Format string `mapstructure:"format" yaml:"format"`
}

type UIConfig struct {
	DefaultTheme string `mapstructure:"defaultTheme" yaml:"defaultTheme"`
	RepoURL      string `mapstructure:"repoURL" yaml:"repoURL"`
	DevProxyURL  string `mapstructure:"devProxyURL" yaml:"devProxyURL"`
}

// OIDCConfig configures the OpenID Connect provider surface (discovery,
// JWKS, /authorize, /token, /userinfo). RefreshMaxTTL and
// RefreshInactivityTTL are reserved for the future refresh-token milestone
// and are not yet enforced.
type OIDCConfig struct {
	AllowedOrigins       []string      `mapstructure:"allowedOrigins" yaml:"allowedOrigins"`
	Enabled              bool          `mapstructure:"enabled" yaml:"enabled"`
	Issuer               string        `mapstructure:"issuer" yaml:"issuer"`
	TransactionTTL       time.Duration `mapstructure:"transactionTTL" yaml:"transactionTTL"`
	CodeTTL              time.Duration `mapstructure:"codeTTL" yaml:"codeTTL"`
	AccessTokenTTL       time.Duration `mapstructure:"accessTokenTTL" yaml:"accessTokenTTL"`
	IDTokenTTL           time.Duration `mapstructure:"idTokenTTL" yaml:"idTokenTTL"`
	RefreshMaxTTL        time.Duration `mapstructure:"refreshMaxTTL" yaml:"refreshMaxTTL"`
	RefreshInactivityTTL time.Duration `mapstructure:"refreshInactivityTTL" yaml:"refreshInactivityTTL"`
	KeyRotationInterval  time.Duration `mapstructure:"keyRotationInterval" yaml:"keyRotationInterval"`
	KeyOverlapPeriod     time.Duration `mapstructure:"keyOverlapPeriod" yaml:"keyOverlapPeriod"`
}

func Default() Config {
	return Config{
		Storage: StorageConfig{DataDir: "data"},
		Auth:    AuthConfig{SessionTTL: 8 * time.Hour},
		App: AppConfig{
			Name:        "OpenID Connect Server",
			Env:         "development",
			URL:         "http://localhost:8080",
			Description: "OpenID Connect Server API and administration console.",
		},
		Server: ServerConfig{
			Host:            "0.0.0.0",
			Port:            8080,
			ReadTimeout:     15 * time.Second,
			WriteTimeout:    15 * time.Second,
			IdleTimeout:     60 * time.Second,
			ShutdownTimeout: 10 * time.Second,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		UI: UIConfig{
			DefaultTheme: "auto",
			RepoURL:      "https://github.com/prasenjit-net/opened-connect-server",
			DevProxyURL:  "http://localhost:5173",
		},
		OIDC: OIDCConfig{
			Enabled:              false,
			TransactionTTL:       10 * time.Minute,
			CodeTTL:              60 * time.Second,
			AccessTokenTTL:       10 * time.Minute,
			IDTokenTTL:           5 * time.Minute,
			RefreshMaxTTL:        30 * 24 * time.Hour,
			RefreshInactivityTTL: 7 * 24 * time.Hour,
			KeyRotationInterval:  90 * 24 * time.Hour,
			KeyOverlapPeriod:     30 * 24 * time.Hour,
		},
	}
}

func (c Config) Address() string {
	return c.Server.Address()
}

func (s ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func SetDefaults(v *viper.Viper) {
	defaults := Default()
	v.SetDefault("storage.dataDir", defaults.Storage.DataDir)
	v.SetDefault("auth.sessionTTL", defaults.Auth.SessionTTL)
	v.SetDefault("auth.cookieSecure", defaults.Auth.CookieSecure)

	v.SetDefault("app.name", defaults.App.Name)
	v.SetDefault("app.env", defaults.App.Env)
	v.SetDefault("app.url", defaults.App.URL)
	v.SetDefault("app.description", defaults.App.Description)
	v.SetDefault("server.host", defaults.Server.Host)
	v.SetDefault("server.port", defaults.Server.Port)
	v.SetDefault("server.readTimeout", defaults.Server.ReadTimeout)
	v.SetDefault("server.writeTimeout", defaults.Server.WriteTimeout)
	v.SetDefault("server.idleTimeout", defaults.Server.IdleTimeout)
	v.SetDefault("server.shutdownTimeout", defaults.Server.ShutdownTimeout)
	v.SetDefault("logging.level", defaults.Logging.Level)
	v.SetDefault("logging.format", defaults.Logging.Format)
	v.SetDefault("ui.devProxyURL", defaults.UI.DevProxyURL)
	v.SetDefault("ui.defaultTheme", defaults.UI.DefaultTheme)
	v.SetDefault("ui.repoURL", defaults.UI.RepoURL)

	v.SetDefault("oidc.enabled", defaults.OIDC.Enabled)
	v.SetDefault("oidc.issuer", defaults.OIDC.Issuer)
	v.SetDefault("oidc.transactionTTL", defaults.OIDC.TransactionTTL)
	v.SetDefault("oidc.codeTTL", defaults.OIDC.CodeTTL)
	v.SetDefault("oidc.accessTokenTTL", defaults.OIDC.AccessTokenTTL)
	v.SetDefault("oidc.idTokenTTL", defaults.OIDC.IDTokenTTL)
	v.SetDefault("oidc.refreshMaxTTL", defaults.OIDC.RefreshMaxTTL)
	v.SetDefault("oidc.refreshInactivityTTL", defaults.OIDC.RefreshInactivityTTL)
	v.SetDefault("oidc.keyRotationInterval", defaults.OIDC.KeyRotationInterval)
	v.SetDefault("oidc.keyOverlapPeriod", defaults.OIDC.KeyOverlapPeriod)
}

func Load(v *viper.Viper) (Config, error) {
	cfg := Default()
	if err := v.Unmarshal(&cfg, viper.DecodeHook(mapstructure.StringToTimeDurationHookFunc())); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	if cfg.UI.DefaultTheme != "auto" && cfg.UI.DefaultTheme != "light" && cfg.UI.DefaultTheme != "dark" {
		return Config{}, fmt.Errorf("ui.defaultTheme must be auto, light, or dark")
	}
	if cfg.Storage.DataDir == "" {
		return Config{}, fmt.Errorf("storage.dataDir is required")
	}
	if cfg.Auth.SessionTTL < time.Minute || cfg.Auth.SessionTTL > 30*24*time.Hour {
		return Config{}, fmt.Errorf("auth.sessionTTL must be between 1m and 720h")
	}
	publicURL, err := url.Parse(cfg.App.URL)
	if err != nil || publicURL.Host == "" || (publicURL.Scheme != "http" && publicURL.Scheme != "https") {
		return Config{}, fmt.Errorf("app.url must be an absolute HTTP or HTTPS URL")
	}
	if publicURL.Scheme == "https" {
		cfg.Auth.CookieSecure = true
	}
	if cfg.App.Env != "development" && cfg.App.Env != "test" {
		if publicURL.Scheme != "https" {
			return Config{}, fmt.Errorf("app.url must use HTTPS outside development; terminate TLS at your reverse proxy")
		}
		cfg.Auth.CookieSecure = true
	}
	if cfg.OIDC.Enabled {
		if strings.TrimSpace(cfg.OIDC.Issuer) == "" {
			cfg.OIDC.Issuer = cfg.App.URL
		}
		// Never derive the issuer from a request's Host or forwarded headers;
		// it is resolved once, here, from trusted configuration only.
		issuer, err := url.Parse(cfg.OIDC.Issuer)
		if err != nil || issuer.Host == "" || (issuer.Scheme != "http" && issuer.Scheme != "https") {
			return Config{}, fmt.Errorf("oidc.issuer must be an absolute HTTP or HTTPS URL")
		}
		if issuer.User != nil || issuer.RawQuery != "" || issuer.ForceQuery || issuer.Fragment != "" || strings.Contains(cfg.OIDC.Issuer, "#") {
			return Config{}, fmt.Errorf("oidc.issuer must not contain user information, a query, or a fragment")
		}
		cfg.OIDC.Issuer = strings.TrimSuffix(cfg.OIDC.Issuer, "/")
		if issuer.RawPath != "" || (issuer.Path != "" && issuer.Path != "/") {
			return Config{}, fmt.Errorf("oidc.issuer must not have a path; path-prefixed issuers are not yet supported")
		}
		if cfg.App.Env != "development" && cfg.App.Env != "test" && issuer.Scheme != "https" {
			return Config{}, fmt.Errorf("oidc.issuer must use HTTPS outside development")
		}
		for _, origin := range cfg.OIDC.AllowedOrigins {
			parsed, err := url.Parse(origin)
			if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || strings.Contains(origin, "#") {
				return Config{}, fmt.Errorf("oidc.allowedOrigins must contain exact HTTP(S) origins without paths, user information, query, or fragment")
			}
			if cfg.App.Env != "development" && cfg.App.Env != "test" && parsed.Scheme != "https" {
				return Config{}, fmt.Errorf("oidc.allowedOrigins must use HTTPS outside development")
			}
		}
		for name, d := range map[string]time.Duration{
			"oidc.transactionTTL": cfg.OIDC.TransactionTTL,
			"oidc.codeTTL":        cfg.OIDC.CodeTTL,
			"oidc.accessTokenTTL": cfg.OIDC.AccessTokenTTL,
			"oidc.idTokenTTL":     cfg.OIDC.IDTokenTTL,
		} {
			if d <= 0 {
				return Config{}, fmt.Errorf("%s must be positive", name)
			}
		}
	}
	return cfg, nil
}

func InitProject(dir string, force bool) error {
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}

	files := map[string]string{
		filepath.Join(dir, "config.yaml"):  DefaultConfigYAML,
		filepath.Join(dir, ".env.example"): DefaultEnvExample,
		filepath.Join(dir, ".env"):         DefaultEnvExample,
	}

	for path, contents := range files {
		if !force {
			if _, err := os.Stat(path); err == nil {
				continue
			}
		}
		if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
	}

	keepFile := filepath.Join(dir, "data", ".gitkeep")
	if force || !fileExists(keepFile) {
		if err := os.WriteFile(keepFile, []byte{}, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", keepFile, err)
		}
	}

	return nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

const DefaultConfigYAML = `app:
  name: OpenID Connect Server
  env: development
  url: http://localhost:8080
  description: OpenID Connect Server API and administration console.

server:
  host: 0.0.0.0
  port: 8080
  readTimeout: 15s
  writeTimeout: 15s
  idleTimeout: 60s
  shutdownTimeout: 10s

logging:
  level: info
  format: text

storage:
  dataDir: data

auth:
  sessionTTL: 8h
  cookieSecure: false # development HTTP only; HTTPS enables Secure automatically

ui:
  defaultTheme: auto
  repoURL: https://github.com/prasenjit-net/opened-connect-server
  devProxyURL: http://localhost:5173

# oidc:
#   enabled: false
#   issuer: https://identity.example.com # defaults to app.url when unset
#   allowedOrigins: [] # exact browser client origins, e.g. [https://app.example.com]
#   transactionTTL: 10m
#   codeTTL: 60s
#   accessTokenTTL: 10m
#   idTokenTTL: 5m
#   keyRotationInterval: 2160h # 90 days
#   keyOverlapPeriod: 720h # 30 days
`

const DefaultEnvExample = `APP_APP_ENV=development
APP_APP_NAME=OpenID Connect Server
APP_SERVER_HOST=0.0.0.0
APP_SERVER_PORT=8080
APP_LOGGING_LEVEL=debug
APP_LOGGING_FORMAT=text
APP_UI_DEV_PROXY_URL=http://localhost:5173
`
