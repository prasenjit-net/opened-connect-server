package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/spf13/viper"
)

type Config struct {
	App     AppConfig     `mapstructure:"app" yaml:"app"`
	Server  ServerConfig  `mapstructure:"server" yaml:"server"`
	Logging LoggingConfig `mapstructure:"logging" yaml:"logging"`
	UI      UIConfig      `mapstructure:"ui" yaml:"ui"`
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
	DevProxyURL string `mapstructure:"devProxyURL" yaml:"devProxyURL"`
}

func Default() Config {
	return Config{
		App: AppConfig{
			Name:        "Go App Template",
			Env:         "development",
			URL:         "http://localhost:8080",
			Description: "Full-stack starter with an embedded React frontend.",
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
			DevProxyURL: "http://localhost:5173",
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
}

func Load(v *viper.Viper) (Config, error) {
	cfg := Default()
	if err := v.Unmarshal(&cfg, viper.DecodeHook(mapstructure.StringToTimeDurationHookFunc())); err != nil {
		return Config{}, fmt.Errorf("decode config: %w", err)
	}

	return cfg, nil
}

func InitProject(dir string, force bool) error {
	if err := os.MkdirAll(filepath.Join(dir, "data"), 0o755); err != nil {
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
  name: Go App Template
  env: development
  url: http://localhost:8080
  description: Full-stack starter with Go at the repo root and an embedded React UI.

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

ui:
  devProxyURL: http://localhost:5173
`

const DefaultEnvExample = `APP_ENV=development
APP_APP_NAME=Go App Template
APP_SERVER_HOST=0.0.0.0
APP_SERVER_PORT=8080
APP_LOGGING_LEVEL=debug
APP_LOGGING_FORMAT=text
APP_UI_DEV_PROXY_URL=http://localhost:5173
`
