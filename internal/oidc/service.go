package oidc

import (
	"strings"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

// Config carries the resolved, validated OIDC settings a Service needs at
// runtime. It mirrors config.OIDCConfig but lives here so this package
// doesn't depend on internal/config for its core logic.
type Config struct {
	PasswordGrantEnabled  bool
	RefreshTokensEnabled  bool
	Resources             []identity.Resource
	RefreshMaxTTL         time.Duration
	RefreshInactivityTTL  time.Duration
	RegistrationEnabled   bool
	RegistrationAllowHTTP bool
	AllowedOrigins        []string
	Issuer                string
	TransactionTTL        time.Duration
	CodeTTL               time.Duration
	AccessTokenTTL        time.Duration
	IDTokenTTL            time.Duration
	// CookieSecure mirrors config.AuthConfig.CookieSecure: whether the
	// authorization-binding cookie must carry the Secure attribute.
	CookieSecure bool
}

// Service holds everything the protocol HTTP handlers need: the identity
// service (for principal/session/client lookups), the raw store (for OIDC
// record transactions, sharing identity.Store's atomicity boundary), the
// signing key store, and resolved configuration.
type Service struct {
	Identity *identity.Service
	Store    identity.Store
	Keys     *KeyStore
	Config   Config
	Now      func() time.Time

	clientAuthLimiter *clientAuthLimiter
	trafficLimiter    *clientAuthLimiter
	passwordLimiter   *clientAuthLimiter
	passwordSlots     chan struct{}
}

func New(idService *identity.Service, store identity.Store, keys *KeyStore, cfg Config) *Service {
	cfg.Issuer = strings.TrimSuffix(cfg.Issuer, "/")
	return &Service{Identity: idService, Store: store, Keys: keys, Config: cfg, Now: time.Now, clientAuthLimiter: newClientAuthLimiter(), trafficLimiter: newClientAuthLimiter(), passwordLimiter: newClientAuthLimiter(), passwordSlots: make(chan struct{}, 4)}
}
