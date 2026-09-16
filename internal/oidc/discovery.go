package oidc

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/prasenjit-net/opened-connect-server/internal/oidc/capability"
)

// discoveryDocument is the subset of OpenID Connect Discovery 1.0 metadata
// this provider actually implements. Fields the provider does not support
// are omitted rather than published as false, except where the
// specification expects an explicit false to avoid implying an unsupported
// default (request_parameter_supported, request_uri_parameter_supported,
// require_request_uri_registration, claims_parameter_supported).
type discoveryDocument struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	RequestParameterSupported         bool     `json:"request_parameter_supported"`
	RequestURIParameterSupported      bool     `json:"request_uri_parameter_supported"`
	RequireRequestURIRegistration     bool     `json:"require_request_uri_registration"`
	ClaimsParameterSupported          bool     `json:"claims_parameter_supported"`
}

var supportedClaims = []string{
	"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
	"name", "given_name", "family_name", "middle_name", "nickname", "preferred_username",
	"profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at",
	"email", "email_verified",
	"address",
	"phone_number", "phone_number_verified",
}

func (s *Service) discoveryDocument() discoveryDocument {
	issuer := strings.TrimSuffix(s.Config.Issuer, "/")
	return discoveryDocument{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + "/authorize",
		TokenEndpoint:                     issuer + "/token",
		UserinfoEndpoint:                  issuer + "/userinfo",
		JWKSURI:                           issuer + "/jwks",
		ResponseTypesSupported:            capability.SupportedResponseTypes,
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               capability.SupportedGrantTypes,
		SubjectTypesSupported:             capability.SupportedSubjectTypes,
		IDTokenSigningAlgValuesSupported:  capability.SupportedSigningAlgs,
		TokenEndpointAuthMethodsSupported: capability.SupportedAuthMethods,
		ScopesSupported:                   capability.SupportedScopes,
		ClaimsSupported:                   supportedClaims,
		CodeChallengeMethodsSupported:     capability.SupportedPKCEMethods,
		RequestParameterSupported:         false,
		RequestURIParameterSupported:      false,
		RequireRequestURIRegistration:     false,
		ClaimsParameterSupported:          false,
	}
}

// DiscoveryHandler serves /.well-known/openid-configuration. It is public,
// non-credentialed information, so a noncredentialed cross-origin read is
// safe to allow.
func (s *Service) DiscoveryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.discoveryDocument())
}

// JWKSHandler serves /jwks: public signing key parameters only. Like
// discovery, this is public and non-credentialed, so cross-origin reads are
// safe to allow; cache lifetime is short enough to permit rotation.
func (s *Service) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.Keys.PublicJWKS())
}
