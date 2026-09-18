// Package capability is the single source of truth for what this OpenID
// Provider implementation actually supports. Discovery, runtime request
// validation, and management-screen compatibility messages all read from
// these values instead of maintaining independent allowlists.
package capability

import "slices"

var (
	SupportedScopes        = []string{"openid", "profile", "email", "address", "phone"}
	SupportedResponseTypes = []string{"code"}
	SupportedGrantTypes    = []string{"authorization_code", "client_credentials", "refresh_token", "password"}
	SupportedAuthMethods   = []string{"client_secret_basic", "client_secret_post", "none"}
	SupportedSubjectTypes  = []string{"public"}
	SupportedSigningAlgs   = []string{"RS256"}
	SupportedPKCEMethods   = []string{"S256"}
)

// ClientProfile is the subset of a registered client's metadata that
// determines whether it can use the currently implemented protocol surface.
type ClientProfile struct {
	ResponseTypes            []string
	GrantTypes               []string
	TokenEndpointAuthMethod  string
	SubjectType              string // "" is treated as "public"
	RequestsEncryption       bool
	IDTokenSignedResponseAlg string // "" is treated as the RS256 default
}

// Audit reports whether a client's registered metadata is compatible with
// the implemented protocol capabilities, and if not, why. It never adjusts
// or downgrades the profile; callers must reject or flag incompatible
// clients rather than silently falling back to different security settings.
func Audit(p ClientProfile) (compatible bool, reasons []string) {
	for _, rt := range p.ResponseTypes {
		if !slices.Contains(SupportedResponseTypes, rt) {
			reasons = append(reasons, "response type \""+rt+"\" is not supported; only \"code\" is implemented")
		}
	}
	for _, gt := range p.GrantTypes {
		if !slices.Contains(SupportedGrantTypes, gt) {
			reasons = append(reasons, "grant type \""+gt+"\" is not supported")
		}
	}
	if method := p.TokenEndpointAuthMethod; method != "" && !slices.Contains(SupportedAuthMethods, method) {
		switch method {
		case "private_key_jwt", "client_secret_jwt":
			reasons = append(reasons, "token endpoint authentication method \""+method+"\" is not yet implemented")
		default:
			reasons = append(reasons, "token endpoint authentication method \""+method+"\" is not supported")
		}
	}
	if subject := p.SubjectType; subject != "" && subject != "public" {
		reasons = append(reasons, "pairwise subject identifiers are not yet implemented; this client requires public subjects")
	}
	if p.RequestsEncryption {
		reasons = append(reasons, "ID token and UserInfo encryption are not yet implemented")
	}
	if alg := p.IDTokenSignedResponseAlg; alg != "" && !slices.Contains(SupportedSigningAlgs, alg) {
		reasons = append(reasons, "ID token signing algorithm \""+alg+"\" is not supported; only RS256 is implemented")
	}
	return len(reasons) == 0, reasons
}
