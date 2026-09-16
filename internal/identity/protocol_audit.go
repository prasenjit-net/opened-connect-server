package identity

import "github.com/prasenjit-net/opened-connect-server/internal/oidc/capability"

// auditMetadata reports whether a client's registered metadata is
// compatible with the implemented OpenID Connect protocol surface. It
// relies on ClientMetadata's unexported text()/list() helpers, so it must
// live in this package rather than internal/oidc.
func auditMetadata(m ClientMetadata) (bool, []string) {
	encrypted := false
	for _, key := range []string{"id_token_encrypted_response_alg", "userinfo_encrypted_response_alg", "request_object_encryption_alg"} {
		if m.text(key) != "" {
			encrypted = true
			break
		}
	}
	return capability.Audit(capability.ClientProfile{
		ResponseTypes:            m.list("response_types"),
		GrantTypes:               m.list("grant_types"),
		TokenEndpointAuthMethod:  m.text("token_endpoint_auth_method"),
		SubjectType:              m.text("subject_type"),
		RequestsEncryption:       encrypted,
		IDTokenSignedResponseAlg: m.text("id_token_signed_response_alg"),
	})
}
