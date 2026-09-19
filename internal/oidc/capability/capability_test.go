package capability

import "testing"

func defaultProfile() ClientProfile {
	// Mirrors internal/identity/client_metadata.go's normalizeClientMetadata
	// defaults: response_types=[code], grant_types=[authorization_code],
	// token_endpoint_auth_method=client_secret_basic, id_token_signed_response_alg=RS256.
	return ClientProfile{
		ResponseTypes:           []string{"code"},
		GrantTypes:              []string{"authorization_code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
}

func TestAuditDefaultsAreCompatible(t *testing.T) {
	ok, reasons := Audit(defaultProfile())
	if !ok || len(reasons) != 0 {
		t.Fatalf("expected default profile to be compatible, got reasons=%v", reasons)
	}
}

func TestAuditEmptyProfileIsCompatible(t *testing.T) {
	// An entirely zero-value profile (nothing set) must not be flagged; it
	// represents fields the caller didn't populate, not fields the client
	// requested unsupported values for.
	ok, reasons := Audit(ClientProfile{})
	if !ok || len(reasons) != 0 {
		t.Fatalf("expected empty profile to be compatible, got reasons=%v", reasons)
	}
}

func TestAuditRejectsUnsupportedResponseType(t *testing.T) {
	p := defaultProfile()
	p.ResponseTypes = []string{"id_token"}
	ok, reasons := Audit(p)
	if ok || len(reasons) == 0 {
		t.Fatalf("expected id_token response type to be rejected")
	}
}

func TestAuditRejectsUnsupportedGrantType(t *testing.T) {
	p := defaultProfile()
	p.GrantTypes = []string{"implicit"}
	ok, reasons := Audit(p)
	if ok || len(reasons) == 0 {
		t.Fatalf("expected implicit grant type to be rejected")
	}
}

func TestAuditRejectsPrivateKeyJWT(t *testing.T) {
	p := defaultProfile()
	p.TokenEndpointAuthMethod = "private_key_jwt"
	ok, reasons := Audit(p)
	if ok || len(reasons) == 0 {
		t.Fatalf("expected private_key_jwt to be rejected")
	}
}

func TestAuditRejectsClientSecretJWT(t *testing.T) {
	p := defaultProfile()
	p.TokenEndpointAuthMethod = "client_secret_jwt"
	ok, reasons := Audit(p)
	if ok || len(reasons) == 0 {
		t.Fatalf("expected client_secret_jwt to be rejected")
	}
}

func TestAuditAcceptsPublicClientAuthMethod(t *testing.T) {
	p := defaultProfile()
	p.TokenEndpointAuthMethod = "none"
	ok, reasons := Audit(p)
	if !ok || len(reasons) != 0 {
		t.Fatalf("expected none auth method to be compatible, got reasons=%v", reasons)
	}
}

func TestAuditRejectsPairwiseSubject(t *testing.T) {
	p := defaultProfile()
	p.SubjectType = "pairwise"
	ok, reasons := Audit(p)
	if ok || len(reasons) == 0 {
		t.Fatalf("expected pairwise subject type to be rejected")
	}
}

func TestAuditAcceptsPublicSubject(t *testing.T) {
	p := defaultProfile()
	p.SubjectType = "public"
	ok, reasons := Audit(p)
	if !ok || len(reasons) != 0 {
		t.Fatalf("expected public subject type to be compatible, got reasons=%v", reasons)
	}
}

func TestAuditRejectsEncryption(t *testing.T) {
	p := defaultProfile()
	p.RequestsEncryption = true
	ok, reasons := Audit(p)
	if ok || len(reasons) == 0 {
		t.Fatalf("expected encryption request to be rejected")
	}
}

func TestAuditRejectsUnsupportedSigningAlg(t *testing.T) {
	p := defaultProfile()
	p.IDTokenSignedResponseAlg = "HS256"
	ok, reasons := Audit(p)
	if ok || len(reasons) == 0 {
		t.Fatalf("expected HS256 ID token signing to be rejected")
	}
}

func TestAuditAcceptsRS256(t *testing.T) {
	p := defaultProfile()
	p.IDTokenSignedResponseAlg = "RS256"
	ok, reasons := Audit(p)
	if !ok || len(reasons) != 0 {
		t.Fatalf("expected RS256 to be compatible, got reasons=%v", reasons)
	}
}

func TestAuditAccumulatesMultipleReasons(t *testing.T) {
	p := ClientProfile{
		ResponseTypes:           []string{"code id_token"},
		GrantTypes:              []string{"authorization_code", "implicit"},
		TokenEndpointAuthMethod: "private_key_jwt",
		SubjectType:             "pairwise",
		RequestsEncryption:      true,
	}
	ok, reasons := Audit(p)
	if ok {
		t.Fatalf("expected incompatible profile")
	}
	if len(reasons) < 5 {
		t.Fatalf("expected at least 5 reasons, got %d: %v", len(reasons), reasons)
	}
}
