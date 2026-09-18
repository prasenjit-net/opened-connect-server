package identity

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/mail"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

var clientStringFields = strings.Fields("client_name application_type logo_uri client_uri policy_uri tos_uri jwks_uri sector_identifier_uri subject_type id_token_signed_response_alg id_token_encrypted_response_alg id_token_encrypted_response_enc userinfo_signed_response_alg userinfo_encrypted_response_alg userinfo_encrypted_response_enc request_object_signing_alg request_object_encryption_alg request_object_encryption_enc token_endpoint_auth_method token_endpoint_auth_signing_alg initiate_login_uri")
var clientArrayFields = strings.Fields("redirect_uris response_types grant_types contacts default_acr_values request_uris")
var displayMetadata = strings.Fields("client_name logo_uri client_uri policy_uri tos_uri")
var languageTag = regexp.MustCompile(`^[A-Za-z]{2,8}(-[A-Za-z0-9]{1,8})*$`)
var signingAlgorithms = strings.Fields("RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512 EdDSA HS256 HS384 HS512 none")
var encryptionAlgorithms = strings.Fields("RSA-OAEP RSA-OAEP-256 A128KW A192KW A256KW dir ECDH-ES ECDH-ES+A128KW ECDH-ES+A192KW ECDH-ES+A256KW A128GCMKW A192GCMKW A256GCMKW PBES2-HS256+A128KW PBES2-HS384+A192KW PBES2-HS512+A256KW")
var encryptionMethods = strings.Fields("A128CBC-HS256 A192CBC-HS384 A256CBC-HS512 A128GCM A192GCM A256GCM")

// ClientMetadataError retains the offending field for protocol error mapping
// while remaining compatible with the management API's ValidationError handling.
type ClientMetadataError struct{ Field, Message string }

func (e *ClientMetadataError) Error() string { return e.Message }
func (e *ClientMetadataError) Unwrap() error { return ValidationError(e.Message) }

func normalizeClientMetadata(input ClientMetadata) (ClientMetadata, error) {
	fail := func(message string) (ClientMetadata, error) { return nil, &ClientMetadataError{Message: message} }
	failField := func(field, message string) (ClientMetadata, error) {
		return nil, &ClientMetadataError{Field: field, Message: message}
	}
	failRedirect := func(message string) (ClientMetadata, error) { return failField("redirect_uris", message) }
	if input == nil {
		return fail("Client metadata must be a JSON object.")
	}
	encoded, err := json.Marshal(input)
	if err != nil || len(encoded) > 16<<10 {
		return fail("Client metadata must fit within 16 KB.")
	}
	m := cloneClient(ClientRecord{Metadata: input}).Metadata
	for key, raw := range m {
		base, tag, localized := strings.Cut(key, "#")
		if localized && (!slices.Contains(displayMetadata, base) || !languageTag.MatchString(tag)) {
			return fail("Invalid localized metadata field: " + key)
		}
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return failField(key, key+" cannot be null.")
		}
		switch {
		case slices.Contains(clientStringFields, base):
			var value string
			if err := json.Unmarshal(raw, &value); err != nil || len(value) > 2048 {
				return failField(key, key+" must be a string within 2048 characters.")
			}
			if value == "" {
				delete(m, key)
			}
		case slices.Contains(clientArrayFields, key):
			var values []string
			if err := json.Unmarshal(raw, &values); err != nil || len(values) > 100 {
				return failField(key, key+" must be an array of at most 100 strings.")
			}
			seen := map[string]bool{}
			for _, v := range values {
				if strings.TrimSpace(v) == "" || len(v) > 2048 || seen[v] {
					return failField(key, key+" contains an empty, duplicate, or oversized value.")
				}
				seen[v] = true
			}
		case key == "require_auth_time":
			var value bool
			if json.Unmarshal(raw, &value) != nil {
				return failField(key, key+" must be a boolean.")
			}
		case key == "default_max_age":
			var value int64
			if json.Unmarshal(raw, &value) != nil || value < 0 || value > 9007199254740991 {
				return failField(key, key+" must be a non-negative safe integer.")
			}
		case key == "jwks":
			if err := validateClientJWKS(raw); err != nil {
				return nil, err
			}
		default:
			return fail("Unsupported or read-only client metadata field: " + key)
		}
	}
	var suppliedGrants []string
	_ = json.Unmarshal(input["grant_types"], &suppliedGrants)
	oauthOnly := len(suppliedGrants) > 0 && !slices.Contains(suppliedGrants, "authorization_code") && !slices.Contains(suppliedGrants, "implicit")
	defaults := map[string]any{"application_type": "web", "response_types": []string{"code"}, "grant_types": []string{"authorization_code"}, "token_endpoint_auth_method": "client_secret_basic", "id_token_signed_response_alg": "RS256", "require_auth_time": false}
	if oauthOnly {
		defaults["response_types"] = []string{}
	}
	for k, v := range defaults {
		if _, ok := m[k]; !ok {
			m.set(k, v)
		}
	}
	if !slices.Contains([]string{"web", "native"}, m.text("application_type")) {
		return fail("Application type must be web or native.")
	}
	if t := m.text("subject_type"); t != "" && t != "public" && t != "pairwise" {
		return fail("Subject type must be public or pairwise.")
	}
	method := m.text("token_endpoint_auth_method")
	if !slices.Contains(strings.Fields("client_secret_basic client_secret_post client_secret_jwt private_key_jwt none"), method) {
		return fail("Invalid token endpoint authentication method.")
	}
	grants := m.list("grant_types")
	if len(grants) == 0 {
		return fail("At least one grant type is required.")
	}
	for _, g := range grants {
		if !slices.Contains(strings.Fields("authorization_code implicit refresh_token client_credentials password"), g) {
			return fail("Unsupported OpenID Connect grant type.")
		}
	}
	responses := m.list("response_types")
	if len(responses) == 0 && !oauthOnly {
		return fail("At least one response type is required.")
	}
	for _, r := range responses {
		tokens := strings.Fields(r)
		slices.Sort(tokens)
		canonical := strings.Join(tokens, " ")
		if !slices.Contains([]string{"code", "id_token", "id_token token", "code id_token", "code token", "code id_token token"}, canonical) {
			return fail("Invalid OpenID Connect response type.")
		}
		if slices.Contains(tokens, "code") && !slices.Contains(grants, "authorization_code") {
			return fail("Code responses require the authorization_code grant.")
		}
		if (slices.Contains(tokens, "id_token") || slices.Contains(tokens, "token")) && !slices.Contains(grants, "implicit") {
			return fail("Token responses require the implicit grant.")
		}
		if slices.Contains(tokens, "id_token") && m.text("id_token_signed_response_alg") == "none" {
			return fail("ID tokens returned by the authorization endpoint must be signed.")
		}
	}
	redirects := m.list("redirect_uris")
	if len(redirects) == 0 && !oauthOnly {
		return failRedirect("At least one redirect URI is required.")
	}
	hosts := map[string]bool{}
	for _, raw := range redirects {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || strings.ContainsAny(raw, "#*\\") || u.User != nil {
			return failRedirect("Redirect URIs must be absolute, without fragments, wildcards, or credentials.")
		}
		loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
		if m.text("application_type") == "native" {
			if u.Scheme == "https" || (u.Scheme == "http" && !loopback) || slices.Contains([]string{"javascript", "data", "file"}, u.Scheme) {
				return failRedirect("Native redirects require a custom scheme or HTTP loopback URL.")
			}
		} else {
			if (u.Scheme != "https" && !(u.Scheme == "http" && loopback)) || u.Host == "" {
				return failRedirect("Web redirects require HTTPS (HTTP loopback is allowed for code flow).")
			}
			if slices.Contains(grants, "implicit") && (u.Scheme != "https" || loopback) {
				return failRedirect("Implicit web redirects require HTTPS and a non-loopback host.")
			}
		}
		hosts[u.Hostname()] = true
	}
	if m.text("subject_type") == "pairwise" && len(hosts) > 1 && m.text("sector_identifier_uri") == "" {
		return failField("sector_identifier_uri", "Pairwise clients with multiple redirect hosts require a sector identifier URI.")
	}
	for key := range m {
		base, _, _ := strings.Cut(key, "#")
		if slices.Contains([]string{"logo_uri", "client_uri", "policy_uri", "tos_uri", "jwks_uri", "sector_identifier_uri", "initiate_login_uri"}, base) {
			httpsOnly := slices.Contains([]string{"jwks_uri", "sector_identifier_uri", "initiate_login_uri"}, base)
			if !validClientURL(m.text(key), httpsOnly, false) {
				return failField(key, key+" must be a valid "+map[bool]string{true: "HTTPS", false: "HTTP(S)"}[httpsOnly]+" URL.")
			}
		}
	}
	for _, uri := range m.list("request_uris") {
		if !validClientURL(uri, true, true) {
			return fail("Request URIs must use HTTPS.")
		}
	}
	for _, contact := range m.list("contacts") {
		a, err := mail.ParseAddress(contact)
		if err != nil || a.Address != contact {
			return fail("Contacts must be email addresses.")
		}
	}
	if m["jwks"] != nil && m.text("jwks_uri") != "" {
		return fail("Specify jwks or jwks_uri, not both.")
	}
	if method == "private_key_jwt" && m["jwks"] == nil && m.text("jwks_uri") == "" {
		return fail("Private key JWT authentication requires jwks or jwks_uri.")
	}
	for _, key := range []string{"id_token_signed_response_alg", "userinfo_signed_response_alg", "request_object_signing_alg", "token_endpoint_auth_signing_alg"} {
		alg := m.text(key)
		if alg == "" {
			continue
		}
		if !slices.Contains(signingAlgorithms, alg) {
			return fail("Unsupported signing algorithm for " + key)
		}
		if key == "token_endpoint_auth_signing_alg" {
			if alg == "none" || (method != "private_key_jwt" && method != "client_secret_jwt") || (method == "client_secret_jwt") != strings.HasPrefix(alg, "HS") {
				return fail("Authentication signing algorithm must match the JWT authentication method.")
			}
		}
	}
	for _, pair := range [][2]string{{"id_token_encrypted_response_alg", "id_token_encrypted_response_enc"}, {"userinfo_encrypted_response_alg", "userinfo_encrypted_response_enc"}, {"request_object_encryption_alg", "request_object_encryption_enc"}} {
		alg, enc := m.text(pair[0]), m.text(pair[1])
		if enc != "" && alg == "" {
			return fail(pair[1] + " requires " + pair[0])
		}
		if alg != "" {
			if !slices.Contains(encryptionAlgorithms, alg) {
				return fail("Unsupported encryption algorithm for " + pair[0])
			}
			if enc == "" {
				m.set(pair[1], "A128CBC-HS256")
			} else if !slices.Contains(encryptionMethods, enc) {
				return fail("Unsupported encryption method for " + pair[1])
			}
		}
	}
	return m, nil
}
func validClientURL(raw string, httpsOnly, fragment bool) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && u.User == nil && !strings.ContainsAny(raw, "*\\") && (fragment || !strings.Contains(raw, "#")) && (u.Scheme == "https" || (!httpsOnly && u.Scheme == "http"))
}
func validateClientJWKS(raw json.RawMessage) error {
	fail := func() error {
		return ValidationError("JWKS must contain public RSA, EC, or OKP keys without private or symmetric material.")
	}
	var set struct {
		Keys []map[string]json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(raw, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > 20 {
		return fail()
	}
	for _, key := range set.Keys {
		for _, private := range strings.Fields("d p q dp dq qi oth k") {
			if _, ok := key[private]; ok {
				return fail()
			}
		}
		text := func(k string) string { var s string; _ = json.Unmarshal(key[k], &s); return s }
		var required []string
		switch text("kty") {
		case "RSA":
			required = []string{"n", "e"}
		case "EC":
			required = []string{"x", "y"}
			if !slices.Contains([]string{"P-256", "P-384", "P-521"}, text("crv")) {
				return fail()
			}
		case "OKP":
			required = []string{"x"}
			if !slices.Contains([]string{"Ed25519", "Ed448", "X25519", "X448"}, text("crv")) {
				return fail()
			}
		default:
			return fail()
		}
		for _, k := range required {
			b, e := base64.RawURLEncoding.DecodeString(text(k))
			if e != nil || len(b) == 0 {
				return fail()
			}
		}
	}
	return nil
}
