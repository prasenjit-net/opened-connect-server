package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Discovery mirrors the subset of the OP's /.well-known/openid-configuration
// document this RP actually uses. Fetched fresh (no caching beyond the
// process lifetime) so config changes to Issuer are picked up on demand.
type Discovery struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	IntrospectionEndpoint             string   `json:"introspection_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	FrontChannelLogoutSupported       bool     `json:"frontchannel_logout_supported"`
	BackChannelLogoutSupported        bool     `json:"backchannel_logout_supported"`
}

// Capabilities is a flattened, template-friendly view of what the connected
// OP actually advertises, so the UI can enable/disable flow buttons instead
// of offering things that will just 400.
type Capabilities struct {
	AuthCode            bool
	ClientCredentials   bool
	Password            bool
	RefreshToken        bool
	OfflineAccessScope  bool
	PKCES256            bool
	DynamicRegistration bool
	Introspection       bool
	Revocation          bool
	EndSession          bool
	FrontChannelLogout  bool
	BackChannelLogout   bool
	AuthMethods         []string
	Scopes              []string
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func (d *Discovery) Capabilities() Capabilities {
	return Capabilities{
		AuthCode:            contains(d.GrantTypesSupported, "authorization_code") && contains(d.ResponseTypesSupported, "code"),
		ClientCredentials:   contains(d.GrantTypesSupported, "client_credentials"),
		Password:            contains(d.GrantTypesSupported, "password"),
		RefreshToken:        contains(d.GrantTypesSupported, "refresh_token"),
		OfflineAccessScope:  contains(d.ScopesSupported, "offline_access"),
		PKCES256:            contains(d.CodeChallengeMethodsSupported, "S256"),
		DynamicRegistration: d.RegistrationEndpoint != "",
		Introspection:       d.IntrospectionEndpoint != "",
		Revocation:          d.RevocationEndpoint != "",
		EndSession:          d.EndSessionEndpoint != "",
		FrontChannelLogout:  d.FrontChannelLogoutSupported,
		BackChannelLogout:   d.BackChannelLogoutSupported,
		AuthMethods:         d.TokenEndpointAuthMethodsSupported,
		Scopes:              d.ScopesSupported,
	}
}

var httpClient = &http.Client{Timeout: 15 * time.Second}

func fetchDiscovery(issuer string) (*Discovery, string, error) {
	u := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := httpClient.Get(u)
	if err != nil {
		return nil, "", fmt.Errorf("fetching discovery document: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, string(body), fmt.Errorf("discovery endpoint returned %s", resp.Status)
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, string(body), fmt.Errorf("decoding discovery document: %w", err)
	}
	return &d, string(body), nil
}

func fetchJWKS(jwksURI string) (*jose.JSONWebKeySet, string, error) {
	resp, err := httpClient.Get(jwksURI)
	if err != nil {
		return nil, "", fmt.Errorf("fetching JWKS: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, string(body), fmt.Errorf("jwks endpoint returned %s", resp.Status)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, string(body), fmt.Errorf("decoding JWKS: %w", err)
	}
	return &set, string(body), nil
}

// PKCE

func newPKCE() (verifier, challenge string) {
	verifier = randomToken(32)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// TokenResponse is the raw JSON shape returned by the token endpoint across
// every grant type this RP exercises; fields not applicable to a given grant
// are simply left empty.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`

	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// exchangeToken posts to the token endpoint using the given client auth
// method, logging the exact request/response for the inspector.
func exchangeToken(store *Store, disc *Discovery, clientID, clientSecret, authMethod string, form url.Values, kind string) (*TokenResponse, error) {
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	if authMethod == "client_secret_post" || authMethod == "none" {
		form.Set("client_id", clientID)
		if authMethod == "client_secret_post" {
			form.Set("client_secret", clientSecret)
		}
	}

	req, err := http.NewRequest(http.MethodPost, disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if authMethod == "client_secret_basic" {
		req.SetBasicAuth(clientID, clientSecret)
	}

	store.log(kind+".request", "POST "+disc.TokenEndpoint, map[string]any{
		"auth_method": authMethod,
		"client_id":   clientID,
	}, form.Encode())

	resp, err := httpClient.Do(req)
	if err != nil {
		store.log(kind+".error", "token request failed", nil, err.Error())
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	var tr TokenResponse
	_ = json.Unmarshal(body, &tr)

	store.log(kind+".response", fmt.Sprintf("HTTP %d", resp.StatusCode), tr, prettyJSON(rawJSON(body)))

	if resp.StatusCode != http.StatusOK {
		if tr.ErrorCode == "" {
			tr.ErrorCode = fmt.Sprintf("http_%d", resp.StatusCode)
		}
		return &tr, fmt.Errorf("token endpoint error: %s - %s", tr.ErrorCode, tr.ErrorDescription)
	}
	return &tr, nil
}

func rawJSON(body []byte) any {
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return string(body)
	}
	return v
}

// verifyJWT checks signature (against the OP's live JWKS), issuer, audience,
// and expiry, returning the decoded claims as a generic map so every claim
// (known or not) can be displayed to the user.
func verifyJWT(raw string, jwks *jose.JSONWebKeySet, issuer, audience string) (map[string]any, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}
	if len(tok.Headers) == 0 {
		return nil, fmt.Errorf("JWT has no header")
	}
	kid := tok.Headers[0].KeyID
	var key jose.JSONWebKey
	found := false
	for _, k := range jwks.Keys {
		if kid == "" || k.KeyID == kid {
			key = k
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no matching key for kid=%q in JWKS", kid)
	}

	var claims map[string]any
	if err := tok.Claims(key.Key, &claims); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	if iss, _ := claims["iss"].(string); iss != issuer {
		return claims, fmt.Errorf("issuer mismatch: got %q, want %q", iss, issuer)
	}
	if !audienceContains(claims["aud"], audience) {
		return claims, fmt.Errorf("audience mismatch: %v does not contain %q", claims["aud"], audience)
	}
	if exp, ok := numericClaim(claims["exp"]); ok && time.Now().Unix() > int64(exp) {
		return claims, fmt.Errorf("token expired at %v", time.Unix(int64(exp), 0))
	}
	return claims, nil
}

// verifyLogoutToken checks signature, issuer, and expiry like verifyJWT, but
// skips the audience check (a single backchannel_logout_uri may be shared
// across several client registrations exercised from this RP) and instead
// enforces the Back-Channel Logout spec's structural rules: no nonce claim,
// and a present backchannel-logout event.
func verifyLogoutToken(raw string, jwks *jose.JSONWebKeySet, issuer string) (map[string]any, error) {
	tok, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("parsing JWT: %w", err)
	}
	if len(tok.Headers) == 0 {
		return nil, fmt.Errorf("JWT has no header")
	}
	if typ := tok.Headers[0].ExtraHeaders[jose.HeaderKey("typ")]; typ != nil && typ != "logout+jwt" {
		return nil, fmt.Errorf(`unexpected typ header %v, want "logout+jwt"`, typ)
	}
	kid := tok.Headers[0].KeyID
	var key jose.JSONWebKey
	found := false
	for _, k := range jwks.Keys {
		if kid == "" || k.KeyID == kid {
			key = k
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("no matching key for kid=%q in JWKS", kid)
	}

	var claims map[string]any
	if err := tok.Claims(key.Key, &claims); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	if iss, _ := claims["iss"].(string); iss != issuer {
		return claims, fmt.Errorf("issuer mismatch: got %q, want %q", iss, issuer)
	}
	if exp, ok := numericClaim(claims["exp"]); ok && time.Now().Unix() > int64(exp) {
		return claims, fmt.Errorf("token expired at %v", time.Unix(int64(exp), 0))
	}
	if _, hasNonce := claims["nonce"]; hasNonce {
		return claims, fmt.Errorf("logout token must not contain a nonce claim")
	}
	events, _ := claims["events"].(map[string]any)
	if events == nil || events["http://schemas.openid.net/event/backchannel-logout"] == nil {
		return claims, fmt.Errorf("missing backchannel-logout event claim")
	}
	if _, ok := claims["sid"].(string); !ok {
		return claims, fmt.Errorf("missing sid claim")
	}
	return claims, nil
}

func audienceContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func numericClaim(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func fetchUserInfo(store *Store, endpoint, accessToken string) (map[string]any, error) {
	req, _ := http.NewRequest(http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := httpClient.Do(req)
	if err != nil {
		store.log("userinfo.error", "request failed", nil, err.Error())
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var claims map[string]any
	_ = json.Unmarshal(body, &claims)
	store.log("userinfo.response", fmt.Sprintf("HTTP %d", resp.StatusCode), claims, prettyJSON(rawJSON(body)))
	if resp.StatusCode != http.StatusOK {
		return claims, fmt.Errorf("userinfo endpoint returned %s", resp.Status)
	}
	return claims, nil
}

func introspectToken(store *Store, disc *Discovery, clientID, clientSecret, token string) (map[string]any, error) {
	form := url.Values{"token": {token}}
	req, _ := http.NewRequest(http.MethodPost, disc.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	_ = json.Unmarshal(body, &result)
	store.log("introspect.response", fmt.Sprintf("HTTP %d", resp.StatusCode), result, prettyJSON(rawJSON(body)))
	return result, nil
}

func revokeToken(store *Store, disc *Discovery, clientID, clientSecret, token, tokenTypeHint string) error {
	form := url.Values{"token": {token}}
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	req, _ := http.NewRequest(http.MethodPost, disc.RevocationEndpoint, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(clientID, clientSecret)
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	store.log("revoke.response", fmt.Sprintf("HTTP %d", resp.StatusCode), nil, string(body))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation endpoint returned %s", resp.Status)
	}
	return nil
}

// readClientRegistration performs the RFC 7592 registration read: GET
// {registration_client_uri} with the registration access token, returning
// the client's current metadata as the OP sees it right now.
func readClientRegistration(store *Store, registrationClientURI, registrationAccessToken string) (map[string]any, error) {
	req, err := http.NewRequest(http.MethodGet, registrationClientURI, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+registrationAccessToken)

	store.log("register.read.request", "GET "+registrationClientURI, nil, "")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var result map[string]any
	_ = json.Unmarshal(body, &result)
	store.log("register.read.response", fmt.Sprintf("HTTP %d", resp.StatusCode), result, prettyJSON(rawJSON(body)))
	if resp.StatusCode != http.StatusOK {
		return result, fmt.Errorf("registration read endpoint returned %s", resp.Status)
	}
	return result, nil
}

// dynamicRegister performs RFC7591-ish dynamic client registration against
// the OP's /register endpoint, returning the raw decoded response so every
// field (including client_secret and registration_access_token) can be
// shown to the user and copied into the live config.
func dynamicRegister(store *Store, disc *Discovery, initialAccessToken string, metadata map[string]any) (map[string]any, error) {
	body, _ := json.Marshal(metadata)
	req, _ := http.NewRequest(http.MethodPost, disc.RegistrationEndpoint, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+initialAccessToken)

	store.log("register.request", "POST "+disc.RegistrationEndpoint, metadata, prettyJSON(metadata))

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	var result map[string]any
	_ = json.Unmarshal(respBody, &result)
	store.log("register.response", fmt.Sprintf("HTTP %d", resp.StatusCode), result, prettyJSON(rawJSON(respBody)))
	if resp.StatusCode != http.StatusCreated {
		return result, fmt.Errorf("registration endpoint returned %s", resp.Status)
	}
	return result, nil
}
