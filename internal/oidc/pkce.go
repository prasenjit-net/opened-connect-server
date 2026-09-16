package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"regexp"
)

var (
	ErrPKCERequired = errors.New("pkce_required")
	ErrPKCEInvalid  = errors.New("pkce_invalid")
)

// pkceVerifierPattern matches RFC 7636's code_verifier syntax: 43-128
// characters from [A-Z] [a-z] [0-9] "-" "." "_" "~".
var pkceVerifierPattern = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// pkceChallengePattern matches the shape of a base64url(SHA-256(...))
// value with no padding: exactly 43 characters from the URL-safe alphabet.
var pkceChallengePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// ValidateCodeChallenge checks a /authorize request's PKCE parameters.
// Only S256 is accepted; "plain" and an absent method are both rejected, so
// there is no way to downgrade PKCE for a code client in this provider.
func ValidateCodeChallenge(challenge, method string) error {
	if challenge == "" {
		return ErrPKCERequired
	}
	if method != "S256" {
		return ErrPKCEInvalid
	}
	if !pkceChallengePattern.MatchString(challenge) {
		return ErrPKCEInvalid
	}
	return nil
}

// VerifyPKCE checks a /token request's code_verifier against the
// code_challenge stored with the authorization code.
func VerifyPKCE(verifier, challenge string) error {
	if !pkceVerifierPattern.MatchString(verifier) {
		return ErrPKCEInvalid
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrPKCEInvalid
	}
	return nil
}
