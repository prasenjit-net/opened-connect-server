package oidc

import (
	"slices"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

// ProjectUserInfo builds a dedicated claims projection for /userinfo. It
// only ever copies specific named fields out of identity.Profile, scope-
// gated — it never serializes the stored profile wholesale, so custom
// attributes, password hashes, and internal bookkeeping fields can never
// reach a protocol response.
func ProjectUserInfo(profile identity.Profile, scopes []string) map[string]any {
	claims := map[string]any{"sub": profile.Sub}
	has := func(scope string) bool { return slices.Contains(scopes, scope) }
	set := func(key, value string) {
		if value != "" {
			claims[key] = value
		}
	}
	if has("profile") {
		set("name", profile.Name)
		set("given_name", profile.GivenName)
		set("family_name", profile.FamilyName)
		set("middle_name", profile.MiddleName)
		set("nickname", profile.Nickname)
		set("preferred_username", profile.PreferredUsername)
		set("profile", profile.ProfileURL)
		set("picture", profile.Picture)
		set("website", profile.Website)
		set("gender", profile.Gender)
		set("birthdate", profile.Birthdate)
		set("zoneinfo", profile.Zoneinfo)
		set("locale", profile.Locale)
		claims["updated_at"] = profile.ClaimUpdatedAt
	}
	if has("email") && profile.Email != "" {
		claims["email"] = profile.Email
		claims["email_verified"] = profile.EmailVerified
	}
	if has("address") && profile.Address != (identity.Address{}) {
		address := map[string]any{}
		set2 := func(key, value string) {
			if value != "" {
				address[key] = value
			}
		}
		set2("formatted", profile.Address.Formatted)
		set2("street_address", profile.Address.StreetAddress)
		set2("locality", profile.Address.Locality)
		set2("region", profile.Address.Region)
		set2("postal_code", profile.Address.PostalCode)
		set2("country", profile.Address.Country)
		claims["address"] = address
	}
	if has("phone") && profile.PhoneNumber != "" {
		claims["phone_number"] = profile.PhoneNumber
		claims["phone_number_verified"] = profile.PhoneNumberVerified
	}
	return claims
}

// signIDToken builds and signs a minimal ID token: issuer, audience,
// subject, issuance/expiry, and auth_time/nonce when applicable. Standard
// profile disclosure stays in UserInfo for this delivery (plan section 8);
// additional ID-token claims are a later, per-client-policy capability.
func (s *Service) signIDToken(client identity.ProtocolClient, sub, nonce string, authTime, issuedAt time.Time) (string, error) {
	claims := jwt.Claims{
		Issuer:   s.Config.Issuer,
		Subject:  sub,
		Audience: jwt.Audience{client.ID},
		Expiry:   jwt.NewNumericDate(issuedAt.Add(s.Config.IDTokenTTL)),
		IssuedAt: jwt.NewNumericDate(issuedAt),
	}
	extra := map[string]any{"auth_time": authTime.Unix()}
	if nonce != "" {
		extra["nonce"] = nonce
	}
	return s.Keys.Sign(claims, extra)
}
