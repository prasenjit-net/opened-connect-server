package identity

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Claims contains the editable OpenID Connect standard profile claims.
// Subject and update time are derived from the account, not supplied by clients.
type Claims struct {
	GivenName         string                     `json:"given_name,omitempty"`
	FamilyName        string                     `json:"family_name,omitempty"`
	MiddleName        string                     `json:"middle_name,omitempty"`
	Nickname          string                     `json:"nickname,omitempty"`
	PreferredUsername string                     `json:"preferred_username,omitempty"`
	ProfileURL        string                     `json:"profile,omitempty"`
	Picture           string                     `json:"picture,omitempty"`
	Website           string                     `json:"website,omitempty"`
	Gender            string                     `json:"gender,omitempty"`
	Birthdate         string                     `json:"birthdate,omitempty"`
	Zoneinfo          string                     `json:"zoneinfo,omitempty"`
	Locale            string                     `json:"locale,omitempty"`
	PhoneNumber       string                     `json:"phone_number,omitempty"`
	Address           Address                    `json:"address"`
	CustomAttributes  map[string]json.RawMessage `json:"custom_attributes,omitempty"`
}
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}
type ProfileInput struct {
	Name  string  `json:"name"`
	Email *string `json:"email,omitempty"`
	*Claims
}

var attributeKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,127}$`)
var birthdatePattern = regexp.MustCompile(`^([0-9]{4})(-[0-9]{2}-[0-9]{2})?$`)

func validateClaims(c *Claims) error {
	if c == nil {
		return nil
	}
	data, err := json.Marshal(c)
	if err != nil || len(data) > 16384 {
		return ValidationError("Profile attributes must be valid JSON within 16 KB.")
	}
	for _, value := range []string{c.ProfileURL, c.Picture, c.Website} {
		if value == "" {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
			return ValidationError("Profile, picture, and website must be HTTP or HTTPS URLs.")
		}
	}
	if c.Birthdate != "" {
		if !birthdatePattern.MatchString(c.Birthdate) {
			return ValidationError("Birthdate must be YYYY-MM-DD or YYYY.")
		}
		if len(c.Birthdate) == 10 {
			date := c.Birthdate
			if strings.HasPrefix(date, "0000") {
				date = "2000" + date[4:]
			}
			if _, err := time.Parse("2006-01-02", date); err != nil {
				return ValidationError("Invalid birthdate.")
			}
		}
	}
	if c.Zoneinfo != "" {
		if _, err := time.LoadLocation(c.Zoneinfo); err != nil {
			return ValidationError("Enter a valid time zone.")
		}
	}
	if len(c.CustomAttributes) > 50 {
		return ValidationError("At most 50 custom attributes are allowed.")
	}
	reserved := " id sub name email role active createdAt updatedAt updated_at password passwordHash email_verified phone_number_verified given_name family_name middle_name nickname preferred_username profile picture website gender birthdate zoneinfo locale phone_number address custom_attributes iss aud exp iat nbf auth_time nonce acr amr azp sid "
	for key := range c.CustomAttributes {
		if !attributeKey.MatchString(key) || strings.Contains(reserved, " "+key+" ") || key == "__proto__" || key == "constructor" || key == "prototype" {
			return ValidationError("Custom attribute names must be unique non-reserved identifiers.")
		}
	}
	return nil
}
func cloneUser(u User) User {
	if u.CustomAttributes != nil {
		copy := make(map[string]json.RawMessage, len(u.CustomAttributes))
		for k, v := range u.CustomAttributes {
			copy[k] = append(json.RawMessage(nil), v...)
		}
		u.CustomAttributes = copy
	}
	u.Sub = u.ID
	u.ClaimUpdatedAt = u.UpdatedAt.Unix()
	return u
}
