package oidc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/prasenjit-net/openid-connect-server/internal/identity"
)

// Registration credentials are accepted only in the header, never cookies,
// URL parameters, client authentication, or protocol access tokens.
func registrationBearer(r *http.Request) string {
	if len(r.Header.Values("Authorization")) != 1 {
		return ""
	}
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || len(fields[1]) > 256 {
		return ""
	}
	return fields[1]
}
func (s *Service) registrationFailure(w http.ResponseWriter, err error) {
	var metadata *identity.RegistrationError
	switch {
	case errors.Is(err, identity.ErrRegistrationCredential):
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeOAuthError(w, 401, "invalid_token", "Registration credential is missing, invalid, or no longer active.")
	case errors.As(err, &metadata):
		writeOAuthError(w, 400, metadata.Code, metadata.Description)
	default:
		writeOAuthError(w, 500, "server_error", "Unable to complete registration operation.")
	}
}
func (s *Service) registrationTraffic(w http.ResponseWriter, r *http.Request, token string) bool {
	if !s.allowTraffic(w, r, "register") {
		return false
	}
	if !s.trafficLimiter.take("registration-credential|"+identity.SessionHash(token), 120, time.Minute) {
		w.Header().Set("Retry-After", "60")
		writeOAuthError(w, 429, "temporarily_unavailable", "Too many registration requests.")
		return false
	}
	return true
}

// Configuration reads remain available when new registrations are disabled,
// but must retain the same transport policy as registration itself.
func (s *Service) registrationTransportAllowed(w http.ResponseWriter) bool {
	issuer, err := url.Parse(s.Config.Issuer)
	if err == nil && issuer.Host != "" {
		if issuer.Scheme == "https" {
			return true
		}
		loopback := issuer.Hostname() == "localhost" || issuer.Hostname() == "127.0.0.1" || issuer.Hostname() == "::1"
		if issuer.Scheme == "http" && loopback && s.Config.RegistrationAllowHTTP {
			return true
		}
	}
	writeOAuthError(w, 404, "invalid_request", "Registration endpoints require HTTPS or a loopback development issuer.")
	return false
}

func (s *Service) RegistrationHandler(w http.ResponseWriter, r *http.Request) {
	if !s.Config.RegistrationEnabled {
		writeOAuthError(w, 404, "invalid_request", "Dynamic registration is disabled.")
		return
	}
	if !s.registrationTransportAllowed(w) {
		return
	}
	token := registrationBearer(r)
	if !s.registrationTraffic(w, r, token) {
		return
	}
	if err := s.Identity.CheckInitialToken(r.Context(), token); err != nil {
		s.registrationFailure(w, err)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		writeOAuthError(w, 415, "invalid_request", "Use application/json.")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16<<10))
	if err != nil {
		writeOAuthError(w, 413, "invalid_client_metadata", "Registration body must fit within 16 KB.")
		return
	}
	var input identity.ClientMetadata
	if err = validateRegistrationJSON(body); err != nil || json.Unmarshal(body, &input) != nil || input == nil {
		writeOAuthError(w, 400, "invalid_client_metadata", "Use one JSON object without duplicate keys or excessive nesting.")
		return
	}
	result, err := s.Identity.RegisterClient(r.Context(), token, input, s.Config.RegistrationAllowHTTP)
	if err != nil {
		s.registrationFailure(w, err)
		return
	}
	result["registration_client_uri"] = s.Config.Issuer + "/register/" + url.PathEscape(result["client_id"].(string))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(result)
}
func (s *Service) RegistrationReadHandler(w http.ResponseWriter, r *http.Request) {
	if !s.registrationTransportAllowed(w) {
		return
	}
	token := registrationBearer(r)
	if !s.registrationTraffic(w, r, token) {
		return
	}
	result, err := s.Identity.ReadRegistration(r.Context(), token, chi.URLParam(r, "clientID"))
	if err != nil {
		s.registrationFailure(w, err)
		return
	}
	result["registration_client_uri"] = s.Config.Issuer + "/register/" + url.PathEscape(result["client_id"].(string))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

// Walk the complete JSON tree before unmarshalling so duplicate security fields
// cannot acquire different meanings in different decoders (including JWKS).
func validateRegistrationJSON(body []byte) error {
	if !utf8.Valid(body) {
		return errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 16 {
			return errors.New("too deeply nested")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		switch token {
		case json.Delim('{'):
			seen := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("duplicate key")
				}
				seen[name] = true
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		case json.Delim('['):
			for d.More() {
				if err = walk(depth + 1); err != nil {
					return err
				}
			}
			_, err = d.Token()
			return err
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}
