package oidc

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

const maxProtocolRequestBytes = 16 * 1024

// Parse exactly one bounded parameter source and reject ambiguous encoding.
func parseProtocolForm(r *http.Request) (url.Values, error) {
	raw := r.URL.RawQuery
	if r.Method == http.MethodPost {
		media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if err != nil || media != "application/x-www-form-urlencoded" || raw != "" {
			return nil, errors.New("expected form body without query parameters")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxProtocolRequestBytes+1))
		if err != nil {
			return nil, err
		}
		raw = string(body)
	} else if r.Method != http.MethodGet {
		return nil, errors.New("unsupported method")
	}
	if len(raw) > maxProtocolRequestBytes {
		return nil, errors.New("request too large")
	}
	params, err := url.ParseQuery(raw)
	if err != nil {
		return nil, err
	}
	for _, values := range params {
		if len(values) != 1 {
			return nil, errors.New("duplicate parameter")
		}
	}
	return params, nil
}

func sessionFresh(session identity.Session, now time.Time, maxAge *int64) bool {
	if session.AuthTime.IsZero() || session.AuthTime.After(now) || !now.Before(session.ExpiresAt) {
		return false
	}
	// Compare seconds without converting untrusted integers into a duration.
	return maxAge == nil || (*maxAge > 0 && now.Unix()-session.AuthTime.Unix() <= *maxAge)
}
