package identity

import "net/url"

// redactDSN strips userinfo (and thus any embedded password) from a
// DSN/URI before it can reach an error message, log line, or diagnostic.
// Falls back to a fixed placeholder if the value doesn't parse as a URL at
// all, so a malformed DSN still never leaks verbatim.
func redactDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.Host == "" {
		return "[redacted]"
	}
	u.User = nil
	return u.String()
}
