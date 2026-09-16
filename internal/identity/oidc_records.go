package identity

import "time"

// AuthzTransaction records a validated /authorize request while the user
// completes login and consent. It is bound to the issuing browser via
// BrowserBindingHash, which is a SHA-256 hash of a value carried only in a
// dedicated cookie — never the raw value itself.
type AuthzTransaction struct {
	ReauthenticateAfter time.Time `json:"reauthenticateAfter,omitempty"`
	ID                  string    `json:"id"`
	ClientID            string    `json:"clientId"`
	RedirectURI         string    `json:"redirectUri"`
	Scopes              []string  `json:"scopes"`
	State               string    `json:"state"`
	Nonce               string    `json:"nonce"`
	CodeChallenge       string    `json:"codeChallenge"`
	CodeChallengeMethod string    `json:"codeChallengeMethod"`
	Prompt              []string  `json:"prompt,omitempty"`
	MaxAge              *int64    `json:"maxAge,omitempty"`
	LoginHint           string    `json:"loginHint,omitempty"`
	BrowserBindingHash  string    `json:"browserBindingHash"`
	UserID              string    `json:"userId,omitempty"`
	AuthTime            int64     `json:"authTime,omitempty"`
	ClientUpdatedAt     time.Time `json:"clientUpdatedAt"`
	ConsentGranted      bool      `json:"consentGranted"`
	Consumed            bool      `json:"consumed"`
	ExpiresAt           time.Time `json:"expiresAt"`
	CreatedAt           time.Time `json:"createdAt"`
}

// AuthorizationCode is a single-use code minted after a transaction
// completes login and consent, exchanged for tokens at /token. Only its
// hash is persisted; the raw code is never stored.
type AuthorizationCode struct {
	RetainUntil         time.Time `json:"retainUntil,omitempty"`
	Hash                string    `json:"hash"`
	TransactionID       string    `json:"transactionId"`
	ClientID            string    `json:"clientId"`
	UserID              string    `json:"userId"`
	RedirectURI         string    `json:"redirectUri"`
	Scopes              []string  `json:"scopes"`
	Nonce               string    `json:"nonce,omitempty"`
	AuthTime            int64     `json:"authTime"`
	CodeChallenge       string    `json:"codeChallenge"`
	CodeChallengeMethod string    `json:"codeChallengeMethod"`
	ClientUpdatedAt     time.Time `json:"clientUpdatedAt"`
	Consumed            bool      `json:"consumed"`
	ExpiresAt           time.Time `json:"expiresAt"`
}

// AccessToken is an opaque bearer token minted at code-exchange time. Only
// its hash is persisted, mirroring how browser session tokens are stored.
// CodeHash links it back to the authorization code that minted it, so a
// replay of that code (which must otherwise already fail safely) can also
// revoke the token issued from the original, legitimate exchange.
type AccessToken struct {
	Hash      string    `json:"hash"`
	ClientID  string    `json:"clientId"`
	UserID    string    `json:"userId"`
	Audience  string    `json:"audience"`
	Scopes    []string  `json:"scopes"`
	CodeHash  string    `json:"codeHash,omitempty"`
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`
	Revoked   bool      `json:"revoked"`
}

// Consent binds a user's approved scope disclosure to a client at a
// specific policy revision (the client's UpdatedAt at grant time). A
// client metadata change invalidates the stored consent for re-approval.
type Consent struct {
	ID             string    `json:"id"`
	UserID         string    `json:"userId"`
	ClientID       string    `json:"clientId"`
	Scopes         []string  `json:"scopes"`
	PolicyRevision int64     `json:"policyRevision"`
	GrantedAt      time.Time `json:"grantedAt"`
	Revoked        bool      `json:"revoked"`
}

func consentID(userID, clientID string) string { return userID + "|" + clientID }

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

func cloneAuthzTransaction(t AuthzTransaction) AuthzTransaction {
	t.Scopes = cloneStrings(t.Scopes)
	t.Prompt = cloneStrings(t.Prompt)
	if t.MaxAge != nil {
		age := *t.MaxAge
		t.MaxAge = &age
	}
	return t
}
func cloneAuthorizationCode(c AuthorizationCode) AuthorizationCode {
	c.Scopes = cloneStrings(c.Scopes)
	return c
}
func cloneAccessToken(a AccessToken) AccessToken {
	a.Scopes = cloneStrings(a.Scopes)
	return a
}
func cloneConsent(c Consent) Consent {
	c.Scopes = cloneStrings(c.Scopes)
	return c
}
