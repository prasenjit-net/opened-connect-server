package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

const authzBindingCookieName = "ocs_authz_binding"

var errClientPolicyChanged = errors.New("client policy changed since this request began")

// invalidRequestMessage is shown whenever a transaction can't be resolved
// for the current browser, for any reason (expired, consumed, wrong
// browser/account, or the client's settings changed). Deliberately generic:
// distinguishing these cases in the UI would help an attacker probe
// transaction IDs.
const invalidRequestMessage = "This sign-in request is no longer valid. Start again from the application you were using."

// ScopeInfo describes one requested scope for the consent screen.
type ScopeInfo struct {
	Scope       string `json:"scope"`
	Description string `json:"description"`
}

var scopeDescriptions = map[string]string{
	"openid":  "Confirm your identity",
	"profile": "Your name and basic profile information",
	"email":   "Your email address",
	"address": "Your postal address",
	"phone":   "Your phone number",
}

// TransactionView is the interaction API's response shape: either the
// request already completed (RedirectTo is where the browser should go
// next, including on denial or error — the relying party always gets a
// callback), it needs a consent decision, or it has failed outright.
type TransactionView struct {
	Status     string      `json:"status"` // "complete", "consent_required", or "error"
	RedirectTo string      `json:"redirectTo,omitempty"`
	ClientName string      `json:"clientName,omitempty"`
	Scopes     []ScopeInfo `json:"scopes,omitempty"`
	Message    string      `json:"message,omitempty"`
}

func errorView() TransactionView {
	return TransactionView{Status: "error", Message: invalidRequestMessage}
}

// currentBinding reads and hashes the authorization-binding cookie /authorize
// set. A transaction is only ever resolved for the browser that presents
// this value; the transaction ID alone is not sufficient.
func (s *Service) currentBinding(r *http.Request) (string, bool) {
	c, err := r.Cookie(authzBindingCookieName)
	if err != nil || c.Value == "" {
		return "", false
	}
	return hashToken(c.Value), true
}

func bindingMatches(txn identity.AuthzTransaction, bindingHash string) bool {
	return bindingHash != "" && subtle.ConstantTimeCompare([]byte(txn.BrowserBindingHash), []byte(bindingHash)) == 1
}

func (s *Service) loadOpenTransaction(r *http.Request, transactionID string) (identity.AuthzTransaction, bool) {
	bindingHash, ok := s.currentBinding(r)
	if !ok {
		return identity.AuthzTransaction{}, false
	}
	var txn identity.AuthzTransaction
	err := s.Store.Read(r.Context(), func(tx identity.ReadTx) error {
		var err error
		txn, err = tx.AuthzTransaction(transactionID)
		return err
	})
	if err != nil || !bindingMatches(txn, bindingHash) || txn.Consumed || !s.Now().Before(txn.ExpiresAt) {
		return identity.AuthzTransaction{}, false
	}
	return txn, true
}

// bindUser associates a transaction with the currently authenticated
// principal the first time it's resolved after login, and verifies it on
// every subsequent resolution. This is what binds the transaction across
// session rotation at login (the transaction is keyed by the browser
// binding cookie and, once set, the user ID — never the session hash).
func (s *Service) bindUser(ctx context.Context, txn identity.AuthzTransaction, principal identity.Principal) (identity.AuthzTransaction, bool) {
	if txn.UserID != "" {
		return txn, txn.UserID == principal.User.ID
	}
	txn.UserID = principal.User.ID
	txn.AuthTime = principal.Session.AuthTime.Unix()
	_ = s.Store.Write(ctx, func(tx identity.Tx) error {
		current, err := tx.AuthzTransaction(txn.ID)
		if err != nil {
			return err
		}
		if current.UserID == "" {
			current.UserID = txn.UserID
			current.AuthTime = txn.AuthTime
			tx.SaveAuthzTransaction(current)
		}
		return nil
	})
	return txn, true
}

func (s *Service) hasValidConsent(ctx context.Context, userID string, client identity.ProtocolClient, requestedScopes []string) (bool, error) {
	var consent identity.Consent
	err := s.Store.Read(ctx, func(tx identity.ReadTx) error {
		var err error
		consent, err = tx.Consent(userID, client.ID)
		return err
	})
	if errors.Is(err, identity.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if consent.Revoked || consent.PolicyRevision != client.UpdatedAt {
		return false, nil
	}
	for _, sc := range requestedScopes {
		if !slices.Contains(consent.Scopes, sc) {
			return false, nil
		}
	}
	return true, nil
}

func (s *Service) resolveClient(ctx context.Context, txn identity.AuthzTransaction) (identity.ProtocolClient, bool) {
	client, err := s.Identity.ProtocolClient(ctx, txn.ClientID)
	if err != nil || !client.Compatible {
		return identity.ProtocolClient{}, false
	}
	if time.Unix(client.UpdatedAt, 0).UTC() != txn.ClientUpdatedAt {
		return identity.ProtocolClient{}, false
	}
	return client, true
}

// Status resolves a transaction for the currently authenticated browser:
// it either completes immediately (a covering consent is already on file
// and no interaction parameter forces a fresh prompt), needs a consent
// decision, or has failed (expired, consumed, or bound to a different
// browser/account, or the client's settings changed).
func (s *Service) Status(r *http.Request, principal identity.Principal, transactionID string) TransactionView {
	txn, ok := s.loadOpenTransaction(r, transactionID)
	if !ok {
		return errorView()
	}
	txn, ok = s.bindUser(r.Context(), txn, principal)
	if !ok {
		return errorView()
	}
	client, ok := s.resolveClient(r.Context(), txn)
	if !ok {
		return errorView()
	}

	if !slices.Contains(txn.Prompt, "consent") {
		if consented, err := s.hasValidConsent(r.Context(), txn.UserID, client, txn.Scopes); err == nil && consented {
			redirectTo := s.mintCode(r.Context(), finishParams{
				client: client, redirectURI: txn.RedirectURI, scopes: txn.Scopes, state: txn.State,
				nonce: txn.Nonce, codeChallenge: txn.CodeChallenge, codeChallengeMethod: txn.CodeChallengeMethod,
				userID: txn.UserID, authTime: time.Unix(txn.AuthTime, 0).UTC(),
			})
			s.consumeTransaction(r.Context(), transactionID)
			return TransactionView{Status: "complete", RedirectTo: redirectTo}
		}
	}

	scopes := make([]ScopeInfo, 0, len(txn.Scopes))
	for _, sc := range txn.Scopes {
		scopes = append(scopes, ScopeInfo{Scope: sc, Description: scopeDescriptions[sc]})
	}
	return TransactionView{Status: "consent_required", ClientName: client.ID, Scopes: scopes}
}

// Decide records a consent decision and completes the transaction. Denial
// still produces a redirect (with error=access_denied): the relying party
// always gets a callback.
func (s *Service) Decide(r *http.Request, principal identity.Principal, transactionID string, approve bool, approvedScopes []string) TransactionView {
	txn, ok := s.loadOpenTransaction(r, transactionID)
	if !ok {
		return errorView()
	}
	txn, ok = s.bindUser(r.Context(), txn, principal)
	if !ok {
		return errorView()
	}
	client, ok := s.resolveClient(r.Context(), txn)
	if !ok {
		return errorView()
	}

	if !approve {
		redirectTo := errorRedirectURL(txn.RedirectURI, "access_denied", "The user denied the request.", txn.State)
		s.consumeTransaction(r.Context(), transactionID)
		return TransactionView{Status: "complete", RedirectTo: redirectTo}
	}

	// The client can only ever narrow scopes below what was requested and
	// validated at /authorize; it can never add scopes here. openid is
	// always included since it was required to reach this point.
	grantedScopes := []string{"openid"}
	for _, sc := range txn.Scopes {
		if sc != "openid" && slices.Contains(approvedScopes, sc) {
			grantedScopes = append(grantedScopes, sc)
		}
	}

	if err := s.Store.Write(r.Context(), func(tx identity.Tx) error {
		tx.SaveConsent(identity.Consent{UserID: txn.UserID, ClientID: client.ID, Scopes: grantedScopes, PolicyRevision: client.UpdatedAt, GrantedAt: s.Now()})
		return nil
	}); err != nil {
		return TransactionView{Status: "error", Message: "Unable to record consent. Try again."}
	}

	redirectTo := s.mintCode(r.Context(), finishParams{
		client: client, redirectURI: txn.RedirectURI, scopes: grantedScopes, state: txn.State,
		nonce: txn.Nonce, codeChallenge: txn.CodeChallenge, codeChallengeMethod: txn.CodeChallengeMethod,
		userID: txn.UserID, authTime: time.Unix(txn.AuthTime, 0).UTC(),
	})
	s.consumeTransaction(r.Context(), transactionID)
	return TransactionView{Status: "complete", RedirectTo: redirectTo}
}

func (s *Service) consumeTransaction(ctx context.Context, id string) {
	_ = s.Store.Write(ctx, func(tx identity.Tx) error {
		txn, err := tx.AuthzTransaction(id)
		if err != nil {
			return nil
		}
		txn.Consumed = true
		tx.SaveAuthzTransaction(txn)
		return nil
	})
}

// finishParams carries everything mintCode needs to atomically re-verify
// eligibility and issue a single-use authorization code.
type finishParams struct {
	client              identity.ProtocolClient
	redirectURI         string
	scopes              []string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
	userID              string
	authTime            time.Time
}

// mintCode atomically re-verifies the account and client policy revision
// haven't changed since the request was validated, then persists a
// single-use authorization code. It always returns a redirect URL — either
// a success response or an OAuth error response — never a bare error, so
// callers can always send the browser back to the relying party.
func (s *Service) mintCode(ctx context.Context, p finishParams) string {
	now := s.Now()
	code, err := randomToken()
	if err != nil {
		return errorRedirectURL(p.redirectURI, "server_error", "Unable to complete this sign-in request.", p.state)
	}
	rec := identity.AuthorizationCode{
		Hash:                hashToken(code),
		ClientID:            p.client.ID,
		UserID:              p.userID,
		RedirectURI:         p.redirectURI,
		Scopes:              p.scopes,
		Nonce:               p.nonce,
		AuthTime:            p.authTime.Unix(),
		CodeChallenge:       p.codeChallenge,
		CodeChallengeMethod: p.codeChallengeMethod,
		ClientUpdatedAt:     time.Unix(p.client.UpdatedAt, 0).UTC(),
		ExpiresAt:           now.Add(s.Config.CodeTTL),
	}
	writeErr := s.Store.Write(ctx, func(tx identity.Tx) error {
		user, err := tx.User(p.userID)
		if err != nil || !user.Active {
			return identity.ErrUnauthorized
		}
		client, err := tx.Client(p.client.ID)
		if err != nil {
			return identity.ErrNotFound
		}
		if client.UpdatedAt.Unix() != p.client.UpdatedAt {
			return errClientPolicyChanged
		}
		tx.PruneOIDCState(now)
		tx.SaveAuthorizationCode(rec)
		return nil
	})
	if writeErr != nil {
		switch {
		case errors.Is(writeErr, identity.ErrUnauthorized), errors.Is(writeErr, identity.ErrNotFound):
			return errorRedirectURL(p.redirectURI, "access_denied", "The account or client is no longer available.", p.state)
		case errors.Is(writeErr, errClientPolicyChanged):
			return errorRedirectURL(p.redirectURI, "invalid_request", "This client's settings changed; please restart the request.", p.state)
		default:
			return errorRedirectURL(p.redirectURI, "server_error", "Unable to complete this sign-in request.", p.state)
		}
	}
	u, _ := url.Parse(p.redirectURI)
	q := u.Query()
	q.Set("code", code)
	if p.state != "" {
		q.Set("state", p.state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
