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
	return consentCovers(consent, client, requestedScopes), nil
}

// Status and Decide share one atomic completion boundary. No code or consent can
// escape a failed write, and competing continuations cannot both consume a request.
func (s *Service) Status(r *http.Request, principal identity.Principal, id string) TransactionView {
	return s.completeInteraction(r, principal, id, nil, nil)
}
func (s *Service) Decide(r *http.Request, principal identity.Principal, id string, approve bool, scopes []string) TransactionView {
	return s.completeInteraction(r, principal, id, &approve, scopes)
}
func (s *Service) completeInteraction(r *http.Request, principal identity.Principal, id string, approve *bool, approvedScopes []string) TransactionView {
	binding, ok := s.currentBinding(r)
	if !ok {
		return errorView()
	}
	view := errorView()
	err := s.Store.Write(r.Context(), func(tx identity.Tx) error {
		now := s.Now()
		txn, err := tx.AuthzTransaction(id)
		if err != nil || txn.Revoked || txn.Consumed || !now.Before(txn.ExpiresAt) || !bindingMatches(txn, binding) {
			return identity.ErrUnauthorized
		}
		session, err := tx.Session(principal.Session.Hash)
		if err != nil || session.UserID != principal.User.ID || session.AuthTime.IsZero() || !now.Before(session.ExpiresAt) || session.AuthTime.After(now) {
			return identity.ErrUnauthorized
		}
		if !txn.ReauthenticateAfter.IsZero() {
			if session.AuthTime.Before(txn.ReauthenticateAfter) {
				return identity.ErrUnauthorized
			}
		} else if !sessionFresh(session, now, txn.MaxAge) {
			return identity.ErrUnauthorized
		}
		if txn.UserID != "" && txn.UserID != session.UserID {
			return identity.ErrUnauthorized
		}
		user, err := tx.User(session.UserID)
		if err != nil || !user.Active {
			return identity.ErrUnauthorized
		}
		record, err := tx.Client(txn.ClientID)
		if err != nil {
			return err
		}
		client := identity.RuntimeClient(record)
		if !client.Compatible || !record.UpdatedAt.Equal(txn.ClientUpdatedAt) {
			return errClientPolicyChanged
		}
		txn.UserID, txn.AuthTime = user.ID, session.AuthTime.Unix()
		consent, consentErr := tx.Consent(user.ID, client.ID)
		covered := consentErr == nil && consentCovers(consent, client, txn.Scopes)
		if consentErr != nil && !errors.Is(consentErr, identity.ErrNotFound) {
			return consentErr
		}
		if approve == nil && (!covered || slices.Contains(txn.Prompt, "consent")) {
			tx.SaveAuthzTransaction(txn)
			scopes := make([]ScopeInfo, 0, len(txn.Scopes))
			for _, sc := range txn.Scopes {
				scopes = append(scopes, ScopeInfo{Scope: sc, Description: scopeDescriptions[sc]})
			}
			view = TransactionView{Status: "consent_required", ClientName: client.ID, Scopes: scopes}
			return nil
		}
		redirect := errorRedirectURL(txn.RedirectURI, "access_denied", "The user denied the request.", txn.State)
		if approve == nil || *approve {
			granted := txn.Scopes
			if approve != nil {
				granted = []string{"openid"}
				for _, sc := range txn.Scopes {
					if sc != "openid" && slices.Contains(approvedScopes, sc) {
						granted = append(granted, sc)
					}
				}
				tx.SaveConsent(identity.Consent{UserID: user.ID, ClientID: client.ID, Scopes: granted, PolicyRevision: client.UpdatedAt, GrantedAt: now})
			}
			redirect, err = s.mintCodeTx(tx, finishParams{client: client, redirectURI: txn.RedirectURI, scopes: granted, state: txn.State, nonce: txn.Nonce, codeChallenge: txn.CodeChallenge, codeChallengeMethod: txn.CodeChallengeMethod, userID: user.ID, authTime: session.AuthTime, transactionID: txn.ID})
			if err != nil {
				return err
			}
		}
		txn.Consumed = true
		tx.SaveAuthzTransaction(txn)
		view = TransactionView{Status: "complete", RedirectTo: redirect}
		return nil
	})
	if err != nil {
		return errorView()
	}
	return view
}

func consentCovers(consent identity.Consent, client identity.ProtocolClient, scopes []string) bool {
	if consent.Revoked || consent.PolicyRevision != client.UpdatedAt {
		return false
	}
	for _, sc := range scopes {
		if !slices.Contains(consent.Scopes, sc) {
			return false
		}
	}
	return true
}

// finishParams carries everything mintCode needs to atomically re-verify
// eligibility and issue a single-use authorization code.
type finishParams struct {
	transactionID       string
	sessionHash         string
	maxAge              *int64
	requireConsent      bool
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
	var redirect string
	err := s.Store.Write(ctx, func(tx identity.Tx) error {
		if p.requireConsent {
			session, err := tx.Session(p.sessionHash)
			if err != nil || session.UserID != p.userID || !sessionFresh(session, s.Now(), p.maxAge) {
				return identity.ErrUnauthorized
			}
			consent, err := tx.Consent(p.userID, p.client.ID)
			if err != nil || !consentCovers(consent, p.client, p.scopes) {
				return identity.ErrUnauthorized
			}
		}
		var err error
		redirect, err = s.mintCodeTx(tx, p)
		return err
	})
	if err != nil {
		return errorRedirectURL(p.redirectURI, "access_denied", "The sign-in request is no longer valid.", p.state)
	}
	return redirect
}
func (s *Service) mintCodeTx(tx identity.Tx, p finishParams) (string, error) {
	user, err := tx.User(p.userID)
	if err != nil || !user.Active {
		return "", identity.ErrUnauthorized
	}
	client, err := tx.Client(p.client.ID)
	if err != nil {
		return "", err
	}
	if client.UpdatedAt.UnixNano() != p.client.UpdatedAt || !identity.RuntimeClient(client).Compatible {
		return "", errClientPolicyChanged
	}
	code, err := randomToken()
	if err != nil {
		return "", err
	}
	tx.PruneOIDCState(s.Now())
	tx.SaveAuthorizationCode(identity.AuthorizationCode{
		CreatedAt: s.Now(), Hash: hashToken(code), TransactionID: p.transactionID, ClientID: p.client.ID, UserID: p.userID,
		RedirectURI: p.redirectURI, Scopes: p.scopes, Nonce: p.nonce, AuthTime: p.authTime.Unix(),
		CodeChallenge: p.codeChallenge, CodeChallengeMethod: p.codeChallengeMethod,
		ClientUpdatedAt: client.UpdatedAt, ExpiresAt: s.Now().Add(s.Config.CodeTTL),
	})
	u, _ := url.Parse(p.redirectURI)
	q := u.Query()
	q.Set("code", code)
	if p.state != "" {
		q.Set("state", p.state)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
