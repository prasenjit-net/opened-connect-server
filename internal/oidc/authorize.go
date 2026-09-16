package oidc

import (
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"github.com/prasenjit-net/opened-connect-server/internal/oidc/capability"
)

// securityCriticalParams must never appear more than once in a single
// /authorize request, whether it arrives as a GET query or a POST body.
var securityCriticalParams = []string{
	"response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
	"code_challenge", "code_challenge_method", "prompt", "max_age",
}

var supportedPrompts = []string{"none", "login", "consent", "select_account"}

// parseAuthorizeParams reads request parameters from exactly one source —
// the query string for GET, the form body for POST — so a single request
// can never mix conflicting query and body values for the same parameter.
func parseAuthorizeParams(r *http.Request) (url.Values, bool) {
	switch r.Method {
	case http.MethodGet:
		return r.URL.Query(), true
	case http.MethodPost:
		if err := r.ParseForm(); err != nil {
			return nil, false
		}
		return r.PostForm, true
	default:
		return nil, false
	}
}

// currentPrincipal resolves the browser's session cookie the same way
// internal/api's requestHash does, without importing that package.
func (s *Service) currentPrincipal(r *http.Request) (identity.Principal, error) {
	c, err := r.Cookie(identity.SessionCookieName)
	if err != nil || len(c.Value) != 43 {
		return identity.Principal{}, identity.ErrUnauthorized
	}
	return s.Identity.Authenticate(r.Context(), identity.SessionHash(c.Value))
}

func clearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name: identity.SessionCookieName, Value: "", Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: -1, Expires: time.Unix(1, 0),
	})
}

// AuthorizeHandler implements the authorization-code profile of /authorize
// (OIDC_IMPLEMENTATION_PLAN.md section 6). Failures before the client and
// redirect URI are validated render an HTML error page directly; failures
// after that point redirect back to the relying party with an OAuth error.
func (s *Service) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
	params, ok := parseAuthorizeParams(r)
	if !ok {
		writeAuthorizeErrorPage(w, "Only GET and POST requests are supported.")
		return
	}
	for _, key := range securityCriticalParams {
		if len(params[key]) > 1 {
			writeAuthorizeErrorPage(w, "The request contains a duplicate "+key+" parameter.")
			return
		}
	}
	clientID := strings.TrimSpace(params.Get("client_id"))
	if clientID == "" {
		writeAuthorizeErrorPage(w, "A client_id is required.")
		return
	}
	client, err := s.Identity.ProtocolClient(r.Context(), clientID)
	if err != nil {
		writeAuthorizeErrorPage(w, "This client is not registered.")
		return
	}
	if !client.Compatible {
		writeAuthorizeErrorPage(w, "This client is registered with settings this provider does not support yet: "+strings.Join(client.IncompatibilityReasons, "; "))
		return
	}
	redirectURI := params.Get("redirect_uri")
	if !slices.Contains(client.RedirectURIs, redirectURI) {
		writeAuthorizeErrorPage(w, "The redirect_uri does not exactly match a URI registered for this client.")
		return
	}

	// The redirect URI is trusted from here on: failures redirect back to
	// the relying party as OAuth errors rather than rendering HTML.
	state := params.Get("state")
	fail := func(code, description string) { redirectWithError(w, r, redirectURI, code, description, state) }

	if params.Get("response_type") != "code" {
		fail("unsupported_response_type", "Only the code response type is supported.")
		return
	}
	if !slices.Contains(client.GrantTypes, "authorization_code") {
		fail("unauthorized_client", "This client is not authorized for the authorization code grant.")
		return
	}

	requestedScopes := strings.Fields(params.Get("scope"))
	if !slices.Contains(requestedScopes, "openid") {
		fail("invalid_scope", "The openid scope is required.")
		return
	}
	scopes := make([]string, 0, len(requestedScopes))
	for _, sc := range requestedScopes {
		if slices.Contains(capability.SupportedScopes, sc) {
			scopes = append(scopes, sc)
		}
	}

	if err := ValidateCodeChallenge(params.Get("code_challenge"), params.Get("code_challenge_method")); err != nil {
		fail("invalid_request", "A valid S256 code_challenge is required.")
		return
	}

	prompts := strings.Fields(params.Get("prompt"))
	for _, p := range prompts {
		if !slices.Contains(supportedPrompts, p) {
			fail("invalid_request", "Unsupported prompt value: "+p)
			return
		}
	}
	if slices.Contains(prompts, "none") && len(prompts) > 1 {
		fail("invalid_request", "prompt=none cannot be combined with other prompt values.")
		return
	}
	if slices.Contains(prompts, "select_account") {
		fail("account_selection_required", "Account selection is not supported by this provider.")
		return
	}

	var maxAge *int64
	if raw := params.Get("max_age"); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || v < 0 {
			fail("invalid_request", "max_age must be a non-negative integer.")
			return
		}
		maxAge = &v
	} else if client.DefaultMaxAge > 0 {
		v := client.DefaultMaxAge
		maxAge = &v
	}

	now := s.Now()
	principal, sessionErr := s.currentPrincipal(r)
	fresh := sessionErr == nil && (maxAge == nil || now.Sub(principal.Session.AuthTime) <= time.Duration(*maxAge)*time.Second)
	needsLogin := sessionErr != nil || slices.Contains(prompts, "login") || !fresh

	if slices.Contains(prompts, "none") {
		if needsLogin {
			fail("login_required", "The user must sign in to continue.")
			return
		}
		consented, err := s.hasValidConsent(r.Context(), principal.User.ID, client, scopes)
		if err != nil {
			fail("server_error", "Unable to evaluate consent.")
			return
		}
		if !consented {
			fail("consent_required", "The user must approve this request.")
			return
		}
		redirectTo := s.mintCode(r.Context(), finishParams{
			client: client, redirectURI: redirectURI, scopes: scopes, state: state,
			nonce: params.Get("nonce"), codeChallenge: params.Get("code_challenge"), codeChallengeMethod: params.Get("code_challenge_method"),
			userID: principal.User.ID, authTime: principal.Session.AuthTime,
		})
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		http.Redirect(w, r, redirectTo, http.StatusFound)
		return
	}

	txnID, err := randomToken()
	if err != nil {
		fail("server_error", "Unable to start this sign-in request.")
		return
	}
	binding, err := randomToken()
	if err != nil {
		fail("server_error", "Unable to start this sign-in request.")
		return
	}
	txn := identity.AuthzTransaction{
		ID:                  txnID,
		ClientID:            client.ID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		State:               state,
		Nonce:               params.Get("nonce"),
		CodeChallenge:       params.Get("code_challenge"),
		CodeChallengeMethod: params.Get("code_challenge_method"),
		Prompt:              prompts,
		MaxAge:              maxAge,
		LoginHint:           params.Get("login_hint"),
		BrowserBindingHash:  hashToken(binding),
		ClientUpdatedAt:     time.Unix(client.UpdatedAt, 0).UTC(),
		ExpiresAt:           now.Add(s.Config.TransactionTTL),
		CreatedAt:           now,
	}
	if !needsLogin {
		txn.UserID = principal.User.ID
		txn.AuthTime = principal.Session.AuthTime.Unix()
	}

	if err := s.Store.Write(r.Context(), func(tx identity.Tx) error {
		tx.PruneOIDCState(now)
		tx.SaveAuthzTransaction(txn)
		return nil
	}); err != nil {
		fail("server_error", "Unable to start this sign-in request.")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name: authzBindingCookieName, Value: binding, Path: "/", HttpOnly: true,
		Secure: s.Config.CookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: int(s.Config.TransactionTTL.Seconds()),
	})

	continuation := "/oidc/continue?tx=" + url.QueryEscape(txn.ID)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if needsLogin {
		// Force a fresh login even if a session cookie is currently valid,
		// by making the browser forget it for this navigation. This does
		// not revoke the session server-side, so it remains usable
		// elsewhere (e.g. another tab) — prompt=login only asks this
		// browser to re-assert identity for this specific request.
		clearSessionCookie(w, s.Config.CookieSecure)
		http.Redirect(w, r, "/login?redirect="+url.QueryEscape(continuation), http.StatusFound)
		return
	}
	http.Redirect(w, r, continuation, http.StatusFound)
}
