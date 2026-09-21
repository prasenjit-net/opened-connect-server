package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const sessionCookieName = "example_rp_session"

type App struct {
	cfg   *Config
	store *Store
	tmpl  *template.Template
}

func newApp(cfg *Config, store *Store, tmpl *template.Template) *App {
	return &App{cfg: cfg, store: store, tmpl: tmpl}
}

func (a *App) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", a.handleHome)

	// Config: every client this RP has acquired (dynamically registered or
	// entered by hand), reusable from any flow's form without retyping.
	mux.HandleFunc("GET /config", a.handleConfig)
	mux.HandleFunc("POST /config/clients", a.handleAddClient)
	mux.HandleFunc("POST /config/clients/{id}/refresh", a.handleRefreshClientRegistration)
	mux.HandleFunc("POST /config/clients/{id}/delete", a.handleDeleteClient)

	// Dynamic client registration, exercised as its own testable action.
	mux.HandleFunc("GET /register", a.handleRegisterForm)
	mux.HandleFunc("POST /register", a.handleRegisterSubmit)

	// Flow starters: GET shows a form to collect client_id/secret/scopes/
	// etc, POST actually begins the flow. Nothing here is remembered past
	// the request except inside the resulting session.
	mux.HandleFunc("GET /start/authcode", a.handleAuthCodeForm)
	mux.HandleFunc("POST /start/authcode", a.handleStartAuthCode)
	mux.HandleFunc("GET /start/password", a.handlePasswordForm)
	mux.HandleFunc("POST /start/password", a.handleStartPassword)
	mux.HandleFunc("GET /start/client-credentials", a.handleClientCredentialsForm)
	mux.HandleFunc("POST /start/client-credentials", a.handleStartClientCredentials)
	mux.HandleFunc("GET /callback", a.handleCallback)
	mux.HandleFunc("POST /refresh", a.handleRefresh)

	mux.HandleFunc("GET /profile", a.handleProfile)
	mux.HandleFunc("POST /userinfo/refresh", a.handleUserInfoRefresh)
	mux.HandleFunc("POST /introspect", a.handleIntrospect)
	mux.HandleFunc("POST /revoke", a.handleRevoke)

	// Logout: RP-initiated (front-channel via OP) and this RP's own
	// receivers for provider-driven front/back-channel notifications.
	mux.HandleFunc("GET /logout/rp-initiated", a.handleLogoutRPInitiated)
	mux.HandleFunc("POST /logout/local", a.handleLogoutLocal)
	mux.HandleFunc("GET /logged-out", a.handleLoggedOut)
	mux.HandleFunc("GET /frontchannel-logout", a.handleFrontChannelLogout)
	mux.HandleFunc("POST /backchannel-logout", a.handleBackChannelLogout)

	mux.HandleFunc("GET /inspector", a.handleInspector)
	mux.HandleFunc("GET /inspector/events", a.handleInspectorEvents)
	mux.HandleFunc("POST /inspector/clear", a.handleInspectorClear)

	return mux
}

// ---- helpers ----

func (a *App) render(w http.ResponseWriter, name string, data map[string]any) {
	if data == nil {
		data = map[string]any{}
	}
	data["Config"] = a.cfg
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl := template.Must(a.tmpl.Clone())
	if _, err := tmpl.ParseFiles("templates/" + name); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "layout", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (a *App) currentSession(r *http.Request) (*AppSession, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return nil, false
	}
	return a.store.getSession(c.Value)
}

func (a *App) discover() (*Discovery, error) {
	disc, raw, err := fetchDiscovery(a.cfg.Issuer)
	if err != nil {
		a.store.log("discovery.error", "failed to fetch discovery document", nil, raw)
		return nil, err
	}
	a.store.log("discovery.response", "GET "+a.cfg.Issuer+"/.well-known/openid-configuration", disc, raw)
	return disc, nil
}

func (a *App) jwks(disc *Discovery) (*jwksHolder, error) {
	set, raw, err := fetchJWKS(disc.JWKSURI)
	if err != nil {
		a.store.log("jwks.error", "failed to fetch JWKS", nil, raw)
		return nil, err
	}
	a.store.log("jwks.response", "GET "+disc.JWKSURI, nil, raw)
	return &jwksHolder{set: set}, nil
}

func fail(w http.ResponseWriter, a *App, title string, err error) {
	a.render(w, "error.html", map[string]any{
		"Title": title,
		"Error": err.Error(),
	})
}

// discoverOrFail fetches discovery and, on success, checks that the given
// capability predicate holds; both failure modes render the same error
// page so every flow entry point gets consistent handling.
func (a *App) discoverOrFail(w http.ResponseWriter, title string, need func(Capabilities) (bool, string)) (*Discovery, bool) {
	disc, err := a.discover()
	if err != nil {
		fail(w, a, title, err)
		return nil, false
	}
	if need != nil {
		if ok, msg := need(disc.Capabilities()); !ok {
			fail(w, a, title, fmt.Errorf("%s", msg))
			return nil, false
		}
	}
	return disc, true
}

// ---- home ----

func (a *App) handleHome(w http.ResponseWriter, r *http.Request) {
	sess, loggedIn := a.currentSession(r)
	data := map[string]any{
		"LoggedIn":    loggedIn,
		"Session":     sess,
		"ClientCount": len(a.store.allClients()),
	}
	if disc, err := a.discover(); err == nil {
		data["Caps"] = disc.Capabilities()
		data["Discovery"] = disc
	} else {
		data["DiscoveryError"] = err.Error()
	}
	a.render(w, "home.html", data)
}

// ---- dynamic client registration ----

func (a *App) handleRegisterForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, "register.html", a.flowFormData())
}

// handleRegisterSubmit exercises the OP's dynamic client registration
// endpoint directly: it builds a metadata document from the submitted form,
// POSTs it using the supplied initial access token, and displays the raw
// result (including client_id/secret) so it can be copied into any other
// flow's form.
func (a *App) handleRegisterSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, a, "Invalid form", err)
		return
	}
	disc, ok := a.discoverOrFail(w, "Dynamic registration failed", func(c Capabilities) (bool, string) {
		return c.DynamicRegistration, "the connected OP does not advertise a registration_endpoint (dynamic registration is disabled: oidc.registrationEnabled)"
	})
	if !ok {
		return
	}

	iat := strings.TrimSpace(r.FormValue("initial_access_token"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	if redirectURI == "" {
		redirectURI = a.cfg.RedirectURI
	}
	authMethod := r.FormValue("auth_method")
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	grantTypes := r.Form["grant_types"]
	if len(grantTypes) == 0 {
		grantTypes = []string{"authorization_code"}
	}

	metadata := map[string]any{
		"client_name":                "example-rp (dynamically registered)",
		"redirect_uris":              []string{redirectURI},
		"grant_types":                grantTypes,
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": authMethod,
		"post_logout_redirect_uris":  []string{a.cfg.PostLogoutRedirectURI},
		"frontchannel_logout_uri":    a.cfg.FrontChannelLogoutURI,
		"backchannel_logout_uri":     a.cfg.BackChannelLogoutURI,
	}

	result, err := dynamicRegister(a.store, disc, iat, metadata)
	data := map[string]any{"Caps": disc.Capabilities(), "Discovery": disc}
	if err != nil {
		data["RegisterError"] = err.Error()
		data["RegisterResult"] = prettyJSON(result)
		a.render(w, "register.html", data)
		return
	}
	data["RegisterResult"] = prettyJSON(result)

	id, _ := result["client_id"].(string)
	if id == "" {
		data["RegisterError"] = "registration succeeded but the response had no client_id"
		a.render(w, "register.html", data)
		return
	}
	client := &Client{
		ClientID:   id,
		AuthMethod: authMethod,
		Label:      "dynamically registered",
		Source:     "dynamic",
		Metadata:   result,
		Created:    time.Now(),
	}
	if secret, ok := result["client_secret"].(string); ok {
		client.ClientSecret = secret
	}
	if rat, ok := result["registration_access_token"].(string); ok {
		client.RegistrationAccessToken = rat
	}
	if uri, ok := result["registration_client_uri"].(string); ok {
		client.RegistrationClientURI = uri
	}
	a.store.putClient(client)

	data["NewClientID"] = client.ClientID
	data["NewClientSecret"] = client.ClientSecret
	data["NewAuthMethod"] = authMethod
	a.render(w, "register.html", data)
}

// ---- config: saved clients ----

func (a *App) handleConfig(w http.ResponseWriter, r *http.Request) {
	a.render(w, "config.html", a.flowFormData())
}

// handleAddClient saves a client entered by hand - e.g. one created through
// the OP's admin API rather than dynamic registration. No registration
// access token exists for these, so they can't be refreshed/edited later,
// only replaced or deleted.
func (a *App) handleAddClient(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, a, "Invalid form", err)
		return
	}
	id := strings.TrimSpace(r.FormValue("client_id"))
	if id == "" {
		fail(w, a, "Cannot save client", fmt.Errorf("client_id is required"))
		return
	}
	authMethod := r.FormValue("auth_method")
	if authMethod == "" {
		authMethod = "client_secret_basic"
	}
	label := strings.TrimSpace(r.FormValue("label"))
	if label == "" {
		label = "manually added"
	}
	a.store.putClient(&Client{
		ClientID:     id,
		ClientSecret: r.FormValue("client_secret"),
		AuthMethod:   authMethod,
		Label:        label,
		Source:       "manual",
		Created:      time.Now(),
	})
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

// handleRefreshClientRegistration re-fetches a dynamically registered
// client's current metadata from the OP via RFC 7592 (GET
// {registration_client_uri} with the registration access token), so edits
// made on the OP side (or by another tool) are reflected here.
func (a *App) handleRefreshClientRegistration(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	client, ok := a.store.getClient(id)
	if !ok {
		fail(w, a, "Cannot refresh client", fmt.Errorf("unknown client_id %q", id))
		return
	}
	if client.RegistrationAccessToken == "" || client.RegistrationClientURI == "" {
		fail(w, a, "Cannot refresh client", fmt.Errorf("client %q has no registration access token (it wasn't dynamically registered by this app)", id))
		return
	}
	metadata, err := readClientRegistration(a.store, client.RegistrationClientURI, client.RegistrationAccessToken)
	if err != nil {
		fail(w, a, "Refreshing client registration failed", err)
		return
	}
	client.Metadata = metadata
	if secret, ok := metadata["client_secret"].(string); ok && secret != "" {
		client.ClientSecret = secret
	}
	if am, ok := metadata["token_endpoint_auth_method"].(string); ok && am != "" {
		client.AuthMethod = am
	}
	a.store.putClient(client)
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

func (a *App) handleDeleteClient(w http.ResponseWriter, r *http.Request) {
	a.store.deleteClient(r.PathValue("id"))
	http.Redirect(w, r, "/config", http.StatusSeeOther)
}

// flowFormData builds the common data every "configure & start a flow" GET
// page needs: live capabilities (so the form can warn about unsupported
// flows) and the list of saved clients for the picker in "client_picker".
func (a *App) flowFormData() map[string]any {
	data := map[string]any{"Clients": a.store.allClients()}
	if disc, err := a.discover(); err == nil {
		data["Caps"] = disc.Capabilities()
		data["Discovery"] = disc
	} else {
		data["DiscoveryError"] = err.Error()
	}
	return data
}

// ---- authorization_code flow ----

func (a *App) handleAuthCodeForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, "authcode_form.html", a.flowFormData())
}

func (a *App) handleStartAuthCode(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, a, "Invalid form", err)
		return
	}
	offline := r.FormValue("offline_access") == "1"
	disc, ok := a.discoverOrFail(w, "Could not start authorization_code flow", func(c Capabilities) (bool, string) {
		if !c.AuthCode {
			return false, "the connected OP does not advertise authorization_code in grant_types_supported"
		}
		if offline && !c.OfflineAccessScope {
			return false, "the connected OP does not advertise offline_access in scopes_supported; refresh tokens are unavailable"
		}
		return true, ""
	})
	if !ok {
		return
	}

	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	authMethod := r.FormValue("auth_method")
	scopes := strings.TrimSpace(r.FormValue("scopes"))
	if offline {
		scopes = strings.TrimSpace(scopes + " offline_access")
	}

	verifier, challenge := newPKCE()
	state := randomToken(16)
	nonce := randomToken(16)

	a.store.addPending(&PendingAuth{
		State:        state,
		Nonce:        nonce,
		CodeVerifier: verifier,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthMethod:   authMethod,
		Created:      time.Now(),
	})

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {a.cfg.RedirectURI},
		"scope":                 {scopes},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	if offline {
		q.Set("prompt", "consent")
	}

	target := disc.AuthorizationEndpoint + "?" + q.Encode()
	a.store.log("authorize.redirect", "redirecting user-agent to authorization endpoint", map[string]any{
		"state": state, "nonce": nonce, "scope": scopes, "client_id": clientID,
	}, target)

	http.Redirect(w, r, target, http.StatusFound)
}

func (a *App) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a.store.log("callback.received", "authorization response", nil, q.Encode())

	if errCode := q.Get("error"); errCode != "" {
		fail(w, a, "Authorization failed", fmt.Errorf("%s: %s", errCode, q.Get("error_description")))
		return
	}

	state := q.Get("state")
	pending, ok := a.store.takePending(state)
	if !ok {
		fail(w, a, "Callback rejected", fmt.Errorf("unknown or reused state %q", state))
		return
	}

	disc, err := a.discover()
	if err != nil {
		fail(w, a, "Callback failed", err)
		return
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {q.Get("code")},
		"redirect_uri":  {a.cfg.RedirectURI},
		"code_verifier": {pending.CodeVerifier},
	}

	tr, err := a.exchangeWithAuth(disc, form, pending.ClientID, pending.ClientSecret, pending.AuthMethod, "token")
	if err != nil {
		fail(w, a, "Token exchange failed", err)
		return
	}

	a.finishLogin(w, r, disc, pending.ClientID, pending.ClientSecret, pending.AuthMethod, "authorization_code", tr, pending.Nonce)
}

// exchangeWithAuth is a thin, named wrapper around exchangeToken so call
// sites read as "exchange with these credentials" rather than a bare
// function call with five positional string args.
func (a *App) exchangeWithAuth(disc *Discovery, form url.Values, clientID, clientSecret, authMethod, kind string) (*TokenResponse, error) {
	return exchangeToken(a.store, disc, clientID, clientSecret, authMethod, form, kind)
}

// finishLogin verifies the ID token (when present), stores the resulting
// session, and redirects to the profile page.
func (a *App) finishLogin(w http.ResponseWriter, r *http.Request, disc *Discovery, clientID, clientSecret, authMethod, flow string, tr *TokenResponse, expectedNonce string) {
	sess := &AppSession{
		Cookie:       randomToken(24),
		ClientID:     clientID,
		ClientSecret: clientSecret,
		AuthMethod:   authMethod,
		Flow:         flow,
		AccessToken:  tr.AccessToken,
		RefreshToken: tr.RefreshToken,
		TokenType:    tr.TokenType,
		IDToken:      tr.IDToken,
		ExpiresAt:    time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second),
		Created:      time.Now(),
	}

	if tr.IDToken != "" {
		holder, err := a.jwks(disc)
		if err != nil {
			fail(w, a, "Login failed", err)
			return
		}
		claims, err := verifyJWT(tr.IDToken, holder.set, disc.Issuer, clientID)
		if err != nil {
			a.store.log("idtoken.verify.error", "ID token verification failed", claims, err.Error())
			fail(w, a, "ID token verification failed", err)
			return
		}
		if expectedNonce != "" && claims["nonce"] != expectedNonce {
			fail(w, a, "ID token verification failed", fmt.Errorf("nonce mismatch: got %v, want %q", claims["nonce"], expectedNonce))
			return
		}
		a.store.log("idtoken.verified", "ID token signature, issuer, audience and nonce checked", claims, "")
		sess.Claims = claims
		if sub, ok := claims["sub"].(string); ok {
			sess.Subject = sub
		}
		if sid, ok := claims["sid"].(string); ok {
			sess.SID = sid
		}
	}

	a.store.putSession(sess)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sess.Cookie,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/profile", http.StatusFound)
}

// ---- password (ROPC) flow ----

func (a *App) handlePasswordForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, "password_form.html", a.flowFormData())
}

func (a *App) handleStartPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, a, "Invalid form", err)
		return
	}
	disc, ok := a.discoverOrFail(w, "Could not start password flow", func(c Capabilities) (bool, string) {
		return c.Password, "the connected OP does not advertise password in grant_types_supported (it may be disabled: oauth.passwordGrantEnabled)"
	})
	if !ok {
		return
	}

	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	authMethod := r.FormValue("auth_method")

	form := url.Values{
		"grant_type": {"password"},
		"username":   {r.FormValue("username")},
		"password":   {r.FormValue("password")},
		"scope":      {strings.TrimSpace(r.FormValue("scopes"))},
	}
	tr, err := a.exchangeWithAuth(disc, form, clientID, clientSecret, authMethod, "token")
	if err != nil {
		fail(w, a, "Password grant failed", err)
		return
	}
	// ROPC issues no id_token/nonce in this OP; still routed through
	// finishLogin so the resulting access token shows up as a session.
	a.finishLogin(w, r, disc, clientID, clientSecret, authMethod, "password", tr, "")
}

// ---- client_credentials flow ----

func (a *App) handleClientCredentialsForm(w http.ResponseWriter, r *http.Request) {
	a.render(w, "client_credentials_form.html", a.flowFormData())
}

func (a *App) handleStartClientCredentials(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		fail(w, a, "Invalid form", err)
		return
	}
	disc, ok := a.discoverOrFail(w, "Could not start client_credentials flow", func(c Capabilities) (bool, string) {
		return c.ClientCredentials, "the connected OP does not advertise client_credentials in grant_types_supported"
	})
	if !ok {
		return
	}

	clientID := strings.TrimSpace(r.FormValue("client_id"))
	clientSecret := r.FormValue("client_secret")
	authMethod := r.FormValue("auth_method")

	form := url.Values{
		"grant_type": {"client_credentials"},
		"resource":   {strings.TrimSpace(r.FormValue("resource"))},
	}
	tr, err := a.exchangeWithAuth(disc, form, clientID, clientSecret, authMethod, "token")
	if err != nil {
		fail(w, a, "Client credentials grant failed", err)
		return
	}
	// Machine tokens are not tied to a browser session; show the raw
	// result directly rather than pretending there's a login.
	a.render(w, "machine_token.html", map[string]any{
		"Token": tr,
	})
}

// ---- refresh_token ----

func (a *App) handleRefresh(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.currentSession(r)
	if !ok || sess.RefreshToken == "" {
		fail(w, a, "Cannot refresh", fmt.Errorf("no active session with a refresh token"))
		return
	}
	disc, ok2 := a.discoverOrFail(w, "Refresh failed", func(c Capabilities) (bool, string) {
		return c.RefreshToken, "the connected OP does not advertise refresh_token in grant_types_supported"
	})
	if !ok2 {
		return
	}

	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {sess.RefreshToken},
	}
	tr, err := a.exchangeWithAuth(disc, form, sess.ClientID, sess.ClientSecret, sess.AuthMethod, "refresh")
	if err != nil {
		fail(w, a, "Refresh failed", err)
		return
	}
	// Refresh does not re-issue an id_token; keep existing claims/subject.
	sess.AccessToken = tr.AccessToken
	sess.TokenType = tr.TokenType
	sess.ExpiresAt = time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	if tr.RefreshToken != "" {
		sess.RefreshToken = tr.RefreshToken
	}
	a.store.putSession(sess)
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

// ---- profile / userinfo / introspect / revoke ----

func (a *App) handleProfile(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	a.render(w, "profile.html", map[string]any{
		"Session":      sess,
		"ClaimsJSON":   prettyJSON(sess.Claims),
		"UserInfoJSON": prettyJSON(sess.UserInfo),
	})
}

func (a *App) handleUserInfoRefresh(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	disc, err := a.discover()
	if err != nil {
		fail(w, a, "UserInfo request failed", err)
		return
	}
	info, err := fetchUserInfo(a.store, disc.UserInfoEndpoint, sess.AccessToken)
	if err != nil {
		fail(w, a, "UserInfo request failed", err)
		return
	}
	sess.UserInfo = info
	a.store.putSession(sess)
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func (a *App) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	disc, ok2 := a.discoverOrFail(w, "Introspection failed", func(c Capabilities) (bool, string) {
		return c.Introspection, "the connected OP does not advertise an introspection_endpoint"
	})
	if !ok2 {
		return
	}
	if _, err := introspectToken(a.store, disc, sess.ClientID, sess.ClientSecret, sess.AccessToken); err != nil {
		fail(w, a, "Introspection failed", err)
		return
	}
	http.Redirect(w, r, "/inspector", http.StatusSeeOther)
}

func (a *App) handleRevoke(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	disc, ok2 := a.discoverOrFail(w, "Revocation failed", func(c Capabilities) (bool, string) {
		return c.Revocation, "the connected OP does not advertise a revocation_endpoint"
	})
	if !ok2 {
		return
	}
	if err := revokeToken(a.store, disc, sess.ClientID, sess.ClientSecret, sess.AccessToken, "access_token"); err != nil {
		fail(w, a, "Revocation failed", err)
		return
	}
	http.Redirect(w, r, "/inspector", http.StatusSeeOther)
}

// ---- logout ----

// handleLogoutRPInitiated sends the browser to the OP's /logout endpoint
// (RP-initiated / "front-channel" logout in the OIDC sense), which will
// show its own confirmation page before ending the OP session and firing
// front/back-channel notifications back to this app.
func (a *App) handleLogoutRPInitiated(w http.ResponseWriter, r *http.Request) {
	sess, ok := a.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	disc, ok2 := a.discoverOrFail(w, "Logout failed", func(c Capabilities) (bool, string) {
		return c.EndSession, "the connected OP does not advertise an end_session_endpoint"
	})
	if !ok2 {
		return
	}
	q := url.Values{
		"post_logout_redirect_uri": {a.cfg.PostLogoutRedirectURI},
		"state":                    {"rp-initiated-" + randomToken(8)},
	}
	if sess.IDToken != "" {
		q.Set("id_token_hint", sess.IDToken)
	} else {
		q.Set("client_id", sess.ClientID)
	}
	target := disc.EndSessionEndpoint + "?" + q.Encode()
	a.store.log("logout.redirect", "redirecting user-agent to end_session_endpoint", nil, target)
	http.Redirect(w, r, target, http.StatusFound)
}

// handleLogoutLocal ends only this app's own session, without telling the
// OP anything - useful for contrasting "app logout" with "provider logout".
func (a *App) handleLogoutLocal(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookieName); err == nil {
		a.store.deleteSession(c.Value)
		a.store.log("logout.local", "local session cleared without contacting the OP", nil, "")
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *App) handleLoggedOut(w http.ResponseWriter, r *http.Request) {
	a.store.log("logout.post_redirect", "landed on post_logout_redirect_uri", nil, r.URL.RawQuery)
	a.render(w, "logged_out.html", map[string]any{
		"Query": r.URL.Query(),
	})
}

// handleFrontChannelLogout is this RP's own frontchannel_logout_uri: the OP
// loads it in a hidden iframe (per spec, with iss/sid query params) after
// the user confirms logout. It must clear the local session synchronously
// and return quickly, without redirecting.
func (a *App) handleFrontChannelLogout(w http.ResponseWriter, r *http.Request) {
	iss := r.URL.Query().Get("iss")
	sid := r.URL.Query().Get("sid")

	found := false
	if iss == a.cfg.Issuer && sid != "" {
		found = a.store.deleteBySID(sid)
	}
	a.store.log("frontchannel-logout.received", fmt.Sprintf("iss=%s sid=%s matched=%v", iss, sid, found), nil, r.URL.RawQuery)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><body style="font:12px monospace">frontchannel-logout ok (matched=%v)</body>`, found)
}

// handleBackChannelLogout is this RP's own backchannel_logout_uri: the OP
// POSTs a signed logout_token here server-to-server. Must verify the JWT
// and respond 200 for the OP to consider it delivered. The token's aud
// claim tells us which client it was issued for, so no session lookup by
// client is needed before verifying.
func (a *App) handleBackChannelLogout(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	raw := r.FormValue("logout_token")
	a.store.log("backchannel-logout.received", "POST /backchannel-logout", nil, raw)
	if raw == "" {
		http.Error(w, "missing logout_token", http.StatusBadRequest)
		return
	}

	disc, err := a.discover()
	if err != nil {
		http.Error(w, "discovery failed", http.StatusInternalServerError)
		return
	}
	holder, err := a.jwks(disc)
	if err != nil {
		http.Error(w, "jwks failed", http.StatusInternalServerError)
		return
	}
	claims, err := verifyLogoutToken(raw, holder.set, disc.Issuer)
	if err != nil {
		a.store.log("backchannel-logout.invalid", "logout token verification failed", claims, err.Error())
		http.Error(w, "invalid logout token", http.StatusBadRequest)
		return
	}

	sid, _ := claims["sid"].(string)
	found := a.store.deleteBySID(sid)
	a.store.log("backchannel-logout.verified", fmt.Sprintf("sid=%s matched local session=%v", sid, found), claims, "")

	w.WriteHeader(http.StatusOK)
}

// ---- inspector ----

func (a *App) handleInspector(w http.ResponseWriter, r *http.Request) {
	a.render(w, "inspector.html", map[string]any{
		"Events":   a.store.recentEvents(),
		"Sessions": a.store.allSessions(),
	})
}

// handleInspectorEvents returns the event log as JSON for the auto-refresh
// script on the inspector page (simple polling, no need for websockets in a
// test tool like this).
func (a *App) handleInspectorEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(a.store.recentEvents())
}

func (a *App) handleInspectorClear(w http.ResponseWriter, r *http.Request) {
	a.store.clearEvents()
	http.Redirect(w, r, "/inspector", http.StatusSeeOther)
}

type jwksHolder struct{ set *jose.JSONWebKeySet }
