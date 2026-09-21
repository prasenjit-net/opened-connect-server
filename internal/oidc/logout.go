package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

const logoutBindingCookie = "ocs_logout_binding"

func metadataString(c identity.ClientRecord, key string) string {
	var v string
	_ = json.Unmarshal(c.Metadata[key], &v)
	return v
}
func metadataList(c identity.ClientRecord, key string) []string {
	var v []string
	_ = json.Unmarshal(c.Metadata[key], &v)
	return v
}

// Hints identify a previously issued login, never authorize an account-wide logout.
func (s *Service) logoutHint(ctx context.Context, raw, clientID string) (string, error) {
	token, e := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if e != nil {
		return "", e
	}
	var claims jwt.Claims
	var extra struct {
		SID string `json:"sid"`
	}
	if len(token.Headers) != 1 || token.Headers[0].ExtraHeaders["typ"] != "JWT" {
		return "", errors.New("invalid hint type")
	}
	verified := false
	for _, key := range s.Keys.PublicJWKS().Keys {
		if token.Claims(key.Key, &claims, &extra) == nil {
			verified = true
			break
		}
	}
	if !verified || claims.Issuer != s.Config.Issuer || claims.Subject == "" || claims.Expiry == nil || claims.IssuedAt == nil || claims.IssuedAt.Time().After(s.Now().Add(time.Minute)) || len(claims.Audience) != 1 {
		return "", errors.New("invalid hint")
	}
	if clientID != "" && claims.Audience[0] != clientID {
		return "", errors.New("client mismatch")
	}
	// The normal confirmation is mandatory even for valid hints. Reject hints
	// unrelated to a known current/recent association when a sid is present.
	if extra.SID != "" {
		e = s.Store.Read(ctx, func(tx identity.ReadTx) error {
			a, e := tx.AppSession(extra.SID)
			if e != nil || a.ClientID != claims.Audience[0] || a.Subject != claims.Subject || (!a.EndedAt.IsZero() && s.Now().Sub(a.EndedAt) > 7*24*time.Hour) {
				return errors.New("unknown hint session")
			}
			return nil
		})
		if e != nil {
			return "", e
		}
	}
	if extra.SID == "" && !s.Now().Before(claims.Expiry.Time()) {
		return "", errors.New("unbound expired hint")
	}
	return claims.Audience[0], nil
}

func (s *Service) prepareLogout(w http.ResponseWriter, r *http.Request, opID, userID, appID, clientID, redirect, state string, completed bool) (string, error) {
	id, e := randomToken()
	if e != nil {
		return "", e
	}
	binding, e := randomToken()
	if e != nil {
		return "", e
	}
	csrf, e := randomToken()
	if e != nil {
		return "", e
	}
	v := identity.LogoutInteraction{ClientID: clientID, AppSessionID: appID, ID: id, BindingHash: hashToken(binding), CSRF: csrf, OPSessionID: opID, UserID: userID, RedirectURI: redirect, State: state, ExpiresAt: s.Now().Add(10 * time.Minute), Completed: completed}
	e = s.Store.Write(r.Context(), func(tx identity.Tx) error {
		tx.PruneLogoutState(s.Now())
		if e := tx.CheckSessionCapacity("interaction"); e != nil {
			return e
		}
		tx.SaveLogoutInteraction(v)
		return nil
	})
	if e != nil {
		return "", e
	}
	http.SetCookie(w, &http.Cookie{Name: logoutBindingCookie, Value: binding, Path: "/logout", HttpOnly: true, Secure: s.Config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: 600}) // NOSONAR: CookieSecure is explicitly configured for HTTPS and loopback development.
	return "/logout/interaction/" + id, nil
}

// PrepareLogout is used by the authenticated first-party API after CSRF checks.
func (s *Service) PrepareLogout(w http.ResponseWriter, r *http.Request, p identity.Principal, completed bool) (string, error) {
	return s.prepareLogout(w, r, p.Session.ID, p.User.ID, "", "", "", "", completed)
}

// PrepareAppLogout permits browser completion only for this browser's association.
func (s *Service) PrepareAppLogout(w http.ResponseWriter, r *http.Request, p identity.Principal, id string) (string, error) {
	var a identity.AppSession
	e := s.Store.Read(r.Context(), func(tx identity.ReadTx) error { var e error; a, e = tx.AppSession(id); return e })
	if e != nil {
		return "", e
	}
	if a.OPSessionID != p.Session.ID || a.UserID != p.User.ID {
		return "", nil
	}
	return s.prepareLogout(w, r, p.Session.ID, p.User.ID, id, "", "", "", true)
}

func (s *Service) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if !s.allowTraffic(w, r, "logout") {
		return
	}
	form, e := parseProtocolForm(r)
	if e != nil {
		writeOAuthError(w, 400, "invalid_request", "Invalid logout parameters.")
		return
	}
	clientID := form.Get("client_id")
	if raw := form.Get("id_token_hint"); raw != "" {
		clientID, e = s.logoutHint(r.Context(), raw, clientID)
		if e != nil {
			writeOAuthError(w, 400, "invalid_request", "Invalid logout hint.")
			return
		}
	}
	redirect := form.Get("post_logout_redirect_uri")
	if clientID != "" || redirect != "" {
		e = s.Store.Read(r.Context(), func(tx identity.ReadTx) error {
			c, e := tx.Client(clientID)
			if e != nil {
				return e
			}
			if redirect != "" {
				for _, u := range metadataList(c, "post_logout_redirect_uris") {
					if redirect == u && (strings.HasPrefix(u, "https://") || s.Config.RegistrationAllowHTTP) {
						return nil
					}
				}
				return errors.New("unregistered return URI")
			}
			return nil
		})
		if e != nil {
			writeOAuthError(w, 400, "invalid_request", "Invalid logout client or return URI.")
			return
		}
	}
	opID, userID := "", ""
	if p, e := s.currentPrincipal(r); e == nil {
		opID, userID = p.Session.ID, p.User.ID
	}
	path, e := s.prepareLogout(w, r, opID, userID, "", clientID, redirect, form.Get("state"), false)
	if e != nil {
		writeOAuthError(w, 503, "server_error", "Unable to prepare logout.")
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

type logoutPageData struct {
	Title, Message, Action, CSRF, Return string
	Confirm                              bool
	Frames                               []string
}

var logoutPage = template.Must(template.New("logout").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title><link rel="stylesheet" href="/logout/style.css"></head><body><main><h1>{{.Title}}</h1><p>{{.Message}}</p>{{if .Confirm}}<form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><button name="decision" value="logout">Sign out of this provider session and connected apps</button> <button name="decision" value="cancel">Cancel</button></form>{{end}}{{range .Frames}}<iframe title="Application logout" src="{{.}}" hidden></iframe>{{end}}{{if .Return}}<p><a href="{{.Return}}">Continue</a></p>{{end}}</main></body></html>`))

func renderLogout(w http.ResponseWriter, data logoutPageData) {
	origins := []string{}
	for _, raw := range data.Frames {
		u, e := url.Parse(raw)
		if e == nil {
			origins = append(origins, u.Scheme+"://"+u.Host)
		}
	}
	frames := "'none'"
	if len(origins) > 0 {
		frames = strings.Join(origins, " ")
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; frame-src "+frames+"; frame-ancestors 'none'; base-uri 'none'")
	_ = logoutPage.Execute(w, data)
}
func (s *Service) LogoutInteractionHandler(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	cookie, e := r.Cookie(logoutBindingCookie)
	if e != nil {
		writeOAuthError(w, 400, "invalid_request", "Logout interaction expired. Start again.")
		return
	}
	var v identity.LogoutInteraction
	e = s.Store.Read(r.Context(), func(tx identity.ReadTx) error {
		var e error
		v, e = tx.LogoutInteraction(id)
		if e != nil || !s.Now().Before(v.ExpiresAt) || subtle.ConstantTimeCompare([]byte(v.BindingHash), []byte(hashToken(cookie.Value))) != 1 {
			return identity.ErrUnauthorized
		}
		return nil
	})
	if e != nil {
		writeOAuthError(w, 400, "invalid_request", "Logout interaction expired. Start again.")
		return
	}
	// Cross-site POSTs can omit a Lax session cookie. Bind only after the safe
	// top-level GET, and never take a target user/session from request parameters.
	if v.OPSessionID == "" && !v.Completed {
		if p, e := s.currentPrincipal(r); e == nil {
			v.OPSessionID = p.Session.ID
			v.UserID = p.User.ID
			e = s.Store.Write(r.Context(), func(tx identity.Tx) error { tx.SaveLogoutInteraction(v); return nil })
			if e != nil {
				writeOAuthError(w, 503, "server_error", "Unable to prepare logout.")
				return
			}
		}
	}
	if r.Method == "POST" {
		form, e := parseProtocolForm(r)
		if e != nil || subtle.ConstantTimeCompare([]byte(form.Get("csrf")), []byte(v.CSRF)) != 1 {
			writeOAuthError(w, 403, "invalid_request", "Invalid logout confirmation.")
			return
		}
		if form.Get("decision") == "cancel" {
			_ = s.Store.Write(r.Context(), func(tx identity.Tx) error { v.ExpiresAt = s.Now(); tx.SaveLogoutInteraction(v); return nil })
			renderLogout(w, logoutPageData{Title: "Logout cancelled", Message: "Your provider session remains signed in.", Return: "/"})
			return
		}
		if p, e := s.currentPrincipal(r); e == nil && v.OPSessionID != "" && p.Session.ID != v.OPSessionID {
			writeOAuthError(w, 400, "invalid_request", "The signed-in session changed. Start logout again.")
			return
		}
		if form.Get("decision") != "logout" {
			writeOAuthError(w, 400, "invalid_request", "Invalid decision.")
			return
		}
		e = s.Store.Write(r.Context(), func(tx identity.Tx) error {
			current, e := tx.LogoutInteraction(id)
			if e != nil || current.Completed || !s.Now().Before(current.ExpiresAt) {
				return identity.ErrUnauthorized
			}
			if v.OPSessionID != "" {
				tx.EndSession(v.OPSessionID, v.UserID, "browser_logout", s.Now())
			}
			current.Completed = true
			tx.SaveLogoutInteraction(current)
			return nil
		})
		if e != nil {
			writeOAuthError(w, 400, "invalid_request", "Logout interaction already completed or expired.")
			return
		}
		// Attempt the initiating RP before showing the return link. Slow RPs
		// cannot hold the browser flow open; durable leases/retries finish later.
		if v.OPSessionID != "" {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			_ = s.processLogoutDelivery(ctx, v.OPSessionID, v.ClientID)
			cancel()
		}
		// Do not clear a different account's cookie after an account switch.
		if p, e := s.currentPrincipal(r); e == nil && p.Session.ID != v.OPSessionID {
		} else {
		http.SetCookie(w, &http.Cookie{Name: identity.SessionCookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.Config.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1}) // NOSONAR: CookieSecure is explicitly configured for HTTPS and loopback development.
		}
		http.Redirect(w, r, "/logout/interaction/"+id, http.StatusSeeOther)
		return
	}
	if !v.Completed {
		renderLogout(w, logoutPageData{Title: "Sign out", Message: "End this provider session and request logout from connected apps. Approved offline access is preserved.", Action: "/logout/interaction/" + id, CSRF: v.CSRF, Confirm: true})
		return
	}
	frames := []string{}
	e = s.Store.Write(r.Context(), func(tx identity.Tx) error {
		for _, d := range tx.ListLogoutDeliveries() {
			if (d.OPSessionID != v.OPSessionID || (v.AppSessionID != "" && d.AppSessionID != v.AppSessionID)) || d.Channel != "frontchannel" || d.Status != "browser_unavailable" {
				continue
			}
			if c, e := tx.Client(d.ClientID); e == nil && metadataString(c, "frontchannel_logout_uri") != d.Endpoint {
				d.Status = "failed"
				d.ErrorCode = "destination_changed"
				d.UpdatedAt = s.Now()
				tx.SaveLogoutDelivery(d)
				continue
			}
			u, e := url.Parse(d.Endpoint)
			if e != nil || (u.Scheme != "https" && !s.Config.RegistrationAllowHTTP) {
				continue
			}
			q := u.Query()
			q.Set("iss", s.Config.Issuer)
			q.Set("sid", d.AppSessionID)
			u.RawQuery = q.Encode()
			frames = append(frames, u.String())
			d.Status = "unconfirmed"
			d.UpdatedAt = s.Now()
			tx.SaveLogoutDelivery(d)
		}
		return nil
	})
	if e != nil {
		writeOAuthError(w, 503, "server_error", "Unable to load logout status.")
		return
	}
	next := "/login"
	if v.RedirectURI != "" {
		u, _ := url.Parse(v.RedirectURI)
		q := u.Query()
		if v.State != "" {
			q.Set("state", v.State)
		}
		u.RawQuery = q.Encode()
		next = u.String()
	}
	if v.AppSessionID != "" {
		renderLogout(w, logoutPageData{Title: "App session ended", Message: "This app association has ended at the provider. Notifications may still be pending or unconfirmed. Your provider session remains signed in.", Frames: frames, Return: "/sessions"})
		return
	}
	renderLogout(w, logoutPageData{Title: "Signed out", Message: "The provider session has ended. App notifications may still be pending. Browser logout requests cannot confirm that an app cleared its session. You can continue safely; server notifications retry in the background.", Frames: frames, Return: next})
}
