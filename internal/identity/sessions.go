package identity

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
)

// AppSession records provider participation, not the RP's private cookie state.
type AppSession struct {
	ID          string    `json:"id"`
	OPSessionID string    `json:"opSessionId"`
	ClientID    string    `json:"clientId"`
	UserID      string    `json:"userId"`
	Subject     string    `json:"subject"`
	CreatedAt   time.Time `json:"createdAt"`
	LastSeenAt  time.Time `json:"lastSeenAt"`
	EndedAt     time.Time `json:"endedAt,omitempty"`
	EndReason   string    `json:"endReason,omitempty"`
}

type LogoutAttempt struct {
	At         time.Time `json:"at"`
	HTTPStatus int       `json:"httpStatus,omitempty"`
	ErrorCode  string    `json:"errorCode,omitempty"`
}

type LogoutDelivery struct {
	History      []LogoutAttempt `json:"history,omitempty"`
	ID           string          `json:"id"`
	OPSessionID  string          `json:"opSessionId"`
	AppSessionID string          `json:"appSessionId,omitempty"`
	ClientID     string          `json:"clientId,omitempty"`
	UserID       string          `json:"userId"`
	Subject      string          `json:"subject,omitempty"`
	Actor        string          `json:"actor"`
	Reason       string          `json:"reason"`
	Channel      string          `json:"channel"`
	Status       string          `json:"status"`
	Endpoint     string          `json:"endpoint,omitempty"`
	CreatedAt    time.Time       `json:"createdAt"`
	UpdatedAt    time.Time       `json:"updatedAt"`
	NextAttempt  time.Time       `json:"nextAttempt"`
	LeaseUntil   time.Time       `json:"leaseUntil"`
	LeaseID      string          `json:"leaseId,omitempty"`
	Attempts     int             `json:"attempts"`
	HTTPStatus   int             `json:"httpStatus,omitempty"`
	ErrorCode    string          `json:"errorCode,omitempty"`
}

type LogoutInteraction struct {
	ClientID     string    `json:"clientId,omitempty"`
	AppSessionID string    `json:"appSessionId,omitempty"`
	ID           string    `json:"id"`
	BindingHash  string    `json:"bindingHash"`
	CSRF         string    `json:"csrf"`
	OPSessionID  string    `json:"opSessionId"`
	UserID       string    `json:"userId"`
	RedirectURI  string    `json:"redirectUri,omitempty"`
	State        string    `json:"state,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Completed    bool      `json:"completed"`
}

func (s *fileState) ListSessions() []Session {
	out := []Session{}
	for _, v := range s.Sessions {
		out = append(out, v)
	}
	return out
}
func (s *fileState) ListAppSessions() []AppSession {
	out := []AppSession{}
	for _, v := range s.AppSessions {
		out = append(out, v)
	}
	return out
}
func (s *fileState) AppSession(id string) (AppSession, error) {
	v, ok := s.AppSessions[id]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (s *fileState) SaveAppSession(v AppSession) {
	if s.AppSessions == nil {
		s.AppSessions = map[string]AppSession{}
	}
	s.AppSessions[v.ID] = v
}
func (s *fileState) ListLogoutDeliveries() []LogoutDelivery {
	out := []LogoutDelivery{}
	for _, v := range s.LogoutDeliveries {
		v.History = append([]LogoutAttempt{}, v.History...)
		out = append(out, v)
	}
	return out
}
func (s *fileState) SaveLogoutDelivery(v LogoutDelivery) {
	if s.LogoutDeliveries == nil {
		s.LogoutDeliveries = map[string]LogoutDelivery{}
	}
	v.History = append([]LogoutAttempt{}, v.History...)
	s.LogoutDeliveries[v.ID] = v
}
func (s *fileState) LogoutInteraction(id string) (LogoutInteraction, error) {
	v, ok := s.LogoutInteractions[id]
	if !ok {
		return v, ErrNotFound
	}
	return v, nil
}
func (s *fileState) SaveLogoutInteraction(v LogoutInteraction) {
	if s.LogoutInteractions == nil {
		s.LogoutInteractions = map[string]LogoutInteraction{}
	}
	s.LogoutInteractions[v.ID] = v
}

func SessionByID(tx ReadTx, id string) (Session, error) {
	for _, v := range tx.ListSessions() {
		if v.ID == id {
			return v, nil
		}
	}
	return Session{}, ErrNotFound
}
func SessionActive(tx ReadTx, id string, now time.Time) bool {
	v, e := SessionByID(tx, id)
	return e == nil && v.EndedAt.IsZero() && now.Before(v.ExpiresAt)
}

func (s *fileState) EndSession(id, actor, reason string, now time.Time) {
	for hash, v := range s.Sessions {
		if v.ID != id || !v.EndedAt.IsZero() {
			continue
		}
		v.EndedAt = now
		v.EndReason = reason
		v.CSRF = ""
		s.Sessions[hash] = v
		s.SaveLogoutDelivery(LogoutDelivery{ID: "op-" + id, OPSessionID: id, UserID: v.UserID, Actor: actor, Reason: reason, Channel: "local", Status: "ended", CreatedAt: now, UpdatedAt: now})
		for _, a := range s.AppSessions {
			if a.OPSessionID == id {
				s.EndAppSession(a.ID, actor, reason, now)
			}
		}
		for k, t := range s.AuthzTransactions {
			if t.OPSessionID == id {
				t.Revoked = true
				s.AuthzTransactions[k] = t
			}
		}
		for k, c := range s.AuthorizationCodes {
			if c.OPSessionID == id {
				c.Revoked = true
				s.AuthorizationCodes[k] = c
			}
		}
	}
}
func (s *fileState) EndAppSession(id, actor, reason string, now time.Time) {
	a, ok := s.AppSessions[id]
	if !ok || !a.EndedAt.IsZero() {
		return
	}
	a.EndedAt = now
	a.EndReason = reason
	s.AppSessions[id] = a
	for k, t := range s.AccessTokens {
		if t.AppSessionID == id && t.FamilyID == "" {
			t.Revoked = true
			s.AccessTokens[k] = t
		}
	}
	for k, c := range s.AuthorizationCodes {
		if c.OPSessionID == a.OPSessionID && c.ClientID == a.ClientID {
			c.Revoked = true
			s.AuthorizationCodes[k] = c
		}
	}
	for k, t := range s.AuthzTransactions {
		if t.OPSessionID == a.OPSessionID && t.ClientID == a.ClientID {
			t.Revoked = true
			s.AuthzTransactions[k] = t
		}
	}
	c := s.ClientsMap[a.ClientID]
	supported := false
	for _, channel := range []string{"backchannel", "frontchannel"} {
		endpoint := c.Metadata.text(channel + "_logout_uri")
		if endpoint == "" {
			continue
		}
		supported = true
		status := "pending"
		if channel == "frontchannel" {
			status = "browser_unavailable"
		}
		s.SaveLogoutDelivery(LogoutDelivery{ID: id + "-" + channel, OPSessionID: a.OPSessionID, AppSessionID: id, ClientID: a.ClientID, UserID: a.UserID, Subject: a.Subject, Actor: actor, Reason: reason, Channel: channel, Status: status, Endpoint: endpoint, CreatedAt: now, UpdatedAt: now, NextAttempt: now})
	}
	if !supported {
		s.SaveLogoutDelivery(LogoutDelivery{ID: id + "-unsupported", OPSessionID: a.OPSessionID, AppSessionID: id, ClientID: a.ClientID, UserID: a.UserID, Actor: actor, Reason: reason, Channel: "none", Status: "unsupported", CreatedAt: now, UpdatedAt: now})
	}
}
func (s *fileState) PruneLogoutState(now time.Time) {
	s.PruneSessions(now)
	cutoff := now.Add(-30 * 24 * time.Hour)
	for id, op := range s.LogoutOperations {
		if op.CreatedAt.Before(cutoff) {
			delete(s.LogoutOperations, id)
		}
	}
	for k, v := range s.LogoutInteractions {
		if !now.Before(v.ExpiresAt) {
			delete(s.LogoutInteractions, k)
		}
	}
	for k, v := range s.LogoutDeliveries {
		if v.CreatedAt.Before(cutoff) {
			delete(s.LogoutDeliveries, k)
		}
	}
	for k, v := range s.AppSessions {
		if !v.EndedAt.IsZero() && v.EndedAt.Before(cutoff) {
			delete(s.AppSessions, k)
		}
	}
	for k, v := range s.Sessions {
		if !v.EndedAt.IsZero() && v.EndedAt.Before(cutoff) {
			delete(s.Sessions, k)
		}
	}
}

// SessionActivity contains public display fields only. Credential material and
// destination URLs are intentionally absent, even for administrators.
type SessionActivity struct {
	ErrorCode        string          `json:"errorCode,omitempty"`
	NextAttempt      time.Time       `json:"nextAttempt"`
	History          []LogoutAttempt `json:"history,omitempty"`
	ID               string          `json:"id"`
	Kind             string          `json:"kind"`
	UserID           string          `json:"userId"`
	UserName         string          `json:"userName"`
	ClientID         string          `json:"clientId,omitempty"`
	ClientName       string          `json:"clientName,omitempty"`
	OPSessionID      string          `json:"opSessionId,omitempty"`
	Status           string          `json:"status"`
	Current          bool            `json:"current"`
	Device           string          `json:"device,omitempty"`
	CreatedAt        time.Time       `json:"createdAt"`
	LastSeenAt       time.Time       `json:"lastSeenAt"`
	ExpiresAt        time.Time       `json:"expiresAt"`
	EndedAt          time.Time       `json:"endedAt"`
	Reason           string          `json:"reason,omitempty"`
	Actor            string          `json:"actor,omitempty"`
	Channel          string          `json:"channel,omitempty"`
	Attempts         int             `json:"attempts,omitempty"`
	HTTPStatus       int             `json:"httpStatus,omitempty"`
	AppCount         int             `json:"appCount"`
	DeliveryStatuses []string        `json:"deliveryStatuses"`
}
type SessionActivityList struct {
	Records  []SessionActivity `json:"records"`
	Total    int               `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"pageSize"`
}

func (s *Service) SessionActivity(ctx context.Context, hash, kind string, admin bool, opts ActivityOptions) (SessionActivityList, error) {
	result := SessionActivityList{Records: []SessionActivity{}, Page: opts.Page, PageSize: 10}
	if result.Page < 1 {
		result.Page = 1
	}
	err := s.store.Read(ctx, func(tx ReadTx) error {
		p, e := s.principal(tx, hash, admin)
		if e != nil {
			return e
		}
		rows := []SessionActivity{}
		now := s.now()
		add := func(r SessionActivity) {
			if !admin && r.UserID != p.User.ID {
				return
			}
			if u, e := tx.User(r.UserID); e == nil {
				r.UserName = u.Name
			}
			if c, e := tx.Client(r.ClientID); e == nil {
				r.ClientName = c.Metadata.text("client_name")
			}
			if r.DeliveryStatuses == nil {
				r.DeliveryStatuses = []string{}
			}
			r.Current = r.OPSessionID == p.Session.ID
			if opts.Status != "" && r.Status != opts.Status {
				return
			}
			if opts.Query != "" && !strings.Contains(strings.ToLower(strings.Join([]string{r.ID, r.UserID, r.UserName, r.ClientID, r.ClientName, r.OPSessionID}, " ")), strings.ToLower(opts.Query)) {
				return
			}
			rows = append(rows, r)
		}
		switch kind {
		case "op-sessions":
			for _, v := range tx.ListSessions() {
				status := "active"
				if !v.EndedAt.IsZero() {
					status = "ended"
				}
				if v.EndReason == "expired" || (v.EndedAt.IsZero() && !now.Before(v.ExpiresAt)) {
					status = "expired"
				}
				r := SessionActivity{ID: v.ID, Kind: kind, UserID: v.UserID, OPSessionID: v.ID, Status: status, Device: v.Device, CreatedAt: v.CreatedAt, LastSeenAt: v.LastSeenAt, ExpiresAt: v.ExpiresAt, EndedAt: v.EndedAt, Reason: v.EndReason}
				for _, a := range tx.ListAppSessions() {
					if a.OPSessionID == v.ID {
						r.AppCount++
					}
				}
				add(r)
			}
		case "app-sessions":
			for _, a := range tx.ListAppSessions() {
				status := "active"
				if !a.EndedAt.IsZero() {
					status = "ended"
				} else if !SessionActive(tx, a.OPSessionID, now) {
					status = "expired"
				}
				r := SessionActivity{ID: a.ID, Kind: kind, UserID: a.UserID, ClientID: a.ClientID, OPSessionID: a.OPSessionID, Status: status, CreatedAt: a.CreatedAt, LastSeenAt: a.LastSeenAt, EndedAt: a.EndedAt, Reason: a.EndReason}
				if op, e := SessionByID(tx, a.OPSessionID); e == nil {
					r.ExpiresAt = op.ExpiresAt
				}
				for _, d := range tx.ListLogoutDeliveries() {
					if d.AppSessionID == a.ID {
						r.DeliveryStatuses = append(r.DeliveryStatuses, d.Channel+": "+d.Status)
					}
				}
				sort.Strings(r.DeliveryStatuses)
				add(r)
			}
		case "logout-events":
			for _, d := range tx.ListLogoutDeliveries() {
				r := SessionActivity{ID: d.ID, Kind: kind, UserID: d.UserID, ClientID: d.ClientID, OPSessionID: d.OPSessionID, Status: d.Status, CreatedAt: d.CreatedAt, LastSeenAt: d.UpdatedAt, Reason: d.Reason, Actor: d.Actor, Channel: d.Channel, Attempts: d.Attempts}
				if admin {
					r.HTTPStatus = d.HTTPStatus
					r.ErrorCode = d.ErrorCode
					r.NextAttempt = d.NextAttempt
					r.History = d.History
				}
				add(r)
			}
		default:
			return ErrNotFound
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
				return rows[i].ID < rows[j].ID
			}
			return rows[i].CreatedAt.After(rows[j].CreatedAt)
		})
		result.Total = len(rows)
		pages := (len(rows) + 9) / 10
		if pages < 1 {
			pages = 1
		}
		if result.Page > pages {
			result.Page = pages
		}
		start := (result.Page - 1) * 10
		end := min(start+10, len(rows))
		result.Records = rows[start:end]
		return nil
	})
	return result, err
}

type SessionLogoutRequest struct {
	Scope         string `json:"scope"`
	RevokeOffline bool   `json:"revokeOffline"`
	Password      string `json:"password"`
}

func (s *Service) EndSessions(ctx context.Context, hash, kind, id string, admin bool, in SessionLogoutRequest) error {
	_, e := s.EndSessionsResult(ctx, hash, kind, id, admin, in)
	return e
}
func (s *Service) EndSessionsResult(ctx context.Context, hash, kind, id string, admin bool, in SessionLogoutRequest) (string, error) {
	operation, e := randomToken()
	if e != nil {
		return "", e
	}
	e = s.endSessions(ctx, hash, kind, id, admin, in, operation)
	if e != nil {
		return "", e
	}
	return operation, nil
}
func (s *Service) endSessions(ctx context.Context, hash, kind, id string, admin bool, in SessionLogoutRequest, operationID string) error {
	// Verify expensive credentials before taking the write lock; recheck hash inside.
	var checkedPassword string
	if kind == "client-access" || kind == "user-sessions" || in.Scope == "all" || in.Scope == "other" || in.RevokeOffline {
		err := s.store.Read(ctx, func(tx ReadTx) error {
			p, e := s.principal(tx, hash, admin)
			if e != nil {
				return e
			}
			u, e := tx.User(p.User.ID)
			if e != nil {
				return e
			}
			checkedPassword = u.PasswordHash
			return nil
		})
		if err != nil {
			return err
		}
		if !VerifyPassword(checkedPassword, in.Password) {
			return ErrCredentials
		}
	}
	return s.store.Write(ctx, func(tx Tx) error {
		p, e := s.principal(tx, hash, admin)
		if e != nil {
			return e
		}
		if checkedPassword != "" {
			u, e := tx.User(p.User.ID)
			if e != nil || u.PasswordHash != checkedPassword {
				return ErrUnauthorized
			}
		}
		now := s.now()
		targets := []string{}
		reason := "user_logout"
		if admin {
			reason = "admin_logout"
		}
		switch kind {
		case "op-sessions":
			if id != "" {
				v, e := SessionByID(tx, id)
				if e != nil || (!admin && v.UserID != p.User.ID) {
					return ErrNotFound
				}
				tx.EndSession(id, p.User.ID, reason, now)
				targets = append(targets, id)
				if in.RevokeOffline {
					for _, f := range tx.ListRefreshFamilies() {
						if f.OPSessionID == id {
							tx.RevokeRefreshFamily(f.ID)
						}
					}
				}
				break
			}
			if in.Scope != "all" && in.Scope != "other" {
				return ValidationError("Scope must be all or other.")
			}
			for _, v := range tx.ListSessions() {
				if v.UserID == p.User.ID && (in.Scope != "other" || v.ID != p.Session.ID) {
					tx.EndSession(v.ID, p.User.ID, reason, now)
					targets = append(targets, v.ID)
				}
			}
			if in.RevokeOffline {
				tx.RevokeAccessTokensForUser(p.User.ID)
			}
		case "app-sessions":
			a, e := tx.AppSession(id)
			if e != nil || (!admin && a.UserID != p.User.ID) {
				return ErrNotFound
			}
			tx.EndAppSession(id, p.User.ID, reason, now)
			targets = append(targets, id)
			if in.RevokeOffline {
				for _, f := range tx.ListRefreshFamilies() {
					if f.AppSessionID == id {
						tx.RevokeRefreshFamily(f.ID)
					}
				}
			}
		case "user-sessions":
			if !admin {
				return ErrForbidden
			}
			if _, e := tx.User(id); e != nil {
				return ErrNotFound
			}
			for _, v := range tx.ListSessions() {
				if v.UserID == id {
					tx.EndSession(v.ID, p.User.ID, reason, now)
					targets = append(targets, v.ID)
				}
			}
			if in.RevokeOffline {
				tx.RevokeAccessTokensForUser(id)
			}
		case "client-access":
			c, e := tx.Consent(p.User.ID, id)
			if e != nil {
				return ErrNotFound
			}
			c.Revoked = true
			tx.SaveConsent(c)
			for _, v := range tx.ListAuthzTransactions() {
				if v.UserID == p.User.ID && v.ClientID == id {
					v.Revoked = true
					tx.SaveAuthzTransaction(v)
				}
			}
			for _, v := range tx.ListAuthorizationCodes() {
				if v.UserID == p.User.ID && v.ClientID == id {
					v.Revoked = true
					tx.SaveAuthorizationCode(v)
				}
			}
			for _, a := range tx.ListAppSessions() {
				if a.UserID == p.User.ID && a.ClientID == id {
					tx.EndAppSession(a.ID, p.User.ID, "access_revoked", now)
					targets = append(targets, a.ID)
				}
			}
			for _, t := range tx.ListAccessTokens() {
				if t.UserID == p.User.ID && t.ClientID == id {
					tx.RevokeAccessToken(t.Hash)
				}
			}
		case "logout-events":
			if !admin {
				return ErrForbidden
			}
			for _, d := range tx.ListLogoutDeliveries() {
				if d.ID == id && d.Channel == "backchannel" && d.Status == "failed" {
					if now.Sub(d.CreatedAt) > 24*time.Hour {
						return ValidationError("The retry window has ended.")
					}
					d.Status = "pending"
					d.NextAttempt = now
					tx.SaveLogoutDelivery(d)
					tx.SaveLogoutOperation(LogoutOperation{ID: operationID, Actor: p.User.ID, Kind: kind, CreatedAt: now, Targets: []string{d.AppSessionID}})
					return nil
				}
			}
			return ErrNotFound
		default:
			return ErrNotFound
		}
		tx.SaveLogoutOperation(LogoutOperation{ID: operationID, Actor: p.User.ID, Kind: kind, CreatedAt: now, Targets: targets})
		return nil
	})
}

func (s *Service) ObserveSession(ctx context.Context, hash, device string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		v, e := tx.Session(hash)
		if e != nil {
			return e
		}
		v.LastSeenAt = s.now()
		if len(device) > 160 {
			device = device[:160]
		}
		v.Device = device
		tx.SaveSession(v)
		return nil
	})
}

func (s *Service) SweepSessions(ctx context.Context) error {
	return s.store.Write(ctx, func(tx Tx) error { tx.PruneLogoutState(s.now()); return nil })
}

// Bound creation, not termination: reserve enough outbox capacity for every
// retained association's two notifications. Saturation never blocks logout.
func (s *fileState) CheckSessionCapacity(kind string) error {
	full := false
	switch kind {
	case "op":
		full = len(s.Sessions) >= 10000
	case "app":
		full = len(s.AppSessions) >= 50000
	case "interaction":
		full = len(s.LogoutInteractions) >= 10000
	}
	if full {
		return errors.New("session storage capacity reached; wait for retention cleanup")
	}
	return nil
}

func (s *fileState) LogoutMaintenanceDue(now time.Time) bool {
	cutoff := now.Add(-30 * 24 * time.Hour)
	for _, v := range s.Sessions {
		if (v.EndedAt.IsZero() && !now.Before(v.ExpiresAt)) || (!v.EndedAt.IsZero() && v.EndedAt.Before(cutoff)) {
			return true
		}
	}
	for _, v := range s.LogoutInteractions {
		if !now.Before(v.ExpiresAt) {
			return true
		}
	}
	for _, v := range s.LogoutDeliveries {
		if v.CreatedAt.Before(cutoff) {
			return true
		}
	}
	for _, v := range s.LogoutOperations {
		if v.CreatedAt.Before(cutoff) {
			return true
		}
	}
	for _, v := range s.AppSessions {
		if !v.EndedAt.IsZero() && v.EndedAt.Before(cutoff) {
			return true
		}
	}
	return false
}
