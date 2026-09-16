package identity

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"time"
)

// ActivityRecord is an explicit administrative projection. It excludes raw
// credentials, their hashes, browser bindings, state, nonce and PKCE material.
type ActivityRecord struct {
	ID               string     `json:"id"`
	Kind             string     `json:"kind"`
	Status           string     `json:"status"`
	ClientID         string     `json:"clientId"`
	ClientName       string     `json:"clientName"`
	UserID           string     `json:"userId,omitempty"`
	UserName         string     `json:"userName,omitempty"`
	UserEmail        string     `json:"userEmail,omitempty"`
	Scopes           []string   `json:"scopes"`
	CreatedAt        *time.Time `json:"createdAt"`
	ExpiresAt        *time.Time `json:"expiresAt"`
	IDTokenExpiresAt *time.Time `json:"idTokenExpiresAt,omitempty"`
	CanRevoke        bool       `json:"canRevoke"`
}
type ActivityOptions struct {
	Query, Status string
	Page          int
}
type ActivityList struct {
	Records  []ActivityRecord `json:"records"`
	Total    int              `json:"total"`
	Page     int              `json:"page"`
	PageSize int              `json:"pageSize"`
}
type ActivityCounts struct {
	Total     int `json:"total"`
	Active    int `json:"active"`
	Revoked   int `json:"revoked"`
	Expired   int `json:"expired"`
	Completed int `json:"completed"`
	Consumed  int `json:"consumed"`
}
type ActivityOverview struct {
	GeneratedAt time.Time                 `json:"generatedAt"`
	Users       int                       `json:"users"`
	Clients     int                       `json:"clients"`
	Counts      map[string]ActivityCounts `json:"counts"`
	Recent      []ActivityRecord          `json:"recent"`
}

var ErrActivityNotActive = errors.New("Only active items can be revoked. Consumed, completed, or expired items cannot be revoked.")

var activityKinds = []string{"transactions", "codes", "tokens", "consents"}

func validActivityKind(kind string) bool {
	for _, k := range activityKinds {
		if k == kind {
			return true
		}
	}
	return false
}
func activityID(kind, key string) string {
	hash := sha256.Sum256([]byte("admin-activity|" + kind + "|" + key))
	return hex.EncodeToString(hash[:])
}
func activityTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}
func activityStatus(revoked, consumed bool, expires, now time.Time, used string) string {
	if revoked {
		return "revoked"
	}
	if consumed {
		return used
	}
	if !now.Before(expires) {
		return "expired"
	}
	return "active"
}
func activityRecords(tx ReadTx, now time.Time) []ActivityRecord {
	out := []ActivityRecord{}
	users := map[string]User{}
	for _, u := range tx.Users() {
		users[u.ID] = u
	}
	clients := map[string]ClientRecord{}
	for _, c := range tx.Clients() {
		clients[c.ID] = c
	}
	appendRecord := func(kind, key, clientID, userID, status string, scopes []string, created, expires time.Time, canRevoke bool, idExpiry time.Time) {
		user := users[userID]
		client := clients[clientID]
		out = append(out, ActivityRecord{ID: activityID(kind, key), Kind: kind, Status: status, ClientID: clientID, ClientName: client.Metadata.text("client_name"), UserID: userID, UserName: user.Name, UserEmail: user.Email, Scopes: append([]string{}, scopes...), CreatedAt: activityTime(created), ExpiresAt: activityTime(expires), IDTokenExpiresAt: activityTime(idExpiry), CanRevoke: canRevoke})
	}
	for _, r := range tx.ListAuthzTransactions() {
		status := activityStatus(r.Revoked, r.Consumed, r.ExpiresAt, now, "completed")
		appendRecord("transactions", r.ID, r.ClientID, r.UserID, status, r.Scopes, r.CreatedAt, r.ExpiresAt, status == "active", time.Time{})
	}
	for _, r := range tx.ListAuthorizationCodes() {
		status := activityStatus(r.Revoked, r.Consumed, r.ExpiresAt, now, "consumed")
		appendRecord("codes", r.Hash, r.ClientID, r.UserID, status, r.Scopes, r.CreatedAt, r.ExpiresAt, status == "active", time.Time{})
	}
	for _, r := range tx.ListAccessTokens() {
		status := activityStatus(r.Revoked, false, r.ExpiresAt, now, "")
		appendRecord("tokens", r.Hash, r.ClientID, r.UserID, status, r.Scopes, r.IssuedAt, r.ExpiresAt, status == "active", r.IDTokenExpiresAt)
	}
	for _, r := range tx.ListConsents() {
		status := "active"
		if r.Revoked {
			status = "revoked"
		} else if c, ok := clients[r.ClientID]; !ok || c.UpdatedAt.UnixNano() != r.PolicyRevision {
			status = "expired"
		}
		appendRecord("consents", r.ID, r.ClientID, r.UserID, status, r.Scopes, r.GrantedAt, time.Time{}, status == "active", time.Time{})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].CreatedAt, out[j].CreatedAt
		if a == nil && b != nil {
			return false
		}
		if a != nil && b == nil {
			return true
		}
		if a != nil && b != nil && !a.Equal(*b) {
			return a.After(*b)
		}
		return out[i].ID < out[j].ID
	})
	return out
}
func (s *Service) Activity(ctx context.Context, hash, kind string, opts ActivityOptions) (ActivityList, error) {
	result := ActivityList{Records: []ActivityRecord{}, Page: opts.Page, PageSize: 10}
	if result.Page < 1 {
		result.Page = 1
	}
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		if !validActivityKind(kind) {
			return ErrNotFound
		}
		switch opts.Status {
		case "", "active", "revoked", "expired", "completed", "consumed":
		default:
			return ValidationError("Invalid activity status.")
		}
		q := strings.ToLower(strings.TrimSpace(opts.Query))
		rows := []ActivityRecord{}
		for _, r := range activityRecords(tx, s.now()) {
			if r.Kind != kind || (opts.Status != "" && r.Status != opts.Status) {
				continue
			}
			if q != "" && !strings.Contains(strings.ToLower(strings.Join([]string{r.ID, r.ClientID, r.ClientName, r.UserID, r.UserName, r.UserEmail}, " ")), q) {
				continue
			}
			rows = append(rows, r)
		}
		result.Total = len(rows)
		pages := (len(rows) + 9) / 10
		if pages < 1 {
			pages = 1
		}
		if result.Page > pages {
			result.Page = pages
		}
		start := (result.Page - 1) * 10
		end := start + 10
		if end > len(rows) {
			end = len(rows)
		}
		result.Records = rows[start:end]
		return nil
	})
	return result, err
}
func (s *Service) ActivityOverview(ctx context.Context, hash string) (ActivityOverview, error) {
	result := ActivityOverview{Counts: map[string]ActivityCounts{}, Recent: []ActivityRecord{}}
	err := s.store.Read(ctx, func(tx ReadTx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		result.GeneratedAt = s.now()
		result.Users = len(tx.Users())
		result.Clients = len(tx.Clients())
		for _, kind := range activityKinds {
			result.Counts[kind] = ActivityCounts{}
		}
		records := activityRecords(tx, result.GeneratedAt)
		for _, r := range records {
			c := result.Counts[r.Kind]
			c.Total++
			switch r.Status {
			case "active":
				c.Active++
			case "revoked":
				c.Revoked++
			case "expired":
				c.Expired++
			case "completed":
				c.Completed++
			case "consumed":
				c.Consumed++
			}
			result.Counts[r.Kind] = c
		}
		if len(records) > 10 {
			records = records[:10]
		}
		result.Recent = records
		return nil
	})
	return result, err
}

// Revocation shares the protocol issuance transaction boundary. Revoking a
// transaction/code cascades to its issued tokens; consent revocation cancels
// all currently stored grants for that user/client, including pending requests.
func (s *Service) RevokeActivity(ctx context.Context, hash, kind, id string) error {
	return s.store.Write(ctx, func(tx Tx) error {
		if _, err := s.principal(tx, hash, true); err != nil {
			return err
		}
		if !validActivityKind(kind) {
			return ErrNotFound
		}
		// Recheck lifecycle under the same lock as issuance and revocation.
		// Lists and mutations deliberately use the same eligibility projection.
		now := s.now()
		found := false
		for _, record := range activityRecords(tx, now) {
			if record.Kind == kind && record.ID == id {
				if record.Status == "revoked" {
					return nil
				} // idempotent retry
				if !record.CanRevoke {
					return ErrActivityNotActive
				}
				found = true
				break
			}
		}
		if !found {
			return ErrNotFound
		}
		revokeCode := func(c AuthorizationCode) {
			if activityStatus(c.Revoked, c.Consumed, c.ExpiresAt, now, "consumed") != "active" {
				return
			}
			c.Revoked = true
			tx.SaveAuthorizationCode(c)
			for _, a := range tx.ListAccessTokens() {
				if a.CodeHash == c.Hash && activityStatus(a.Revoked, false, a.ExpiresAt, now, "") == "active" {
					tx.RevokeAccessToken(a.Hash)
				}
			}
		}
		switch kind {
		case "tokens":
			for _, r := range tx.ListAccessTokens() {
				if activityID(kind, r.Hash) == id {
					tx.RevokeAccessToken(r.Hash)
					return nil
				}
			}
		case "codes":
			for _, r := range tx.ListAuthorizationCodes() {
				if activityID(kind, r.Hash) == id {
					revokeCode(r)
					return nil
				}
			}
		case "transactions":
			for _, r := range tx.ListAuthzTransactions() {
				if activityID(kind, r.ID) == id {
					r.Revoked = true
					tx.SaveAuthzTransaction(r)
					for _, c := range tx.ListAuthorizationCodes() {
						if c.TransactionID == r.ID {
							revokeCode(c)
						}
					}
					return nil
				}
			}
		case "consents":
			for _, r := range tx.ListConsents() {
				if activityID(kind, r.ID) == id {
					r.Revoked = true
					tx.SaveConsent(r)
					for _, t := range tx.ListAuthzTransactions() {
						if t.UserID == r.UserID && t.ClientID == r.ClientID && activityStatus(t.Revoked, t.Consumed, t.ExpiresAt, now, "completed") == "active" {
							t.Revoked = true
							tx.SaveAuthzTransaction(t)
						}
					}
					for _, c := range tx.ListAuthorizationCodes() {
						if c.UserID == r.UserID && c.ClientID == r.ClientID {
							revokeCode(c)
						}
					}
					for _, a := range tx.ListAccessTokens() {
						if a.UserID == r.UserID && a.ClientID == r.ClientID && activityStatus(a.Revoked, false, a.ExpiresAt, now, "") == "active" {
							tx.RevokeAccessToken(a.Hash)
						}
					}
					return nil
				}
			}
		}
		return ErrNotFound
	})
}
