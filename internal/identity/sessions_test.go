package identity

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func sessionTestStore(t *testing.T) (*Service, *FileStore, LoginResult) {
	t.Helper()
	store, e := NewFileStore(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	s, e := NewService(store, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	_, e = s.Bootstrap(t.Context(), "Admin", "admin@example.com", "a secure test password")
	if e != nil {
		t.Fatal(e)
	}
	login, e := s.Login(t.Context(), "admin@example.com", "a secure test password", "")
	if e != nil {
		t.Fatal(e)
	}
	return s, store, login
}
func TestSessionTerminationScopePersistenceAndOfflinePolicy(t *testing.T) {
	s, store, login := sessionTestStore(t)
	other, e := s.Login(t.Context(), login.User.Email, "a secure test password", "")
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	meta := ClientMetadata{}
	meta.set("backchannel_logout_uri", "https://rp.example/logout")
	meta.set("frontchannel_logout_uri", "https://rp.example/front")
	e = store.Write(t.Context(), func(tx Tx) error {
		tx.SaveClient(ClientRecord{ID: "app", Metadata: meta})
		for _, v := range []struct{ id, op string }{{"app-a", login.Session.ID}, {"app-b", other.Session.ID}} {
			tx.SaveAppSession(AppSession{ID: v.id, OPSessionID: v.op, UserID: login.User.ID, ClientID: "app", Subject: login.User.Sub, CreatedAt: now})
		}
		tx.SaveAccessToken(AccessToken{Hash: "online", AppSessionID: "app-a", OPSessionID: login.Session.ID, ExpiresAt: now.Add(time.Hour)})
		tx.SaveAccessToken(AccessToken{Hash: "offline", AppSessionID: "app-a", OPSessionID: login.Session.ID, FamilyID: "family", ExpiresAt: now.Add(time.Hour)})
		tx.SaveRefreshFamily(RefreshFamily{ID: "family", UserID: login.User.ID})
		tx.SaveAuthorizationCode(AuthorizationCode{Hash: "pending", OPSessionID: login.Session.ID})
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	if e = s.Logout(t.Context(), login.Session.Hash); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Authenticate(t.Context(), login.Session.Hash); !errors.Is(e, ErrUnauthorized) {
		t.Fatalf("terminated credential accepted: %v", e)
	}
	if _, e = s.Authenticate(t.Context(), other.Session.Hash); e != nil {
		t.Fatal("other device terminated", e)
	}
	_ = store.Read(t.Context(), func(tx ReadTx) error {
		a, _ := tx.AppSession("app-a")
		b, _ := tx.AppSession("app-b")
		if a.EndedAt.IsZero() || !b.EndedAt.IsZero() {
			t.Fatal("incorrect app scope")
		}
		online, _ := tx.AccessToken("online")
		offline, _ := tx.AccessToken("offline")
		family, _ := tx.RefreshFamily("family")
		code, _ := tx.AuthorizationCode("pending")
		if !online.Revoked || offline.Revoked || family.Revoked || !code.Revoked {
			t.Fatal("incorrect grant policy")
		}
		if len(tx.ListLogoutDeliveries()) != 3 {
			t.Fatal("expected local, front and back events")
		}
		return nil
	})
	// Idempotency across another store instance, as after a restart.
	reopened, _ := NewFileStore(sStoreDir(store))
	_ = reopened.Write(t.Context(), func(tx Tx) error {
		tx.EndSession(login.Session.ID, login.User.ID, "retry", now)
		if len(tx.ListLogoutDeliveries()) != 3 {
			t.Fatal("duplicate outbox records")
		}
		return nil
	})
}
func sStoreDir(s *FileStore) string { return strings.TrimSuffix(s.path, "/identity.json") }

func TestSessionOwnershipProjectionRotationAndExpiry(t *testing.T) {
	s, store, login := sessionTestStore(t)
	rotated, e := s.Login(t.Context(), login.User.Email, "a secure test password", login.Session.Hash)
	if e != nil {
		t.Fatal(e)
	}
	if rotated.Session.ID != login.Session.ID || rotated.Session.Hash == login.Session.Hash {
		t.Fatal("logical session must survive credential rotation")
	}
	_ = store.Write(t.Context(), func(tx Tx) error {
		tx.SaveSession(Session{ID: "foreign", Hash: "foreign-credential", UserID: "another", ExpiresAt: time.Now().Add(time.Hour)})
		return nil
	})
	if e = s.EndSessions(t.Context(), rotated.Session.Hash, "op-sessions", "foreign", false, SessionLogoutRequest{}); !errors.Is(e, ErrNotFound) {
		t.Fatal("foreign session accepted", e)
	}
	result, e := s.SessionActivity(t.Context(), rotated.Session.Hash, "op-sessions", false, ActivityOptions{})
	if e != nil || result.Total != 1 {
		t.Fatal(result, e)
	}
	raw, _ := json.Marshal(result)
	for _, secret := range []string{rotated.Session.Hash, rotated.Session.CSRF, "foreign-credential"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("credential or foreign data exposed")
		}
	}
	_ = store.Write(t.Context(), func(tx Tx) error {
		tx.SaveAppSession(AppSession{ID: "expiring-app", OPSessionID: rotated.Session.ID, UserID: login.User.ID})
		tx.PruneLogoutState(time.Now().Add(2 * time.Hour))
		if SessionActive(tx, rotated.Session.ID, time.Now()) {
			t.Fatal("expiry not enforced")
		}
		if len(tx.ListLogoutDeliveries()) != 3 {
			t.Fatal("expiry must create events for both sessions and app")
		}
		return nil
	})
}
func TestSecurityDeletionQueuesBeforeRemovingClient(t *testing.T) {
	_, store, login := sessionTestStore(t)
	_ = store.Write(t.Context(), func(tx Tx) error {
		m := ClientMetadata{}
		m.set("backchannel_logout_uri", "https://rp.example/logout")
		tx.SaveClient(ClientRecord{ID: "client", Metadata: m})
		tx.SaveAppSession(AppSession{ID: "app", ClientID: "client", UserID: login.User.ID, OPSessionID: login.Session.ID})
		tx.DeleteClient("client")
		jobs := tx.ListLogoutDeliveries()
		if len(jobs) != 1 || jobs[0].Endpoint != "https://rp.example/logout" {
			t.Fatal("deleted client lost destination")
		}
		return nil
	})
}

func TestLogoutAllOtherAndSecurityTriggers(t *testing.T) {
	for _, action := range []string{"other", "all", "all_offline", "password", "disable", "delete", "consent", "client_policy"} {
		t.Run(action, func(t *testing.T) {
			s, store, login := sessionTestStore(t)
			other, e := s.Login(t.Context(), login.User.Email, "a secure test password", "")
			if e != nil {
				t.Fatal(e)
			}
			now := time.Now().UTC()
			if e = store.Write(t.Context(), func(tx Tx) error {
				m := ClientMetadata{}
				m.set("backchannel_logout_uri", "https://rp.example/logout")
				tx.SaveClient(ClientRecord{ID: "rp", Metadata: m})
				for _, op := range []Session{login.Session, other.Session} {
					tx.SaveAppSession(AppSession{ID: op.ID + "-app", OPSessionID: op.ID, UserID: login.User.ID, ClientID: "rp", CreatedAt: now})
				}
				tx.SaveRefreshFamily(RefreshFamily{ID: "offline", UserID: login.User.ID, ClientID: "rp", OPSessionID: other.Session.ID})
				tx.SaveConsent(Consent{UserID: login.User.ID, ClientID: "rp"})
				return nil
			}); e != nil {
				t.Fatal(e)
			}
			switch action {
			case "other", "all", "all_offline":
				scope := action
				if action == "all_offline" {
					scope = "all"
				}
				e = s.EndSessions(t.Context(), login.Session.Hash, "op-sessions", "", false, SessionLogoutRequest{Scope: scope, Password: "a secure test password", RevokeOffline: action == "all_offline"})
			default:
				e = store.Write(t.Context(), func(tx Tx) error {
					switch action {
					case "password":
						u, _ := tx.User(login.User.ID)
						u.PasswordHash = "changed"
						return tx.SaveUser(u)
					case "disable":
						u, _ := tx.User(login.User.ID)
						u.Active = false
						return tx.SaveUser(u)
					case "delete":
						tx.DeleteUser(login.User.ID)
					case "consent":
						c, _ := tx.Consent(login.User.ID, "rp")
						c.Revoked = true
						tx.SaveConsent(c)
					case "client_policy":
						tx.SaveOAuthPolicy("rp", OAuthPolicy{})
					}
					return nil
				})
			}
			if e != nil {
				t.Fatal(e)
			}
			_ = store.Read(t.Context(), func(tx ReadTx) error {
				currentActive := SessionActive(tx, login.Session.ID, now)
				wantActive := action == "other" || action == "consent" || action == "client_policy"
				if currentActive != wantActive {
					t.Fatalf("current session active=%v want %v", currentActive, wantActive)
				}
				a, _ := tx.AppSession(other.Session.ID + "-app")
				if a.EndedAt.IsZero() {
					t.Fatal("target association not ended")
				}
				f, _ := tx.RefreshFamily("offline")
				wantRevoked := action != "other" && action != "all"
				if f.Revoked != wantRevoked {
					t.Fatalf("offline revoked=%v want %v", f.Revoked, wantRevoked)
				}
				found := false
				for _, d := range tx.ListLogoutDeliveries() {
					if d.AppSessionID == a.ID && d.Channel == "backchannel" {
						found = true
					}
				}
				if !found {
					t.Fatal("missing security notification")
				}
				return nil
			})
		})
	}
}
