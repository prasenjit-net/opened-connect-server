package identity

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRegistrationAtomicQuotaPersistenceAndCredentialIsolation(t *testing.T) {
	s, store, _ := fixture(t)
	ctx := context.Background()
	login, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	view, iat, err := s.IssueInitialToken(ctx, login.Session.Hash, InitialTokenInput{Label: "One client"})
	if err != nil {
		t.Fatal(err)
	}
	input := metadata(t, `{"redirect_uris":["https://rp.example/cb"],"future_extension":{"ignored":true},"client_name#fr":"Portail"}`)
	var successes atomic.Int32
	var wg sync.WaitGroup
	var created ClientView
	var mu sync.Mutex
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			out, err := s.RegisterClient(ctx, iat, input, false)
			if err == nil {
				successes.Add(1)
				mu.Lock()
				created = out
				mu.Unlock()
			} else if !errors.Is(err, ErrRegistrationCredential) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("single-use token created %d clients", successes.Load())
	}
	id := created["client_id"].(string)
	rat := created["registration_access_token"].(string)
	if created["future_extension"] != nil || created["protocol_compatible"] != nil || created["registration_origin"] != nil {
		t.Fatal("protocol response leaked internal/unknown metadata")
	}
	if _, err = s.RegisterClient(ctx, rat, input, false); !errors.Is(err, ErrRegistrationCredential) {
		t.Fatal("RAT authorized registration")
	}
	for _, token := range []string{iat, login.Token, created["client_secret"].(string), "garbage"} {
		if _, err = s.ReadRegistration(ctx, token, id); !errors.Is(err, ErrRegistrationCredential) {
			t.Fatal("credential substitution accepted")
		}
	}
	if _, err = s.ReadRegistration(ctx, rat, "other"); !errors.Is(err, ErrRegistrationCredential) {
		t.Fatal("cross-client read accepted")
	}
	disk, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{iat, rat, created["client_secret"].(string)} {
		if strings.Contains(string(disk), secret) {
			t.Fatal("plaintext credential persisted")
		}
	}
	restarted, err := NewFileStore(filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	again, err := NewService(restarted, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := again.ReadRegistration(ctx, rat, id)
	if err != nil || got["client_secret"] != created["client_secret"] {
		t.Fatal("restart lost client credentials", err)
	}
	inventory, err := s.ListInitialTokens(ctx, login.Session.Hash, "One", 1)
	if err != nil || len(inventory.Tokens) != 1 || inventory.Tokens[0].Status != "consumed" {
		t.Fatalf("bad inventory: %+v %v", inventory, err)
	}
	if err = s.RevokeInitialToken(ctx, login.Session.Hash, view.ID); !errors.Is(err, ErrRegistrationInactive) {
		t.Fatal("consumed token can be revoked")
	}
	if _, err = s.ManageRegistrationToken(ctx, login.Session.Hash, id, true); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadRegistration(ctx, rat, id); !errors.Is(err, ErrRegistrationCredential) {
		t.Fatal("replacement left old token active")
	}
	newRAT, err := s.ManageRegistrationToken(ctx, login.Session.Hash, id, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.DeleteClient(ctx, login.Session.Hash, id); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadRegistration(ctx, newRAT, id); !errors.Is(err, ErrRegistrationCredential) {
		t.Fatal("deleted client readable")
	}
}

func TestRegistrationValidationAndRevocation(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	login, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	view, iat, err := s.IssueInitialToken(ctx, login.Session.Hash, InitialTokenInput{Label: "Validation", MaxUses: 2})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		`{}`, `{"redirect_uris":["https://rp.example/cb#bad"]}`, `{"redirect_uris":["http://localhost/cb"]}`,
		`{"redirect_uris":["https://rp.example/cb"],"client_id":"chosen"}`,
		`{"redirect_uris":["https://rp.example/cb"],"grant_types":["refresh_token"]}`,
		`{"redirect_uris":["https://rp.example/cb"],"subject_type":"pairwise"}`,
		`{"redirect_uris":["https://rp.example/cb"],"sector_identifier_uri":"https://private.example/sector"}`,
		`{"redirect_uris":["https://rp.example/cb"],"default_acr_values":["urn:mfa"]}`,
		`{"redirect_uris":["https://rp.example/cb"],"request_uris":["https://private.example/request"]}`,
		`{"redirect_uris":["https://rp.example/cb"],"jwks":{"keys":[{"kty":"oct","k":"secret"}]}}`,
	} {
		t.Run(raw, func(t *testing.T) {
			_, err := s.RegisterClient(ctx, iat, metadata(t, raw), false)
			var invalid *RegistrationError
			if !errors.As(err, &invalid) {
				t.Fatalf("invalid metadata accepted: %v", err)
			}
		})
	}
	list, err := s.ListInitialTokens(ctx, login.Session.Hash, "", 1)
	if err != nil || list.Tokens[0].Uses != 0 {
		t.Fatal("validation consumed quota")
	}
	input := metadata(t, `{"redirect_uris":["com.example.app:/cb"],"application_type":"native","token_endpoint_auth_method":"none"}`)
	created, err := s.RegisterClient(ctx, iat, input, false)
	if err != nil {
		t.Fatal(err)
	}
	if created["client_secret"] != nil || created["client_secret_expires_at"] != nil {
		t.Fatal("public client received secret")
	}
	if err = s.RevokeInitialToken(ctx, login.Session.Hash, view.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.RegisterClient(ctx, iat, input, false); !errors.Is(err, ErrRegistrationCredential) {
		t.Fatal("revoked IAT accepted")
	}
	if _, err = s.ReadRegistration(ctx, created["registration_access_token"].(string), created["client_id"].(string)); err != nil {
		t.Fatal("IAT revocation invalidated existing client")
	}
	_, expired, err := s.IssueInitialToken(ctx, login.Session.Hash, InitialTokenInput{Label: "Expired", LifetimeHours: 1})
	if err != nil {
		t.Fatal(err)
	}
	now := s.now()
	s.now = func() time.Time { return now.Add(2 * time.Hour) }
	if err = s.CheckInitialToken(ctx, expired); !errors.Is(err, ErrRegistrationCredential) {
		t.Fatal("expired IAT accepted")
	}
}

type rollbackRegistrationStore struct{ Store }

func (s rollbackRegistrationStore) Write(ctx context.Context, fn func(Tx) error) error {
	return s.Store.Write(ctx, func(tx Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return errors.New("simulated commit failure")
	})
}
func TestRegistrationRollbackAndMigration(t *testing.T) {
	s, store, _ := fixture(t)
	ctx := context.Background()
	login, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	_, iat, err := s.IssueInitialToken(ctx, login.Session.Hash, InitialTokenInput{Label: "Rollback"})
	if err != nil {
		t.Fatal(err)
	}
	s.store = rollbackRegistrationStore{store}
	if out, err := s.RegisterClient(ctx, iat, metadata(t, `{"redirect_uris":["https://rp.example/cb"]}`), false); err == nil || out != nil {
		t.Fatal("failed commit returned credentials")
	}
	s.store = store
	if err = store.Read(ctx, func(tx ReadTx) error {
		if len(tx.Clients()) != 0 || tx.InitialTokens()[0].Uses != 0 {
			t.Fatal("failed commit changed state")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	var state map[string]any
	if err = json.Unmarshal(data, &state); err != nil {
		t.Fatal(err)
	}
	state["version"] = 2
	delete(state, "initialAccessTokens")
	delete(state, "registrationAccessTokens")
	data, err = json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(store.path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = s.IssueInitialToken(ctx, login.Session.Hash, InitialTokenInput{Label: "After migration"}); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(store.path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version": 5`) {
		t.Fatal("store not migrated")
	}
}

// Block only the mutation boundary, allowing a credential to be revoked after
// pre-validation but before registration commits.
type gatedRegistrationStore struct {
	Store
	ready, proceed chan struct{}
}

func (g gatedRegistrationStore) Write(ctx context.Context, fn func(Tx) error) error {
	close(g.ready)
	<-g.proceed
	return g.Store.Write(ctx, fn)
}
func TestRegistrationRechecksRevocationAtCommit(t *testing.T) {
	s, store, _ := fixture(t)
	ctx := context.Background()
	login, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	view, iat, err := s.IssueInitialToken(ctx, login.Session.Hash, InitialTokenInput{Label: "Race"})
	if err != nil {
		t.Fatal(err)
	}
	ready, proceed := make(chan struct{}), make(chan struct{})
	registrar := *s
	registrar.store = gatedRegistrationStore{store, ready, proceed}
	done := make(chan error, 1)
	input := metadata(t, `{"redirect_uris":["https://rp.example/cb"]}`)
	go func() { _, err := registrar.RegisterClient(ctx, iat, input, false); done <- err }()
	<-ready
	if err = s.RevokeInitialToken(ctx, login.Session.Hash, view.ID); err != nil {
		t.Fatal(err)
	}
	close(proceed)
	if err = <-done; !errors.Is(err, ErrRegistrationCredential) {
		t.Fatal("revoked invitation committed client", err)
	}
	if err = store.Read(ctx, func(tx ReadTx) error {
		if len(tx.Clients()) != 0 {
			t.Fatal("client created after revocation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestRegistrationReadTracksAdminEditsAndDeletion(t *testing.T) {
	s, _, _ := fixture(t)
	ctx := context.Background()
	login, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	_, iat, err := s.IssueInitialToken(ctx, login.Session.Hash, InitialTokenInput{Label: "Lifecycle"})
	if err != nil {
		t.Fatal(err)
	}
	created, err := s.RegisterClient(ctx, iat, metadata(t, `{"redirect_uris":["https://rp.example/cb"]}`), false)
	if err != nil {
		t.Fatal(err)
	}
	id, rat := created["client_id"].(string), created["registration_access_token"].(string)
	rotated, err := s.RotateClientSecret(ctx, login.Session.Hash, id)
	if err != nil {
		t.Fatal(err)
	}
	read, err := s.ReadRegistration(ctx, rat, id)
	if err != nil || read["client_secret"] != rotated["client_secret"] || read["client_secret"] == created["client_secret"] {
		t.Fatal("read did not return current secret", err)
	}
	_, err = s.SaveClient(ctx, login.Session.Hash, id, metadata(t, `{"redirect_uris":["https://rp.example/new-cb"],"client_name":"Updated"}`))
	if err != nil {
		t.Fatal(err)
	}
	read, err = s.ReadRegistration(ctx, rat, id)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(read)
	if !strings.Contains(string(encoded), "Updated") || !strings.Contains(string(encoded), "new-cb") {
		t.Fatal("read did not return updated metadata")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.ReadRegistration(ctx, rat, id)
			if err != nil && !errors.Is(err, ErrRegistrationCredential) {
				t.Error(err)
			}
		}()
	}
	if err = s.DeleteClient(ctx, login.Session.Hash, id); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if _, err = s.ReadRegistration(ctx, rat, id); !errors.Is(err, ErrRegistrationCredential) {
		t.Fatal("read after deletion accepted")
	}
}
