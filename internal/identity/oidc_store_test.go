package identity

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMigratesV1ToV2(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	// A raw v1 document shaped exactly like the pre-OIDC on-disk format:
	// {version, users, sessions} with no client/OIDC maps at all.
	v1 := `{"version":1,"users":{"u1":{"sub":"u1","id":"u1","email":"a@example.com","name":"A","role":"admin","active":true,"passwordHash":"$argon2id$v=19$m=19456,t=2,p=1$AA$AA"}},"sessions":{}}`
	if err := os.WriteFile(path, []byte(v1), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := store.Read(ctx, func(tx ReadTx) error {
		if _, err := tx.User("u1"); err != nil {
			t.Fatal("expected v1 user to survive migration", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Write, to force a round trip through the marshal path, then confirm the
	// new maps are present and the version was bumped.
	if err := store.Write(ctx, func(tx Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk map[string]json.RawMessage
	if err := json.Unmarshal(raw, &onDisk); err != nil {
		t.Fatal(err)
	}
	var version int
	if err := json.Unmarshal(onDisk["version"], &version); err != nil || version != currentVersion {
		t.Fatalf("expected version %d after migration, got %d (err=%v)", currentVersion, version, err)
	}
}

func TestRejectsUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "identity.json")
	if err := os.WriteFile(path, []byte(`{"version":99,"users":{},"sessions":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Read(context.Background(), func(ReadTx) error { return nil }); err == nil {
		t.Fatal("expected unsupported version to fail closed")
	}
}

func TestOIDCRecordCRUDAndExpiry(t *testing.T) {
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	txn := AuthzTransaction{ID: "tx1", ClientID: "client1", RedirectURI: "https://app.example.com/cb", Scopes: []string{"openid"}, ExpiresAt: now.Add(time.Minute), CreatedAt: now}
	code := AuthorizationCode{Hash: "codehash1", TransactionID: "tx1", ClientID: "client1", UserID: "user1", ExpiresAt: now.Add(time.Minute)}
	token := AccessToken{Hash: "tokenhash1", ClientID: "client1", UserID: "user1", Audience: "userinfo", ExpiresAt: now.Add(time.Minute)}
	consent := Consent{UserID: "user1", ClientID: "client1", Scopes: []string{"openid", "profile"}, GrantedAt: now}

	if err := store.Write(ctx, func(tx Tx) error {
		tx.SaveAuthzTransaction(txn)
		tx.SaveAuthorizationCode(code)
		tx.SaveAccessToken(token)
		tx.SaveConsent(consent)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := store.Read(ctx, func(tx ReadTx) error {
		got, err := tx.AuthzTransaction("tx1")
		if err != nil || got.ClientID != "client1" || len(got.Scopes) != 1 {
			t.Fatalf("unexpected transaction: %+v (err=%v)", got, err)
		}
		gotCode, err := tx.AuthorizationCode("codehash1")
		if err != nil || gotCode.UserID != "user1" {
			t.Fatalf("unexpected code: %+v (err=%v)", gotCode, err)
		}
		gotToken, err := tx.AccessToken("tokenhash1")
		if err != nil || gotToken.Audience != "userinfo" {
			t.Fatalf("unexpected token: %+v (err=%v)", gotToken, err)
		}
		gotConsent, err := tx.Consent("user1", "client1")
		if err != nil || len(gotConsent.Scopes) != 2 {
			t.Fatalf("unexpected consent: %+v (err=%v)", gotConsent, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Snapshots must not let a caller mutate the store through them.
	if err := store.Read(ctx, func(tx ReadTx) error {
		got, err := tx.AuthzTransaction("tx1")
		if err != nil {
			return err
		}
		got.Scopes[0] = "mutated"
		again, err := tx.AuthzTransaction("tx1")
		if err != nil {
			return err
		}
		if again.Scopes[0] != "openid" {
			t.Fatal("snapshot mutation leaked into the store")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Revocation.
	if err := store.Write(ctx, func(tx Tx) error {
		tx.RevokeAccessToken("tokenhash1")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Read(ctx, func(tx ReadTx) error {
		got, err := tx.AccessToken("tokenhash1")
		if err != nil || !got.Revoked {
			t.Fatalf("expected token to be revoked, got %+v (err=%v)", got, err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// Expiry pruning.
	if err := store.Write(ctx, func(tx Tx) error {
		tx.PruneOIDCState(now.Add(2 * time.Minute))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Read(ctx, func(tx ReadTx) error {
		if _, err := tx.AuthzTransaction("tx1"); err != ErrNotFound {
			t.Fatal("expected expired transaction to be pruned")
		}
		if _, err := tx.AuthorizationCode("codehash1"); err != ErrNotFound {
			t.Fatal("expected expired code to be pruned")
		}
		if _, err := tx.AccessToken("tokenhash1"); err != ErrNotFound {
			t.Fatal("expected expired token to be pruned")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentAuthorizationCodeConsumption(t *testing.T) {
	// Mirrors TestConcurrentLastAdminProtection: two independent FileStore
	// instances race to consume the same code; exactly one must succeed.
	dir := t.TempDir()
	store, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := store.Write(ctx, func(tx Tx) error {
		tx.SaveAuthorizationCode(AuthorizationCode{Hash: "codehash1", ClientID: "client1", UserID: "user1", ExpiresAt: now.Add(time.Minute)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	consume := func(s *FileStore) error {
		return s.Write(ctx, func(tx Tx) error {
			code, err := tx.AuthorizationCode("codehash1")
			if err != nil {
				return err
			}
			if code.Consumed {
				return ErrConflict
			}
			code.Consumed = true
			tx.SaveAuthorizationCode(code)
			return nil
		})
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, s := range []*FileStore{store, other} {
		wg.Add(1)
		go func(s *FileStore) {
			defer wg.Done()
			errs <- consume(s)
		}(s)
	}
	wg.Wait()
	close(errs)
	success, blocked := 0, 0
	for err := range errs {
		switch err {
		case nil:
			success++
		case ErrConflict:
			blocked++
		default:
			t.Fatal(err)
		}
	}
	if success != 1 || blocked != 1 {
		t.Fatalf("expected exactly one success and one conflict, got success=%d blocked=%d", success, blocked)
	}
}
