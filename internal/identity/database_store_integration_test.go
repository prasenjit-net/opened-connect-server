package identity

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestPostgresStoreContract(t *testing.T) {
	dsn := os.Getenv("TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	store, err := NewPostgresStore(context.Background(), PostgresStoreConfig{
		DSN: dsn, DataDir: t.TempDir(), MaxOpenConns: 4, MaxIdleConns: 1,
		ConnMaxLifetime: time.Minute, ConnectTimeout: 5 * time.Second, StatementTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	exerciseDatabaseStore(t, store)
	exerciseDatabaseScenarios(t, store)
}

func TestMongoStoreContract(t *testing.T) {
	uri := os.Getenv("TEST_MONGODB_URI")
	if uri == "" {
		t.Skip("set TEST_MONGODB_URI to a transaction-capable replica set")
	}
	store, err := NewMongoStore(context.Background(), uri, "ocs_test_"+activityID("db", time.Now().String())[:12], t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close(context.Background())
	exerciseDatabaseStore(t, store)
	exerciseDatabaseScenarios(t, store)
}

// exerciseDatabaseStore is the baseline contract every backend must
// satisfy, generic across the JSON-blob and normalized-schema shapes.
func exerciseDatabaseStore(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()
	user := User{Profile: Profile{ID: "database-user", Sub: "database-user", Email: "database@example.test", Name: "Database", Active: true, Role: RoleAdmin}, PasswordHash: "hash"}
	if err := store.Write(ctx, func(tx Tx) error { return tx.SaveUser(user) }); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, func(tx Tx) error {
		_ = tx.SaveUser(User{Profile: Profile{ID: "rolled-back", Email: "rollback@example.test"}})
		return errors.New("rollback")
	}); err == nil {
		t.Fatal("rollback callback succeeded")
	}
	if err := store.Read(ctx, func(tx ReadTx) error {
		if _, err := tx.User(user.ID); err != nil {
			return err
		}
		if _, err := tx.User("rolled-back"); !errors.Is(err, ErrNotFound) {
			t.Fatalf("rollback leaked user: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// exerciseDatabaseScenarios runs the same persistence and replay contract for
// both databases, including their different timestamp and refresh-token layouts.
func exerciseDatabaseScenarios(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()
	client, pinnedRevision := checkDatabaseClientRevision(t, store)
	user := User{Profile: Profile{ID: "db-code-user", Sub: "db-code-user", Email: "db-code-user@example.test", Name: "Coder", Active: true, Role: RoleUser}, PasswordHash: "hash"}
	if err := store.Write(ctx, func(tx Tx) error { return tx.SaveUser(user) }); err != nil {
		t.Fatal(err)
	}

	accessToken := checkDatabaseCodeReplay(t, store, client, user, pinnedRevision)
	checkDatabaseRefreshReplay(t, store, client, user, pinnedRevision)
	checkDatabaseInitialTokenUses(t, store)
	checkDatabaseSessionCascade(t, store, client, user, pinnedRevision, accessToken)
	checkDatabaseCancellation(t, store)
}

func checkDatabaseClientRevision(t *testing.T, store Store) (ClientRecord, time.Time) {
	t.Helper()
	ctx := context.Background()
	client := ClientRecord{ID: "db-test-client", Metadata: ClientMetadata{}, UpdatedAt: time.Now()}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveClient(client); return nil }); err != nil {
		t.Fatal(err)
	}
	var pinnedRevision time.Time
	if err := store.Read(ctx, func(tx ReadTx) error {
		c, err := tx.Client(client.ID)
		pinnedRevision = c.UpdatedAt
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if pinnedRevision.UnixNano() != client.UpdatedAt.UnixNano() {
		t.Fatalf("client revision lost nanosecond precision: wrote %d, read back %d", client.UpdatedAt.UnixNano(), pinnedRevision.UnixNano())
	}

	return client, pinnedRevision
}

func checkDatabaseCodeReplay(t *testing.T, store Store, client ClientRecord, user User, pinnedRevision time.Time) AccessToken {
	t.Helper()
	ctx := context.Background()

	code := AuthorizationCode{
		Hash: "db-test-code-hash", ClientID: client.ID, UserID: user.ID,
		ClientUpdatedAt: pinnedRevision, ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
	}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveAuthorizationCode(code); return nil }); err != nil {
		t.Fatal(err)
	}
	accessToken := AccessToken{Hash: "db-test-code-access", ClientID: client.ID, UserID: user.ID, CodeHash: code.Hash, Audience: "userinfo", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	if err := store.Write(ctx, func(tx Tx) error {
		record, err := tx.AuthorizationCode(code.Hash)
		if err != nil {
			return err
		}
		if record.Consumed {
			t.Fatal("code already consumed on first exchange")
		}
		record.Consumed = true
		record.RetainUntil = time.Now().Add(time.Minute)
		tx.SaveAuthorizationCode(record)
		tx.SaveAccessToken(accessToken)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, func(tx Tx) error {
		record, err := tx.AuthorizationCode(code.Hash)
		if err != nil {
			return err
		}
		if !record.Consumed {
			t.Fatal("expected code to already be consumed (replay)")
		}
		tx.RevokeAccessTokensForCode(code.Hash)
		return nil // replay revocation must commit despite being an error case at the HTTP layer
	}); err != nil {
		t.Fatal(err)
	}
	assertDatabaseCodeRevoked(t, store, accessToken)

	return accessToken
}

func checkDatabaseRefreshReplay(t *testing.T, store Store, client ClientRecord, user User, pinnedRevision time.Time) {
	t.Helper()
	ctx := context.Background()

	family := RefreshFamily{
		ID: "db-test-family", ClientID: client.ID, UserID: user.ID, ClientRevision: pinnedRevision.UnixNano(),
		CreatedAt: time.Now(), AbsoluteExpiry: time.Now().Add(time.Hour), IdleExpiry: time.Now().Add(time.Hour), RetainUntil: time.Now().Add(2 * time.Hour),
	}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveRefreshFamily(family); return nil }); err != nil {
		t.Fatal(err)
	}
	firstToken := RefreshToken{Hash: "db-test-refresh-1", FamilyID: family.ID, IssuedAt: time.Now()}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveRefreshToken(firstToken); return nil }); err != nil {
		t.Fatal(err)
	}
	// Rotate: mark the first token consumed and add a second, inside one
	// transaction - mirrors refresh.go's read-check-flag-then-save pattern
	// against the family's embedded array rather than a standalone table.
	if err := store.Write(ctx, func(tx Tx) error {
		old, err := tx.RefreshToken(firstToken.Hash)
		if err != nil {
			return err
		}
		if old.Consumed {
			t.Fatal("token already consumed before rotation")
		}
		old.Consumed = true
		tx.SaveRefreshToken(old)
		tx.SaveRefreshToken(RefreshToken{Hash: "db-test-refresh-2", FamilyID: family.ID, IssuedAt: time.Now()})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// Replay of the first (now-consumed) token must be detectable and
	// revoking the family must commit.
	if err := store.Write(ctx, func(tx Tx) error {
		old, err := tx.RefreshToken(firstToken.Hash)
		if err != nil {
			return err
		}
		if !old.Consumed {
			t.Fatal("expected first token to already be consumed (replay)")
		}
		tx.RevokeRefreshFamily(family.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	assertDatabaseRefreshRevoked(t, store, family)

}

func checkDatabaseInitialTokenUses(t *testing.T, store Store) {
	t.Helper()
	ctx := context.Background()

	iat := InitialAccessToken{Hash: "db-test-iat-hash", ID: "db-test-iat-id", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 3}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveInitialToken(iat); return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := store.Write(ctx, func(tx Tx) error {
			return useDatabaseInitialToken(tx, iat.Hash)
		}); err != nil {
			t.Fatalf("use %d: %v", i, err)
		}
	}
	if err := store.Read(ctx, func(tx ReadTx) error {
		t2, err := tx.InitialToken(iat.Hash)
		if err != nil {
			return err
		}
		if t2.Uses != 3 {
			t.Fatalf("expected 3 uses recorded, got %d", t2.Uses)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

}

func checkDatabaseSessionCascade(t *testing.T, store Store, client ClientRecord, user User, pinnedRevision time.Time, accessToken AccessToken) {
	t.Helper()
	ctx := context.Background()

	txn := AuthzTransaction{ID: "db-test-txn", ClientID: client.ID, UserID: user.ID, ClientUpdatedAt: pinnedRevision, ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now()}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveAuthzTransaction(txn); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, func(tx Tx) error { tx.DeleteUserSessions(user.ID); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := store.Read(ctx, func(tx ReadTx) error {
		if _, err := tx.AuthzTransaction(txn.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected transaction to be deleted by DeleteUserSessions, got %v", err)
		}
		tok, err := tx.AccessToken(accessToken.Hash)
		if err != nil {
			return err
		}
		if !tok.Revoked {
			t.Fatal("expected access token to remain (revoked, not deleted) after DeleteUserSessions")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertDatabaseCodeRevoked(t *testing.T, store Store, accessToken AccessToken) {
	t.Helper()
	ctx := context.Background()
	if err := store.Read(ctx, func(tx ReadTx) error {
		tok, err := tx.AccessToken(accessToken.Hash)
		if err != nil {
			return err
		}
		if !tok.Revoked {
			t.Fatal("replay did not revoke the access token issued by the original exchange")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func assertDatabaseRefreshRevoked(t *testing.T, store Store, family RefreshFamily) {
	t.Helper()
	ctx := context.Background()
	if err := store.Read(ctx, func(tx ReadTx) error {
		f, err := tx.RefreshFamily(family.ID)
		if err != nil {
			return err
		}
		if !f.Revoked {
			t.Fatal("replay did not revoke the refresh family")
		}
		second, err := tx.RefreshToken("db-test-refresh-2")
		if err != nil {
			t.Fatalf("second rotated token not found in embedded array: %v", err)
		}
		if second.Consumed {
			t.Fatal("second token should not be consumed yet")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func useDatabaseInitialToken(tx Tx, hash string) error {
	t, err := tx.InitialToken(hash)
	if err != nil {
		return err
	}
	if t.Revoked || !t.ExpiresAt.After(time.Now()) || t.Uses >= t.MaxUses {
		return errors.New("token not usable")
	}
	t.Uses++
	tx.SaveInitialToken(t)
	return nil
}

// Cancellation during a callback must reach database I/O and abort its writes,
// even when the callback itself returns nil.
func checkDatabaseCancellation(t *testing.T, store Store) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := store.Write(ctx, func(tx Tx) error {
		cancel()
		_ = tx.SaveUser(User{Profile: Profile{ID: "cancelled-user", Email: "cancelled@example.test"}})
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancelled transaction, got %v", err)
	}
	if err := store.Read(context.Background(), func(tx ReadTx) error {
		_, err := tx.User("cancelled-user")
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("cancelled write persisted: %v", err)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
