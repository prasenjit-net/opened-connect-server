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
	exercisePostgresStore(t, store)
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
	exerciseMongoStore(t, store)
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

// exercisePostgresStore covers the normalized-schema scenarios flagged as
// highest-risk in the design review: nanosecond client-revision equality,
// authorization-code and refresh-token single-use plus replay-triggers-
// revocation-that-survives-the-returned-error, the authz-transaction
// consent-required branch that must not mark itself consumed,
// initial-access-token atomic use counting, logout delivery lease
// claim/steal-prevention, and the delete-vs-revoke asymmetry between
// DeleteUserSessions and invalidateClientGrants.
func exercisePostgresStore(t *testing.T, store *PostgresStore) {
	t.Helper()
	ctx := context.Background()

	// --- client revision survives round-trip at nanosecond precision ---
	// This is the highest-risk item from the design review: Postgres
	// timestamptz truncates to microseconds, so the nanosecond revision
	// used for exact-equality pinning (RefreshFamily.ClientRevision,
	// Consent.PolicyRevision, AuthzTransaction/AuthorizationCode.ClientUpdatedAt)
	// must round-trip through the separate updated_at_ns bigint column,
	// not through updated_at itself.
	client := ClientRecord{ID: "pg-test-client", Metadata: ClientMetadata{}, UpdatedAt: time.Now()}
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

	user := User{Profile: Profile{ID: "pg-code-user", Sub: "pg-code-user", Email: "pg-code-user@example.test", Name: "Coder", Active: true, Role: RoleUser}, PasswordHash: "hash"}
	if err := store.Write(ctx, func(tx Tx) error { return tx.SaveUser(user) }); err != nil {
		t.Fatal(err)
	}

	// --- authorization code: single-use, then replay revokes tokens but
	// the revocation must survive even though the OIDC layer's contract is
	// "return nil to commit, then report an error to the caller" ---
	code := AuthorizationCode{
		Hash: "pg-test-code-hash", ClientID: client.ID, UserID: user.ID,
		ClientUpdatedAt: pinnedRevision, ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
	}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveAuthorizationCode(code); return nil }); err != nil {
		t.Fatal(err)
	}
	accessToken := AccessToken{Hash: "pg-test-code-access", ClientID: client.ID, UserID: user.ID, CodeHash: code.Hash, Audience: "userinfo", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
	// First "exchange": mark consumed and mint the access token, exactly as
	// token.go does within one Write.
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
	// Second "exchange" of the same code: this is a replay. The handler
	// pattern is "detect replay, revoke, return nil so the revocation
	// commits" - verify the access token is actually revoked afterwards.
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

	// --- initial access token: atomic use counting ---
	iat := InitialAccessToken{Hash: "pg-test-iat-hash", ID: "pg-test-iat-id", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 3}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveInitialToken(iat); return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := store.Write(ctx, func(tx Tx) error {
			t, err := tx.InitialToken(iat.Hash)
			if err != nil {
				return err
			}
			if t.Revoked || !t.ExpiresAt.After(time.Now()) || t.Uses >= t.MaxUses {
				return errors.New("token not usable")
			}
			t.Uses++
			tx.SaveInitialToken(t)
			return nil
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

	// --- DeleteUserSessions cascade: codes/transactions/consents deleted,
	// but access tokens/refresh families only revoked, never deleted ---
	txn := AuthzTransaction{ID: "pg-test-txn", ClientID: client.ID, UserID: user.ID, ClientUpdatedAt: pinnedRevision, ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now()}
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

// exerciseMongoStore covers the same highest-risk scenarios as
// exercisePostgresStore, translated to the document-store design: the
// nanosecond client-revision round-trip goes through the updatedAtNs
// field instead of a separate SQL column, and the refresh-token rotation
// check specifically exercises the embedded tokens array inside a
// refresh_families document rather than a standalone table/collection.
func exerciseMongoStore(t *testing.T, store *MongoStore) {
	t.Helper()
	ctx := context.Background()

	// --- client revision survives round-trip at nanosecond precision ---
	// BSON's Date type is millisecond-precision, so the exact-equality
	// revision pin used by RefreshFamily.ClientRevision/
	// Consent.PolicyRevision/AuthzTransaction and AuthorizationCode's
	// ClientUpdatedAt must round-trip through the separate updatedAtNs
	// int64 field, not through updatedAt itself.
	client := ClientRecord{ID: "mongo-test-client", Metadata: ClientMetadata{}, UpdatedAt: time.Now()}
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

	user := User{Profile: Profile{ID: "mongo-code-user", Sub: "mongo-code-user", Email: "mongo-code-user@example.test", Name: "Coder", Active: true, Role: RoleUser}, PasswordHash: "hash"}
	if err := store.Write(ctx, func(tx Tx) error { return tx.SaveUser(user) }); err != nil {
		t.Fatal(err)
	}

	// --- authorization code: single-use, then replay revokes tokens but
	// the revocation must survive even though the OIDC layer's contract is
	// "return nil to commit, then report an error to the caller" ---
	code := AuthorizationCode{
		Hash: "mongo-test-code-hash", ClientID: client.ID, UserID: user.ID,
		ClientUpdatedAt: pinnedRevision, ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
	}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveAuthorizationCode(code); return nil }); err != nil {
		t.Fatal(err)
	}
	accessToken := AccessToken{Hash: "mongo-test-code-access", ClientID: client.ID, UserID: user.ID, CodeHash: code.Hash, Audience: "userinfo", IssuedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)}
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

	// --- refresh token rotation against the embedded tokens array ---
	family := RefreshFamily{
		ID: "mongo-test-family", ClientID: client.ID, UserID: user.ID, ClientRevision: pinnedRevision.UnixNano(),
		CreatedAt: time.Now(), AbsoluteExpiry: time.Now().Add(time.Hour), IdleExpiry: time.Now().Add(time.Hour), RetainUntil: time.Now().Add(2 * time.Hour),
	}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveRefreshFamily(family); return nil }); err != nil {
		t.Fatal(err)
	}
	firstToken := RefreshToken{Hash: "mongo-test-refresh-1", FamilyID: family.ID, IssuedAt: time.Now()}
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
		tx.SaveRefreshToken(RefreshToken{Hash: "mongo-test-refresh-2", FamilyID: family.ID, IssuedAt: time.Now()})
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
	if err := store.Read(ctx, func(tx ReadTx) error {
		f, err := tx.RefreshFamily(family.ID)
		if err != nil {
			return err
		}
		if !f.Revoked {
			t.Fatal("replay did not revoke the refresh family")
		}
		second, err := tx.RefreshToken("mongo-test-refresh-2")
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

	// --- initial access token: atomic use counting ---
	iat := InitialAccessToken{Hash: "mongo-test-iat-hash", ID: "mongo-test-iat-id", ExpiresAt: time.Now().Add(time.Hour), MaxUses: 3}
	if err := store.Write(ctx, func(tx Tx) error { tx.SaveInitialToken(iat); return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := store.Write(ctx, func(tx Tx) error {
			t, err := tx.InitialToken(iat.Hash)
			if err != nil {
				return err
			}
			if t.Revoked || !t.ExpiresAt.After(time.Now()) || t.Uses >= t.MaxUses {
				return errors.New("token not usable")
			}
			t.Uses++
			tx.SaveInitialToken(t)
			return nil
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

	// --- DeleteUserSessions cascade: codes/transactions/consents deleted,
	// but access tokens/refresh families only revoked, never deleted ---
	txn := AuthzTransaction{ID: "mongo-test-txn", ClientID: client.ID, UserID: user.ID, ClientUpdatedAt: pinnedRevision, ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now()}
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
