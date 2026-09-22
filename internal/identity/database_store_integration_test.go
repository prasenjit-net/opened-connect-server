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
	store, err := NewPostgresStore(context.Background(), dsn, t.TempDir(), 4, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	exerciseDatabaseStore(t, store)
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
}

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
