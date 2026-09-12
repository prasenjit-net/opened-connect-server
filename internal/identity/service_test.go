package identity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

const password = "a secure test password"

func fixture(t *testing.T) (*Service, *FileStore, Profile) {
	t.Helper()
	store, err := NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewService(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	u, err := s.Bootstrap(context.Background(), "Admin", "admin@example.com", password)
	if err != nil {
		t.Fatal(err)
	}
	return s, store, u
}
func TestPasswords(t *testing.T) {
	one, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	two, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if one == two || !VerifyPassword(one, password) || VerifyPassword(one, "bad") {
		t.Fatal("password verification or salt failed")
	}
	for _, value := range []string{"", "short"} {
		if _, err = HashPassword(value); err == nil {
			t.Fatal("weak password accepted")
		}
	}
	if VerifyPassword("$argon2id$v=19$m=999999999,t=2,p=1$x$x", password) {
		t.Fatal("unbounded hash parameters accepted")
	}
}
func TestBootstrapExpiryAndRollback(t *testing.T) {
	ctx := context.Background()
	s, store, _ := fixture(t)
	if _, err := s.Bootstrap(ctx, "Second", "second@example.com", password); !errors.Is(err, ErrInitialized) {
		t.Fatal("bootstrap overwrote users", err)
	}
	session, err := s.Login(ctx, "admin@example.com", password, "")
	if err != nil {
		t.Fatal(err)
	}
	original := s.now
	s.now = func() time.Time { return original().Add(2 * time.Hour) }
	if _, err = s.Authenticate(ctx, session.Session.Hash); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("expired session accepted", err)
	}
	s.now = original
	rollback := errors.New("rollback")
	if err = store.Write(ctx, func(tx Tx) error { tx.DeleteSession(session.Session.Hash); return rollback }); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if _, err = s.Authenticate(ctx, session.Session.Hash); err != nil {
		t.Fatal("transaction did not roll back", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(store.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatal("identity file permissions are not private")
		}
	}
}
func TestConcurrentLastAdminProtection(t *testing.T) {
	ctx := context.Background()
	s, store, first := fixture(t)
	a, err := s.Login(ctx, first.Email, password, "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.CreateUser(ctx, a.Session.Hash, UserInput{Name: "Second", Email: "second@example.com", Role: RoleAdmin}, password)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Login(ctx, second.Email, password, "")
	if err != nil {
		t.Fatal(err)
	}
	otherStore, err := NewFileStore(filepath.Dir(store.path))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewService(otherStore, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i, item := range []struct {
		u       Profile
		session LoginResult
	}{{first, a}, {second, b}} {
		wg.Add(1)
		go func(i int, item struct {
			u       Profile
			session LoginResult
		}) {
			defer wg.Done()
			svc := s
			if i == 1 {
				svc = other
			}
			_, err := svc.UpdateUser(ctx, item.session.Session.Hash, item.u.ID, UserInput{Name: item.u.Name, Email: item.u.Email, Role: RoleUser, Active: true})
			errs <- err
		}(i, item)
	}
	wg.Wait()
	close(errs)
	success, blocked := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrLastAdmin) {
			blocked++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || blocked != 1 {
		t.Fatalf("last admin invariant failed: success=%d blocked=%d", success, blocked)
	}
}
func TestCorruptStoreFailsClosed(t *testing.T) {
	_, store, _ := fixture(t)
	if err := os.WriteFile(store.path, []byte(`{"version":9}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := store.Read(context.Background(), func(ReadTx) error { return nil }); err == nil {
		t.Fatal("corrupt store accepted")
	}
}
