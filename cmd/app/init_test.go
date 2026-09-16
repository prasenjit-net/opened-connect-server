package app

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"github.com/prasenjit-net/opened-connect-server/internal/oidc"
	"github.com/spf13/cobra"
)

func TestInitCreatesAdminAndRerunIsIdempotent(t *testing.T) {
	oldPath, oldEmail, oldName, oldStdin, oldForce, oldDir, oldConfig := initPath, adminEmail, adminName, passwordStdin, initForce, dataDir, cfgFile
	t.Cleanup(func() {
		initPath, adminEmail, adminName, passwordStdin, initForce, dataDir, cfgFile = oldPath, oldEmail, oldName, oldStdin, oldForce, oldDir, oldConfig
	})
	initPath = t.TempDir()
	adminEmail = "first@example.com"
	adminName = "First Admin"
	passwordStdin = true
	initForce = false
	dataDir = ""
	cfgFile = ""
	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.SetIn(strings.NewReader("a private admin password\n"))
	command.SetOut(&output)
	command.SetErr(&output)
	if err := runInit(command, nil); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "a private admin password") {
		t.Fatal("password printed")
	}
	store, err := identity.NewFileStore(filepath.Join(initPath, "data"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	login, err := service.Login(context.Background(), adminEmail, "a private admin password", "")
	if err != nil {
		t.Fatal(err)
	}
	if login.User.Role != identity.RoleAdmin {
		t.Fatal("initial user is not admin")
	}
	initForce = true
	if err := runInit(command, nil); err != nil {
		t.Fatalf("rerunning init on an existing store should succeed: %v", err)
	}
	// Rerunning init (including --force) must not have touched the existing
	// administrator's password.
	if _, err := service.Login(context.Background(), adminEmail, "a private admin password", ""); err != nil {
		t.Fatalf("rerunning init changed the existing administrator: %v", err)
	}
}

func TestInitProvisionsSigningKeyWhenOIDCEnabled(t *testing.T) {
	oldPath, oldEmail, oldName, oldStdin, oldForce, oldDir, oldConfig := initPath, adminEmail, adminName, passwordStdin, initForce, dataDir, cfgFile
	t.Cleanup(func() {
		initPath, adminEmail, adminName, passwordStdin, initForce, dataDir, cfgFile = oldPath, oldEmail, oldName, oldStdin, oldForce, oldDir, oldConfig
	})
	initPath = t.TempDir()
	adminEmail = "admin@example.com"
	adminName = "Admin"
	passwordStdin = true
	initForce = false
	dataDir = ""
	cfgFile = ""
	t.Setenv("APP_OIDC_ENABLED", "true")

	var output bytes.Buffer
	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.SetIn(strings.NewReader("a private admin password\n"))
	command.SetOut(&output)
	command.SetErr(&output)
	if err := runInit(command, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "Signing key") {
		t.Fatalf("expected signing key provisioning output, got: %s", output.String())
	}
	keys, err := oidc.NewFileKeyStore(filepath.Join(initPath, "data", "signing-keys"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Load(context.Background()); err != nil {
		t.Fatalf("expected a valid signing key after init: %v", err)
	}
}

func TestInitOnExistingUsersOnlyProvisionsMissingKeys(t *testing.T) {
	oldPath, oldEmail, oldName, oldStdin, oldForce, oldDir, oldConfig := initPath, adminEmail, adminName, passwordStdin, initForce, dataDir, cfgFile
	t.Cleanup(func() {
		initPath, adminEmail, adminName, passwordStdin, initForce, dataDir, cfgFile = oldPath, oldEmail, oldName, oldStdin, oldForce, oldDir, oldConfig
	})
	initPath = t.TempDir()
	adminEmail = "admin@example.com"
	adminName = "Admin"
	passwordStdin = true
	initForce = false
	dataDir = ""
	cfgFile = ""

	// First init with OIDC disabled: creates the administrator, no keys yet.
	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.SetIn(strings.NewReader("a private admin password\n"))
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	if err := runInit(command, nil); err != nil {
		t.Fatal(err)
	}
	keyDir := filepath.Join(initPath, "data", "signing-keys")
	if _, err := oidc.NewFileKeyStore(keyDir); err != nil {
		t.Fatal(err)
	}
	if entries, _ := filepath.Glob(filepath.Join(keyDir, "*")); len(entries) != 0 {
		t.Fatal("expected no signing key material before OIDC was enabled")
	}

	// Enable OIDC and rerun init: the existing user/password must be
	// untouched, and a signing key must now be provisioned.
	t.Setenv("APP_OIDC_ENABLED", "true")
	store, err := identity.NewFileStore(filepath.Join(initPath, "data"))
	if err != nil {
		t.Fatal(err)
	}
	service, err := identity.NewService(store, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := runInit(command, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Login(context.Background(), adminEmail, "a private admin password", ""); err != nil {
		t.Fatalf("enabling OIDC on an existing install changed the administrator: %v", err)
	}
	keys, err := oidc.NewFileKeyStore(keyDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Load(context.Background()); err != nil {
		t.Fatalf("expected a signing key to be provisioned for the existing install: %v", err)
	}
}

func TestInitForceNeverReplacesValidSigningKey(t *testing.T) {
	oldPath, oldEmail, oldName, oldStdin, oldForce, oldDir, oldConfig := initPath, adminEmail, adminName, passwordStdin, initForce, dataDir, cfgFile
	t.Cleanup(func() {
		initPath, adminEmail, adminName, passwordStdin, initForce, dataDir, cfgFile = oldPath, oldEmail, oldName, oldStdin, oldForce, oldDir, oldConfig
	})
	initPath = t.TempDir()
	adminEmail = "admin@example.com"
	adminName = "Admin"
	passwordStdin = true
	initForce = true
	dataDir = ""
	cfgFile = ""
	t.Setenv("APP_OIDC_ENABLED", "true")

	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.SetIn(strings.NewReader("a private admin password\n"))
	command.SetOut(&bytes.Buffer{})
	command.SetErr(&bytes.Buffer{})
	if err := runInit(command, nil); err != nil {
		t.Fatal(err)
	}
	keys, err := oidc.NewFileKeyStore(filepath.Join(initPath, "data", "signing-keys"))
	if err != nil {
		t.Fatal(err)
	}
	first, err := keys.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if err := runInit(command, nil); err != nil {
		t.Fatal(err)
	}
	second, err := keys.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.ActiveKID != second.ActiveKID {
		t.Fatalf("init --force replaced a valid signing key: %s vs %s", first.ActiveKID, second.ActiveKID)
	}
}
