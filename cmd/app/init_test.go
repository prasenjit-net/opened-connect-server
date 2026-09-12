package app

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"github.com/spf13/cobra"
)

func TestInitCreatesAdminAndRefusesOverwrite(t *testing.T) {
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
	if err := runInit(command, nil); !errors.Is(err, identity.ErrInitialized) {
		t.Fatalf("--force overwrote the identity store: %v", err)
	}
}
