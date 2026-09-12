package app

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
)

var (
	initForce     bool
	initPath      string
	adminEmail    string
	adminName     string
	passwordStdin bool
)
var initCmd = &cobra.Command{Use: "init", Short: "Initialize local storage and create the first administrator", Args: cobra.NoArgs, RunE: runInit}

func init() {
	initCmd.Flags().BoolVarP(&initForce, "force", "f", false, "Overwrite configuration files only; never overwrite existing users")
	initCmd.Flags().StringVarP(&initPath, "path", "p", ".", "Project directory to initialize")
	initCmd.Flags().StringVar(&adminEmail, "admin-email", "", "Initial administrator email (prompted when omitted)")
	initCmd.Flags().StringVar(&adminName, "admin-name", "Administrator", "Initial administrator display name")
	initCmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read the administrator password from stdin instead of a hidden prompt")
}

func runInit(cmd *cobra.Command, args []string) error {
	abs, err := filepath.Abs(initPath)
	if err != nil {
		return err
	}
	v := viper.New()
	config.SetDefaults(v)
	v.SetEnvPrefix("APP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	configPath := filepath.Join(abs, "config.yaml")
	if cfgFile != "" {
		configPath = cfgFile
	}
	v.SetConfigFile(configPath)
	if err = v.ReadInConfig(); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read config: %w", err)
	}
	if dataDir != "" {
		v.Set("storage.dataDir", dataDir)
	}
	cfg, err := config.Load(v)
	if err != nil {
		return err
	}
	dir := cfg.Storage.DataDir
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(abs, dir)
	}
	store, err := identity.NewFileStore(dir)
	if err != nil {
		return err
	}
	service, err := identity.NewService(store, cfg.Auth.SessionTTL)
	if err != nil {
		return err
	}
	initialized, err := service.Initialized(cmd.Context())
	if err != nil {
		return err
	}
	if initialized {
		return identity.ErrInitialized
	}
	email := strings.TrimSpace(adminEmail)
	if email == "" {
		if passwordStdin || !term.IsTerminal(int(os.Stdin.Fd())) {
			return fmt.Errorf("--admin-email is required for noninteractive initialization")
		}
		fmt.Fprint(cmd.ErrOrStderr(), "Administrator email: ")
		email, err = bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if err != nil {
			return err
		}
		email = strings.TrimSpace(email)
	}
	password, err := readAdminPassword(cmd, passwordStdin)
	if err != nil {
		return err
	}
	// Bootstrap is atomic and refuses an existing identity store, including with --force.
	user, err := service.Bootstrap(cmd.Context(), adminName, email, password)
	if err != nil {
		return err
	}
	if err = config.InitProject(abs, initForce); err != nil {
		return fmt.Errorf("administrator created, but config initialization failed: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Initialized administrator %s in %s\n", user.Email, dir)
	fmt.Fprintln(cmd.OutOrStdout(), "Start the server with: opened-connect-server serve")
	return nil
}
func readAdminPassword(cmd *cobra.Command, stdin bool) (string, error) {
	if stdin {
		content, err := io.ReadAll(io.LimitReader(cmd.InOrStdin(), 1025))
		if err != nil {
			return "", err
		}
		if len(content) > 1024 {
			return "", fmt.Errorf("password input is too long")
		}
		return strings.TrimSuffix(strings.TrimSuffix(string(content), "\n"), "\r"), nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("use --password-stdin for noninteractive initialization")
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Administrator password (12–128 characters): ")
	first, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	fmt.Fprint(cmd.ErrOrStderr(), "Confirm password: ")
	second, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(cmd.ErrOrStderr())
	if err != nil {
		return "", err
	}
	if string(first) != string(second) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(first), nil
}
