package app

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/prasenjit-net/opened-connect-server/internal/config"
	"github.com/prasenjit-net/opened-connect-server/internal/identity"
	"github.com/prasenjit-net/opened-connect-server/internal/oidc"
)

var (
	initForce                bool
	initPath                 string
	adminEmail               string
	adminName                string
	passwordStdin            bool
	initRegistrationEnabled  bool
	initRefreshTokensEnabled bool
	initPasswordGrantEnabled bool
	initAudience             string
	initAudienceScopes       []string
)
var initCmd = &cobra.Command{Use: "init", Short: "Initialize local storage and create the first administrator", Args: cobra.NoArgs, RunE: runInit}

func init() {
	initCmd.Flags().BoolVarP(&initForce, "force", "f", false, "Overwrite configuration files only; never overwrite existing users")
	initCmd.Flags().StringVarP(&initPath, "path", "p", ".", "Project directory to initialize")
	initCmd.Flags().StringVar(&adminEmail, "admin-email", "", "Initial administrator email (prompted when omitted)")
	initCmd.Flags().StringVar(&adminName, "admin-name", "Administrator", "Initial administrator display name")
	initCmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "Read the administrator password from stdin instead of a hidden prompt")
	initCmd.Flags().BoolVar(&initRegistrationEnabled, "registration-enabled", false, "Enable token-protected dynamic client registration")
	initCmd.Flags().BoolVar(&initRefreshTokensEnabled, "refresh-tokens-enabled", false, "Enable refresh-token issuance for permitted clients")
	initCmd.Flags().BoolVar(&initPasswordGrantEnabled, "password-grant-enabled", false, "Enable the legacy password grant")
	initCmd.Flags().StringVar(&initAudience, "audience", "", "OAuth resource audience URI (requires --audience-scope)")
	initCmd.Flags().StringSliceVar(&initAudienceScopes, "audience-scope", nil, "OAuth scope allowed for --audience; repeat or use comma-separated values")
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
	options, err := initProjectOptions(cmd)
	if err != nil {
		return err
	}
	if options.HasSelections() && !initForce {
		if _, statErr := os.Stat(configPath); statErr == nil {
			return fmt.Errorf("initialization options would not update existing %s; edit it directly or rerun init with --force", configPath)
		} else if !os.IsNotExist(statErr) {
			return fmt.Errorf("check config: %w", statErr)
		}
	}
	if options.RegistrationEnabled != nil {
		v.Set("oidc.registrationEnabled", *options.RegistrationEnabled)
	}
	if options.RefreshTokensEnabled != nil {
		v.Set("oauth.refreshTokensEnabled", *options.RefreshTokensEnabled)
	}
	if options.PasswordGrantEnabled != nil {
		v.Set("oauth.passwordGrantEnabled", *options.PasswordGrantEnabled)
	}
	if len(options.Resources) > 0 {
		v.Set("oauth.resources", options.Resources)
	}
	if options.EnablesOIDC() {
		v.Set("oidc.enabled", true)
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
	if !initialized {
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
		fmt.Fprintf(cmd.OutOrStdout(), "Initialized administrator %s in %s\n", user.Email, dir)
	} else {
		// Rerunning init (including with --force) never touches an existing
		// identity store; it only provisions whatever is still missing below.
		fmt.Fprintln(cmd.OutOrStdout(), "Identity store already initialized; skipping administrator setup.")
	}
	if cfg.OIDC.Enabled {
		keys, err := oidc.NewFileKeyStore(filepath.Join(dir, "signing-keys"))
		if err != nil {
			return fmt.Errorf("prepare signing key directory: %w", err)
		}
		// Provision is idempotent and never wired to --force: it preserves any
		// valid existing key rather than replacing it.
		record, err := keys.Provision(cmd.Context())
		if err != nil {
			return fmt.Errorf("provision signing key: %w", err)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Signing key %s active (expires %s)\n", record.KID, record.NotAfter.Format(time.RFC3339))
	}
	if err = config.InitProjectWithOptions(abs, initForce, options); err != nil {
		return fmt.Errorf("initialization succeeded, but config initialization failed: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Start the server with: opened-connect-server serve")
	return nil
}

func initProjectOptions(cmd *cobra.Command) (config.InitProjectOptions, error) {
	options := config.InitProjectOptions{}
	if cmd.Flags().Changed("registration-enabled") {
		options.RegistrationEnabled = &initRegistrationEnabled
	}
	if cmd.Flags().Changed("refresh-tokens-enabled") {
		options.RefreshTokensEnabled = &initRefreshTokensEnabled
	}
	if cmd.Flags().Changed("password-grant-enabled") {
		options.PasswordGrantEnabled = &initPasswordGrantEnabled
	}
	audience := strings.TrimSpace(initAudience)
	if audience == "" && len(initAudienceScopes) > 0 {
		return options, fmt.Errorf("--audience-scope requires --audience")
	}
	if audience != "" {
		scopes := []string{}
		for _, scope := range initAudienceScopes {
			for _, value := range strings.Split(scope, ",") {
				if value = strings.TrimSpace(value); value != "" {
					scopes = append(scopes, value)
				}
			}
		}
		if len(scopes) == 0 {
			return options, fmt.Errorf("--audience requires at least one --audience-scope")
		}
		options.Resources = []identity.Resource{{Audience: audience, Enabled: true, Scopes: scopes}}
	}
	return options, nil
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
