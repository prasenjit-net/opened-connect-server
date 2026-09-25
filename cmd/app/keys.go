package app

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/prasenjit-net/openid-connect-server/internal/config"
	"github.com/prasenjit-net/openid-connect-server/internal/oidc"
)

var keysCmd = &cobra.Command{Use: "keys", Short: "Manage OpenID Connect provider signing keys"}
var keysStatusCmd = &cobra.Command{Use: "status", Short: "Report the active and retired signing keys", Args: cobra.NoArgs, RunE: runKeysStatus}
var keysRotateCmd = &cobra.Command{Use: "rotate", Short: "Generate and activate a new signing key, retiring the previous one", Args: cobra.NoArgs, RunE: runKeysRotate}

func init() {
	keysCmd.AddCommand(keysStatusCmd)
	keysCmd.AddCommand(keysRotateCmd)
	rootCmd.AddCommand(keysCmd)
}

// keyStoreFromConfig resolves the signing key directory the same way
// `serve` resolves the identity store: from the global viper instance that
// cobra.OnInitialize(initConfig) has already populated from config.yaml/
// .env/environment/flags, relative to the current working directory.
func keyStoreFromConfig() (*oidc.KeyStore, error) {
	cfg, err := config.Load(viper.GetViper())
	if err != nil {
		return nil, err
	}
	return oidc.NewFileKeyStore(filepath.Join(cfg.Storage.DataDir, "signing-keys"))
}

func runKeysStatus(cmd *cobra.Command, args []string) error {
	keys, err := keyStoreFromConfig()
	if err != nil {
		return err
	}
	active, records, err := keys.Status(cmd.Context())
	if err != nil {
		return err
	}
	if active == "" {
		fmt.Fprintln(cmd.OutOrStdout(), "No signing key has been provisioned. Run `init` with oidc.enabled: true, or `keys rotate`.")
		return nil
	}
	for _, r := range records {
		state := "retired"
		if r.KID == active {
			state = "active"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\texpires %s\n", r.KID, state, r.NotAfter.Format(time.RFC3339))
	}
	return nil
}

func runKeysRotate(cmd *cobra.Command, args []string) error {
	keys, err := keyStoreFromConfig()
	if err != nil {
		return err
	}
	record, err := keys.Rotate(cmd.Context())
	if err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Rotated to signing key %s (expires %s). The previous key remains published in /jwks until manually removed.\n", record.KID, record.NotAfter.Format(time.RFC3339))
	return nil
}
