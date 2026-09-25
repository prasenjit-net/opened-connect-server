package app

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/prasenjit-net/openid-connect-server/internal/config"
)

var (
	cfgFile string
	dataDir string
	uiFS    fs.FS
	rootCmd = &cobra.Command{
		Use:   "openid-connect-server",
		Short: "OpenID Connect Server with an embedded administration console",
		Long:  "Run OpenID Connect Server and its administration console from a single binary.",
	}
)

func Execute(files fs.FS) {
	uiFS = files
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default: ./config.yaml)")
	rootCmd.PersistentFlags().StringVar(&dataDir, "data-dir", "", "Directory for local users and sessions (default: ./data)")
	_ = viper.BindPFlag("storage.dataDir", rootCmd.PersistentFlags().Lookup("data-dir"))
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(versionCmd)
}

func initConfig() {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}

	for _, candidate := range []string{filepath.Join(cwd, ".env"), filepath.Join(cwd, ".env.local")} {
		_ = godotenv.Load(candidate)
	}

	v := viper.GetViper()
	config.SetDefaults(v)
	v.SetEnvPrefix("APP")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		v.AddConfigPath(cwd)
	}

	if err := v.ReadInConfig(); err == nil {
		fmt.Fprintf(os.Stderr, "Using config file: %s\n", v.ConfigFileUsed())
	}
}
