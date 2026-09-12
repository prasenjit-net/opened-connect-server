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

	"github.com/your-org/go-app-template/internal/config"
)

var (
	cfgFile string
	uiFS    fs.FS
	rootCmd = &cobra.Command{
		Use:   "go-app-template",
		Short: "Go + React starter with an embedded frontend",
		Long:  "A production-ready template for shipping a Go API and React frontend as a single binary.",
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
