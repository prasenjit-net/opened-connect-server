package app

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/prasenjit-net/openid-connect-server/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print build metadata",
	Run: func(cmd *cobra.Command, args []string) {
		info := version.Current()
		fmt.Printf("version=%s commit=%s buildDate=%s\n", info.Version, info.Commit, info.BuildDate)
	},
}
