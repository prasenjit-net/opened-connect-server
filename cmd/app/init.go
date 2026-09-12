package app

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/your-org/go-app-template/internal/config"
)

var (
	initForce bool
	initPath  string
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Write starter config and local development files",
	RunE:  runInit,
}

func init() {
	initCmd.Flags().BoolVarP(&initForce, "force", "f", false, "Overwrite existing files")
	initCmd.Flags().StringVarP(&initPath, "path", "p", ".", "Directory to initialize")
}

func runInit(cmd *cobra.Command, args []string) error {
	absPath, err := filepath.Abs(initPath)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	if err := config.InitProject(absPath, initForce); err != nil {
		return err
	}

	fmt.Printf("Initialized project files in %s\n", absPath)
	fmt.Println("Next steps:")
	fmt.Println("  1. cp .env.example .env")
	fmt.Println("  2. make install-deps")
	fmt.Println("  3. make dev-all")

	return nil
}
