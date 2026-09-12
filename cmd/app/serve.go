package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/your-org/go-app-template/internal/config"
	"github.com/your-org/go-app-template/internal/logging"
	"github.com/your-org/go-app-template/internal/server"
	"github.com/your-org/go-app-template/internal/version"
)

var (
	devMode  bool
	portFlag int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HTTP server",
	RunE:  runServe,
}

func init() {
	serveCmd.Flags().BoolVar(&devMode, "dev", false, "Enable development mode and proxy UI requests to Vite")
	serveCmd.Flags().IntVarP(&portFlag, "port", "p", 0, "Override server port")
	_ = viper.BindPFlag("server.port", serveCmd.Flags().Lookup("port"))
}

func runServe(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load(viper.GetViper())
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if portFlag > 0 {
		cfg.Server.Port = portFlag
	}

	logger := logging.New(cfg.Logging)
	buildInfo := version.Current()

	appServer, err := server.New(cfg, logger, buildInfo, server.Options{
		DevMode: devMode,
		UIFS:    uiFS,
	})
	if err != nil {
		return err
	}

	httpServer := &http.Server{
		Addr:         cfg.Server.Address(),
		Handler:      appServer.Handler(),
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("starting server",
			"addr", httpServer.Addr,
			"env", cfg.App.Env,
			"dev_mode", devMode,
			"ui_proxy", cfg.UI.DevProxyURL,
		)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer cancel()

	return httpServer.Shutdown(shutdownCtx)
}
