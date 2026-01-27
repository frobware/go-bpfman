package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/frobware/go-bpfman/server"
)

// ServeCmd starts the gRPC daemon.
type ServeCmd struct {
	TCPAddress   string `name:"tcp-address" help:"TCP address for gRPC server." default:"[::]:50051"`
	CSISupport   bool   `name:"csi-support" help:"Enable CSI driver support."`
	PprofAddress string `name:"pprof-address" help:"Address for pprof HTTP server. Port 0 selects an ephemeral port. Empty string disables." env:"BPFMAN_PPROF_ADDRESS" default:"localhost:0"`
}

// Run executes the serve command.
func (c *ServeCmd) Run(cli *CLI) error {
	logger, err := cli.LoggerFromConfig()
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	appConfig, err := cli.LoadConfig()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg := server.RunConfig{
		Dirs:         cli.RuntimeDirs(),
		TCPAddress:   c.TCPAddress,
		CSISupport:   c.CSISupport,
		PprofAddress: c.PprofAddress,
		Logger:       logger,
		Config:       appConfig,
	}

	// Create context that cancels on SIGINT/SIGTERM.
	// The first signal initiates graceful shutdown; a second signal
	// forces an immediate exit.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	go func() {
		// After the first signal, NotifyContext stops catching.
		// Re-register so the next signal reaches us.
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-ctx.Done()
		logger.Info("shutting down gracefully, send another signal to force exit")
		<-sig
		logger.Warn("received second signal, forcing exit")
		os.Exit(1)
	}()

	return server.Run(ctx, cfg)
}
