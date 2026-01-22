package cli

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/frobware/go-bpfman/pkg/bpfman/server"
)

// ServeCmd starts the gRPC daemon.
type ServeCmd struct {
	TCPAddress string `name:"tcp-address" help:"TCP address for gRPC server." default:"[::]:50051"`
	CSISupport bool   `name:"csi-support" help:"Enable CSI driver support."`
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
		Dirs:       cli.RuntimeDirs(),
		TCPAddress: c.TCPAddress,
		CSISupport: c.CSISupport,
		Logger:     logger,
		Config:     appConfig,
	}

	// Create context that cancels on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return server.Run(ctx, cfg)
}
