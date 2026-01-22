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
	Socket     string `name:"socket" help:"Unix socket path for gRPC server." default:"${default_socket_path}"`
	TCPAddress string `name:"tcp-address" help:"TCP address for gRPC server. Binds to localhost for security." default:"localhost:50051"`
	CSISupport bool   `name:"csi-support" help:"Enable CSI driver support."`
	CSISocket  string `name:"csi-socket" help:"Unix socket path for CSI driver." default:"${default_csi_socket}"`
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
		SocketPath:    c.Socket,
		TCPAddress:    c.TCPAddress,
		DBPath:        cli.DB.Path,
		CSISupport:    c.CSISupport,
		CSISocketPath: c.CSISocket,
		Logger:        logger,
		Config:        appConfig,
	}

	// Create context that cancels on SIGINT/SIGTERM
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	return server.Run(ctx, cfg)
}
