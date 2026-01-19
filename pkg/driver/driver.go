package driver

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
)

// Driver implements a minimal CSI driver for learning purposes.
type Driver struct {
	name     string
	version  string
	nodeID   string
	endpoint string
	logger   *slog.Logger

	server *grpc.Server
}

// New creates a new CSI driver instance.
func New(name, version, nodeID, endpoint string, logger *slog.Logger) *Driver {
	return &Driver{
		name:     name,
		version:  version,
		nodeID:   nodeID,
		endpoint: endpoint,
		logger:   logger.With("component", "driver"),
	}
}

// Run starts the CSI driver gRPC server.
func (d *Driver) Run() error {
	scheme, addr, err := parseEndpoint(d.endpoint)
	if err != nil {
		return fmt.Errorf("failed to parse endpoint: %w", err)
	}

	if scheme == "unix" {
		if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove existing socket: %w", err)
		}
	}

	listener, err := net.Listen(scheme, addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s://%s: %w", scheme, addr, err)
	}

	d.server = grpc.NewServer()

	csi.RegisterIdentityServer(d.server, d)
	csi.RegisterNodeServer(d.server, d)

	d.logger.Info("gRPC server listening",
		"scheme", scheme,
		"address", addr,
	)

	return d.server.Serve(listener)
}

// Stop gracefully stops the gRPC server.
func (d *Driver) Stop() {
	if d.server != nil {
		d.logger.Info("stopping gRPC server")
		d.server.GracefulStop()
	}
}

func parseEndpoint(endpoint string) (string, string, error) {
	if strings.HasPrefix(endpoint, "unix://") {
		return "unix", strings.TrimPrefix(endpoint, "unix://"), nil
	}
	if strings.HasPrefix(endpoint, "tcp://") {
		return "tcp", strings.TrimPrefix(endpoint, "tcp://"), nil
	}
	return "", "", fmt.Errorf("unsupported endpoint scheme: %s", endpoint)
}
