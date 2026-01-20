package driver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"

	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

// ProgramStore provides metadata lookup for BPF programs.
type ProgramStore interface {
	// FindProgramByMetadata finds a program by a metadata key/value pair.
	FindProgramByMetadata(ctx context.Context, key, value string) (managed.Program, uint32, error)
}

// KernelOperations provides BPF map operations.
type KernelOperations interface {
	// RepinMap loads a pinned map and re-pins it to a new path.
	RepinMap(srcPath, dstPath string) error
}

// Driver implements a minimal CSI driver for learning purposes.
type Driver struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedNodeServer

	name     string
	version  string
	nodeID   string
	endpoint string
	logger   *slog.Logger

	// Optional dependencies for bpfman integration.
	// When nil, the driver operates in simple bind-mount mode.
	store  ProgramStore
	kernel KernelOperations

	// csiFsRoot is the root directory for per-pod bpffs mounts.
	// Defaults to /run/bpfman/csi/fs
	csiFsRoot string

	server *grpc.Server
}

// Option configures the Driver.
type Option func(*Driver)

// WithStore configures the program store for metadata lookups.
func WithStore(store ProgramStore) Option {
	return func(d *Driver) {
		d.store = store
	}
}

// WithKernel configures kernel operations for map re-pinning.
func WithKernel(kernel KernelOperations) Option {
	return func(d *Driver) {
		d.kernel = kernel
	}
}

// WithCSIFsRoot configures the root directory for per-pod bpffs mounts.
func WithCSIFsRoot(root string) Option {
	return func(d *Driver) {
		d.csiFsRoot = root
	}
}

// DefaultCSIFsRoot is the default root directory for per-pod bpffs mounts.
const DefaultCSIFsRoot = "/run/bpfman/csi/fs"

// New creates a new CSI driver instance.
func New(name, version, nodeID, endpoint string, logger *slog.Logger, opts ...Option) *Driver {
	d := &Driver{
		name:      name,
		version:   version,
		nodeID:    nodeID,
		endpoint:  endpoint,
		logger:    logger.With("component", "driver"),
		csiFsRoot: DefaultCSIFsRoot,
	}
	for _, opt := range opts {
		opt(d)
	}
	return d
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
