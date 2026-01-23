package driver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"

	"github.com/frobware/go-bpfman"
)

// ProgramStore provides metadata lookup for BPF programs.
type ProgramStore interface {
	// FindProgramByMetadata finds a program by a metadata key/value pair.
	FindProgramByMetadata(ctx context.Context, key, value string) (bpfman.Program, uint32, error)
}

// KernelOperations provides BPF map operations.
type KernelOperations interface {
	// RepinMap loads a pinned map and re-pins it to a new path.
	RepinMap(srcPath, dstPath string) error
}

// Driver implements a CSI node plugin that exposes BPF maps to pods.
type Driver struct {
	csi.UnimplementedIdentityServer
	csi.UnimplementedNodeServer

	name     string // CSI driver name for registration.
	version  string // Driver version reported to kubelet.
	nodeID   string // Kubernetes node name.
	endpoint string // CSI socket endpoint (unix:// or tcp://).
	logger   *slog.Logger

	// store provides program metadata lookups. When nil, the driver
	// operates in simple bind-mount mode without bpfman integration.
	store ProgramStore

	// kernel provides BPF map operations. When nil, map re-pinning
	// is unavailable.
	kernel KernelOperations

	// csiFsRoot is the root directory for per-pod bpffs mounts.
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

// parseEndpoint parses an endpoint URL and returns the network type and
// address. Supported schemes are "unix" (returns path) and "tcp" (returns
// host:port).
func parseEndpoint(endpoint string) (string, string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", "", err
	}

	switch u.Scheme {
	case "unix":
		return "unix", u.Path, nil
	case "tcp":
		return "tcp", u.Host, nil
	default:
		return "", "", fmt.Errorf("unsupported endpoint scheme: %s", u.Scheme)
	}
}
