package client

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"google.golang.org/grpc"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/config"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/ebpf"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	"github.com/frobware/go-bpfman/pkg/bpfman/server"
	pb "github.com/frobware/go-bpfman/pkg/bpfman/server/pb"
)

// EphemeralClient spawns an in-process gRPC server and connects to it.
// This ensures CLI commands use the same code path as remote clients,
// making gRPC handlers the canonical implementation.
//
// Operations are routed as follows:
//   - Daemon ops (load, attach, etc.): via ephemeral gRPC server
//   - Host ops (GC, reconcile): direct to manager
//   - Image ops: pull locally, load via gRPC
type EphemeralClient struct {
	remote     *RemoteClient
	mgr        *manager.Manager // Direct access for host-only operations
	puller     interpreter.ImagePuller
	grpcServer *grpc.Server
	listener   net.Listener
	socketPath string // Cleaned up on Close
	store      *sqlite.Store
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	logger     *slog.Logger
}

// NewEphemeral creates an EphemeralClient that spawns an in-process gRPC
// server using a temporary Unix socket.
// The server is started immediately and the client connects to it.
// The socket file is removed when Close is called.
func NewEphemeral(dirs config.RuntimeDirs, logger *slog.Logger) (*EphemeralClient, error) {
	// Ensure runtime directories exist and bpffs is mounted
	if err := dirs.EnsureDirectories(); err != nil {
		return nil, fmt.Errorf("ensure directories: %w", err)
	}

	// Open SQLite store
	st, err := sqlite.New(dirs.DBPath(), logger)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}

	// Create kernel adapter
	kernel := ebpf.New()

	// Create manager for direct GC operations
	mgr := manager.New(dirs, st, kernel, logger)

	// Create gRPC server with injected dependencies and logging
	srv := server.NewForTest(dirs, st, kernel, logger)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(loggingInterceptor(logger)),
	)
	pb.RegisterBpfmanServer(grpcServer, srv)

	// Create Unix socket in temp directory
	// Use a unique name based on time and PID to avoid conflicts
	socketPath := fmt.Sprintf("/tmp/bpfman-ephemeral-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		st.Close()
		return nil, fmt.Errorf("listen on socket %s: %w", socketPath, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	e := &EphemeralClient{
		mgr:        mgr,
		grpcServer: grpcServer,
		listener:   listener,
		socketPath: socketPath,
		store:      st,
		cancel:     cancel,
		logger:     logger,
	}

	// Start server in background
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		if err := grpcServer.Serve(listener); err != nil {
			// Ignore error from GracefulStop
			select {
			case <-ctx.Done():
				return
			default:
				logger.Error("ephemeral server failed", "error", err)
			}
		}
	}()

	// Connect RemoteClient to the ephemeral server
	remote, err := NewRemote(socketPath, logger)
	if err != nil {
		cancel()
		grpcServer.GracefulStop()
		st.Close()
		os.Remove(socketPath)
		return nil, fmt.Errorf("connect to ephemeral server: %w", err)
	}

	e.remote = remote
	return e, nil
}

// Close shuts down the ephemeral server and releases all resources.
func (e *EphemeralClient) Close() error {
	e.cancel()
	if e.remote != nil {
		e.remote.Close()
	}
	e.grpcServer.GracefulStop()
	e.wg.Wait()
	if e.store != nil {
		e.store.Close()
	}
	if e.socketPath != "" {
		os.Remove(e.socketPath)
	}
	return nil
}

// Load loads a BPF program via the ephemeral gRPC server.
func (e *EphemeralClient) Load(ctx context.Context, spec managed.LoadSpec, opts manager.LoadOpts) (bpfman.ManagedProgram, error) {
	return e.remote.Load(ctx, spec, opts)
}

// Unload removes a BPF program via the ephemeral gRPC server.
func (e *EphemeralClient) Unload(ctx context.Context, kernelID uint32) error {
	return e.remote.Unload(ctx, kernelID)
}

// List returns all managed programs via the ephemeral gRPC server.
func (e *EphemeralClient) List(ctx context.Context) ([]manager.ManagedProgram, error) {
	return e.remote.List(ctx)
}

// Get retrieves a program by its kernel ID via the ephemeral gRPC server.
func (e *EphemeralClient) Get(ctx context.Context, kernelID uint32) (manager.ProgramInfo, error) {
	return e.remote.Get(ctx, kernelID)
}

// AttachTracepoint attaches a program to a tracepoint via the ephemeral gRPC server.
func (e *EphemeralClient) AttachTracepoint(ctx context.Context, programKernelID uint32, group, name, linkPinPath string) (managed.LinkSummary, error) {
	return e.remote.AttachTracepoint(ctx, programKernelID, group, name, linkPinPath)
}

// AttachXDP attaches an XDP program to a network interface via the ephemeral gRPC server.
func (e *EphemeralClient) AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname, linkPinPath string) (managed.LinkSummary, error) {
	return e.remote.AttachXDP(ctx, programKernelID, ifindex, ifname, linkPinPath)
}

// Detach removes a link via the ephemeral gRPC server.
func (e *EphemeralClient) Detach(ctx context.Context, kernelLinkID uint32) error {
	return e.remote.Detach(ctx, kernelLinkID)
}

// ListLinks returns all managed links via the ephemeral gRPC server.
func (e *EphemeralClient) ListLinks(ctx context.Context) ([]managed.LinkSummary, error) {
	return e.remote.ListLinks(ctx)
}

// ListLinksByProgram returns all links for a given program via the ephemeral gRPC server.
func (e *EphemeralClient) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	return e.remote.ListLinksByProgram(ctx, programKernelID)
}

// GetLink retrieves a link by kernel link ID via the ephemeral gRPC server.
func (e *EphemeralClient) GetLink(ctx context.Context, kernelLinkID uint32) (managed.LinkSummary, managed.LinkDetails, error) {
	return e.remote.GetLink(ctx, kernelLinkID)
}

// PlanGC creates a garbage collection plan via direct manager access.
// This bypasses gRPC as GC is a local-only operation.
func (e *EphemeralClient) PlanGC(ctx context.Context, cfg manager.GCConfig) (manager.GCPlan, error) {
	return e.mgr.PlanGC(ctx, cfg)
}

// ApplyGC executes a garbage collection plan via direct manager access.
// This bypasses gRPC as GC is a local-only operation.
func (e *EphemeralClient) ApplyGC(ctx context.Context, plan manager.GCPlan) (manager.GCResult, error) {
	return e.mgr.ApplyGC(ctx, plan)
}

// Reconcile cleans up orphaned store entries via direct manager access.
// This bypasses gRPC as reconciliation is a local-only operation.
func (e *EphemeralClient) Reconcile(ctx context.Context) error {
	return e.mgr.Reconcile(ctx)
}

// SetImagePuller configures the image puller for OCI operations.
func (e *EphemeralClient) SetImagePuller(p interpreter.ImagePuller) {
	e.puller = p
}

// PullImage pulls an OCI image and extracts the bytecode.
// Always executes locally, never forwarded to daemon.
func (e *EphemeralClient) PullImage(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error) {
	if e.puller == nil {
		return interpreter.PulledImage{}, fmt.Errorf("PullImage: %w (no image puller configured)", ErrNotSupported)
	}
	return e.puller.Pull(ctx, ref)
}

// LoadImage pulls an OCI image and loads the specified programs.
// Pull happens locally, load goes through the gRPC server.
func (e *EphemeralClient) LoadImage(ctx context.Context, ref interpreter.ImageRef, programs []managed.LoadSpec, opts LoadImageOpts) ([]bpfman.ManagedProgram, error) {
	// Step 1: Pull image locally
	pulled, err := e.PullImage(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("pull image: %w", err)
	}

	// Step 2: Load each program via gRPC
	results := make([]bpfman.ManagedProgram, 0, len(programs))
	for _, spec := range programs {
		// Override ObjectPath with pulled location
		spec.ObjectPath = pulled.ObjectPath
		spec.ImageSource = &managed.ImageSource{
			URL:        ref.URL,
			Digest:     pulled.Digest,
			PullPolicy: ref.PullPolicy,
		}

		loadOpts := manager.LoadOpts{
			UserMetadata: opts.UserMetadata,
		}

		loaded, err := e.remote.Load(ctx, spec, loadOpts)
		if err != nil {
			return results, fmt.Errorf("load program %s: %w", spec.ProgramName, err)
		}
		results = append(results, loaded)
	}

	return results, nil
}

// loggingInterceptor returns a gRPC unary interceptor that logs requests.
func loggingInterceptor(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		logger.Info("grpc request", "method", info.FullMethod)
		resp, err := handler(ctx, req)
		if err != nil {
			logger.Info("grpc response", "method", info.FullMethod, "error", err)
		}
		return resp, err
	}
}
