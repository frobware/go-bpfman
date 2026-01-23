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

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/config"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/interpreter/image/oci"
	"github.com/frobware/go-bpfman/interpreter/image/verify"
	"github.com/frobware/go-bpfman/manager"
	"github.com/frobware/go-bpfman/server"
	pb "github.com/frobware/go-bpfman/server/pb"
)

// ephemeralClient spawns an in-process gRPC server and connects to it.
// This ensures CLI commands use the same code path as remote clients,
// making gRPC handlers the canonical implementation.
//
// Operations are routed as follows:
//   - Daemon ops (load, attach, etc.): via ephemeral gRPC server
//   - Host ops (GC, reconcile): direct to manager
//   - Image ops: pull locally, load via gRPC
type ephemeralClient struct {
	remote     Client
	env        *manager.RuntimeEnv
	puller     interpreter.ImagePuller
	grpcServer *grpc.Server
	listener   net.Listener
	socketPath string // Cleaned up on Close
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	logger     *slog.Logger
}

// newEphemeral creates a Client that spawns an in-process gRPC
// server using a temporary Unix socket.
func newEphemeral(dirs config.RuntimeDirs, cfg config.Config, logger *slog.Logger) (Client, error) {
	// Set up runtime environment (ensures directories, opens store, creates manager)
	env, err := manager.SetupRuntimeEnv(dirs, logger)
	if err != nil {
		return nil, fmt.Errorf("setup runtime: %w", err)
	}

	// Build signature verifier based on config
	var verifier interpreter.SignatureVerifier
	if cfg.Signing.ShouldVerify() {
		logger.Info("signature verification enabled")
		verifier = verify.Cosign(
			verify.WithLogger(logger),
			verify.WithAllowUnsigned(cfg.Signing.AllowUnsigned),
		)
	} else {
		logger.Info("signature verification disabled")
		verifier = verify.NoSign()
	}

	// Create image puller for OCI images
	puller, err := oci.NewPuller(
		oci.WithLogger(logger),
		oci.WithVerifier(verifier),
	)
	if err != nil {
		env.Close()
		return nil, fmt.Errorf("create image puller: %w", err)
	}

	// Create gRPC server with injected dependencies
	srv := server.New(dirs, env.Store, env.Kernel, puller, logger)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(loggingInterceptor(logger)),
	)
	pb.RegisterBpfmanServer(grpcServer, srv)

	// Create Unix socket in temp directory
	// Use a unique name based on time and PID to avoid conflicts
	socketPath := fmt.Sprintf("/tmp/bpfman-ephemeral-%d-%d.sock", os.Getpid(), time.Now().UnixNano())
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		env.Close()
		return nil, fmt.Errorf("listen on socket %s: %w", socketPath, err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	e := &ephemeralClient{
		env:        env,
		grpcServer: grpcServer,
		listener:   listener,
		socketPath: socketPath,
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

	// Connect remoteClient to the ephemeral server
	remote, err := newRemote(socketPath, logger)
	if err != nil {
		cancel()
		grpcServer.GracefulStop()
		env.Close()
		if rmErr := os.Remove(socketPath); rmErr != nil && !os.IsNotExist(rmErr) {
			logger.Warn("failed to remove socket during cleanup", "path", socketPath, "error", rmErr)
		}
		return nil, fmt.Errorf("connect to ephemeral server: %w", err)
	}

	e.remote = remote
	return e, nil
}

// Close shuts down the ephemeral server and releases all resources.
func (e *ephemeralClient) Close() error {
	e.cancel()
	if e.remote != nil {
		e.remote.Close()
	}
	e.grpcServer.GracefulStop()
	e.wg.Wait()
	if e.env != nil {
		e.env.Close()
	}
	if e.socketPath != "" {
		if err := os.Remove(e.socketPath); err != nil && !os.IsNotExist(err) {
			e.logger.Warn("failed to remove socket during close", "path", e.socketPath, "error", err)
		}
	}
	return nil
}

// Load loads a BPF program via the ephemeral gRPC server.
func (e *ephemeralClient) Load(ctx context.Context, spec bpfman.LoadSpec, opts manager.LoadOpts) (bpfman.ManagedProgram, error) {
	return e.remote.Load(ctx, spec, opts)
}

// Unload removes a BPF program via the ephemeral gRPC server.
func (e *ephemeralClient) Unload(ctx context.Context, kernelID uint32) error {
	return e.remote.Unload(ctx, kernelID)
}

// List returns all managed programs via the ephemeral gRPC server.
func (e *ephemeralClient) List(ctx context.Context) ([]manager.ManagedProgram, error) {
	return e.remote.List(ctx)
}

// Get retrieves a program by its kernel ID via the ephemeral gRPC server.
func (e *ephemeralClient) Get(ctx context.Context, kernelID uint32) (manager.ProgramInfo, error) {
	return e.remote.Get(ctx, kernelID)
}

// AttachTracepoint attaches a program to a tracepoint via the ephemeral gRPC server.
func (e *ephemeralClient) AttachTracepoint(ctx context.Context, programKernelID uint32, group, name, linkPinPath string) (bpfman.LinkSummary, error) {
	return e.remote.AttachTracepoint(ctx, programKernelID, group, name, linkPinPath)
}

// AttachXDP attaches an XDP program to a network interface via the ephemeral gRPC server.
func (e *ephemeralClient) AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname, linkPinPath string) (bpfman.LinkSummary, error) {
	return e.remote.AttachXDP(ctx, programKernelID, ifindex, ifname, linkPinPath)
}

// Detach removes a link via the ephemeral gRPC server.
func (e *ephemeralClient) Detach(ctx context.Context, kernelLinkID uint32) error {
	return e.remote.Detach(ctx, kernelLinkID)
}

// ListLinks returns all managed links via the ephemeral gRPC server.
func (e *ephemeralClient) ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error) {
	return e.remote.ListLinks(ctx)
}

// ListLinksByProgram returns all links for a given program via the ephemeral gRPC server.
func (e *ephemeralClient) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkSummary, error) {
	return e.remote.ListLinksByProgram(ctx, programKernelID)
}

// GetLink retrieves a link by kernel link ID via the ephemeral gRPC server.
func (e *ephemeralClient) GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error) {
	return e.remote.GetLink(ctx, kernelLinkID)
}

// PlanGC creates a garbage collection plan via direct manager access.
// This bypasses gRPC as GC is a local-only operation.
func (e *ephemeralClient) PlanGC(ctx context.Context, cfg manager.GCConfig) (manager.GCPlan, error) {
	return e.env.Manager.PlanGC(ctx, cfg)
}

// ApplyGC executes a garbage collection plan via direct manager access.
// This bypasses gRPC as GC is a local-only operation.
func (e *ephemeralClient) ApplyGC(ctx context.Context, plan manager.GCPlan) (manager.GCResult, error) {
	return e.env.Manager.ApplyGC(ctx, plan)
}

// Reconcile cleans up orphaned store entries via direct manager access.
// This bypasses gRPC as reconciliation is a local-only operation.
func (e *ephemeralClient) Reconcile(ctx context.Context) error {
	return e.env.Manager.Reconcile(ctx)
}

// SetImagePuller configures the image puller for OCI operations.
func (e *ephemeralClient) SetImagePuller(p interpreter.ImagePuller) {
	e.puller = p
}

// PullImage pulls an OCI image and extracts the bytecode.
// Always executes locally, never forwarded to daemon.
func (e *ephemeralClient) PullImage(ctx context.Context, ref interpreter.ImageRef) (interpreter.PulledImage, error) {
	if e.puller == nil {
		return interpreter.PulledImage{}, fmt.Errorf("PullImage: %w (no image puller configured)", ErrNotSupported)
	}
	return e.puller.Pull(ctx, ref)
}

// LoadImage loads programs from an OCI image via the ephemeral gRPC server.
// The server handles pulling and caching the image.
func (e *ephemeralClient) LoadImage(ctx context.Context, ref interpreter.ImageRef, programs []bpfman.LoadSpec, opts LoadImageOpts) ([]bpfman.ManagedProgram, error) {
	return e.remote.LoadImage(ctx, ref, programs, opts)
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
