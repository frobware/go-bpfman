// Package server implements the bpfman gRPC server.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/config"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/ebpf"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	pb "github.com/frobware/go-bpfman/pkg/bpfman/server/pb"
	"github.com/frobware/go-bpfman/pkg/csi/driver"
)

const (
	// DefaultCSIDriverName is the default CSI driver name.
	DefaultCSIDriverName = "csi.go-bpfman.io"
	// DefaultCSIVersion is the default CSI driver version.
	DefaultCSIVersion = "0.1.0"
)

// RunConfig configures the server daemon.
type RunConfig struct {
	Dirs       config.RuntimeDirs
	TCPAddress string // Optional TCP address (e.g., ":50051") for remote access
	CSISupport bool
	Logger     *slog.Logger
	Config     config.Config
}

// Run starts the bpfman daemon with the given configuration.
// This is the main entry point for the serve command.
// The context is used for cancellation - when cancelled, the server shuts down gracefully.
func Run(ctx context.Context, cfg RunConfig) error {
	dirs := cfg.Dirs

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}

	// Ensure directories exist and bpffs is mounted
	if err := dirs.EnsureDirectories(); err != nil {
		return fmt.Errorf("runtime directory setup failed: %w", err)
	}

	// Open shared SQLite store
	dbPath := dirs.DBPath()
	st, err := sqlite.New(dbPath, logger)
	if err != nil {
		return fmt.Errorf("failed to open store at %s: %w", dbPath, err)
	}
	defer st.Close()

	// Create kernel adapter
	kernel := ebpf.New()

	// Track CSI driver for graceful shutdown
	var csiDriver *driver.Driver

	// Start CSI driver if enabled
	if cfg.CSISupport {
		nodeID, err := os.Hostname()
		if err != nil {
			return fmt.Errorf("failed to get hostname for node ID: %w", err)
		}

		csiSocketPath := dirs.CSISocketPath()
		csiDriver = driver.New(
			DefaultCSIDriverName,
			DefaultCSIVersion,
			nodeID,
			"unix://"+csiSocketPath,
			logger,
			driver.WithStore(st),
			driver.WithKernel(kernel),
		)

		go func() {
			logger.Info("starting CSI driver",
				"socket", csiSocketPath,
				"driver", DefaultCSIDriverName,
			)
			if err := csiDriver.Run(); err != nil {
				logger.Error("CSI driver failed", "error", err)
			}
		}()
	}

	// Handle context cancellation
	go func() {
		<-ctx.Done()
		logger.Info("context cancelled, shutting down")
		if csiDriver != nil {
			csiDriver.Stop()
		}
	}()

	// Start bpfman gRPC server
	srv := newWithStore(dirs, st, logger)
	return srv.serve(ctx, dirs.SocketPath(), cfg.TCPAddress)
}

// Server implements the bpfman gRPC service.
type Server struct {
	pb.UnimplementedBpfmanServer

	mu     sync.RWMutex
	dirs   config.RuntimeDirs
	kernel interpreter.KernelOperations
	store  interpreter.Store
	mgr    *manager.Manager
	logger *slog.Logger
}

// newWithStore creates a new bpfman gRPC server with a pre-configured store.
func newWithStore(dirs config.RuntimeDirs, store *sqlite.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		dirs:   dirs,
		kernel: ebpf.New(),
		store:  store,
		logger: logger.With("component", "server"),
	}
}

// NewForTest creates a server with injected dependencies for testing.
func NewForTest(dirs config.RuntimeDirs, store interpreter.Store, kernel interpreter.KernelOperations, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		dirs:   dirs,
		kernel: kernel,
		store:  store,
		logger: logger.With("component", "server"),
	}
	s.mgr = manager.New(dirs, store, kernel, logger)
	return s
}

// Load implements the Load RPC method.
func (s *Server) Load(ctx context.Context, req *pb.LoadRequest) (*pb.LoadResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.Bytecode == nil {
		return nil, status.Error(codes.InvalidArgument, "bytecode location is required")
	}

	// Get the bytecode path
	var objectPath string
	switch loc := req.Bytecode.Location.(type) {
	case *pb.BytecodeLocation_File:
		objectPath = loc.File
	case *pb.BytecodeLocation_Image:
		return nil, status.Error(codes.Unimplemented, "OCI image bytecode not yet supported")
	default:
		return nil, status.Error(codes.InvalidArgument, "invalid bytecode location")
	}

	if len(req.Info) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one program info is required")
	}

	// Determine pin directory using timestamp for uniqueness
	pinDir := filepath.Join(s.dirs.FS, fmt.Sprintf("%d", time.Now().UnixNano()))

	resp := &pb.LoadResponse{
		Programs: make([]*pb.LoadResponseInfo, 0, len(req.Info)),
	}

	// Load each requested program using the manager (transactional)
	for _, info := range req.Info {
		spec := managed.LoadSpec{
			ObjectPath:  objectPath,
			ProgramName: info.Name,
			ProgramType: protoToBpfmanType(info.ProgramType),
			PinPath:     pinDir,
			GlobalData:  req.GlobalData,
		}

		opts := manager.LoadOpts{
			UserMetadata: req.Metadata,
			Owner:        "bpfman",
		}

		loaded, err := s.mgr.Load(ctx, spec, opts)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to load program %s: %v", info.Name, err)
		}

		resp.Programs = append(resp.Programs, &pb.LoadResponseInfo{
			Info: &pb.ProgramInfo{
				Name:       info.Name,
				Bytecode:   req.Bytecode,
				Metadata:   req.Metadata,
				GlobalData: req.GlobalData,
				MapPinPath: pinDir,
			},
			KernelInfo: &pb.KernelProgramInfo{
				Id:            loaded.ID,
				Name:          loaded.Name,
				ProgramType:   uint32(loaded.ProgramType),
				GplCompatible: true,
				Jited:         true,
				MapIds:        loaded.MapIDs,
			},
		})
	}

	return resp, nil
}

// Unload implements the Unload RPC method.
func (s *Server) Unload(ctx context.Context, req *pb.UnloadRequest) (*pb.UnloadResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.mgr.Unload(ctx, req.Id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
		}
		return nil, status.Errorf(codes.Internal, "failed to unload program: %v", err)
	}

	return &pb.UnloadResponse{}, nil
}

// Attach implements the Attach RPC method.
func (s *Server) Attach(ctx context.Context, req *pb.AttachRequest) (*pb.AttachResponse, error) {
	// Attachment is not yet implemented in the new architecture
	return nil, status.Error(codes.Unimplemented, "Attach not yet implemented")
}

// Detach implements the Detach RPC method.
func (s *Server) Detach(ctx context.Context, req *pb.DetachRequest) (*pb.DetachResponse, error) {
	// Detachment is not yet implemented in the new architecture
	return nil, status.Error(codes.Unimplemented, "Detach not yet implemented")
}

// List implements the List RPC method.
func (s *Server) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	stored, err := s.store.List(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list programs: %v", err)
	}

	var results []*pb.ListResponse_ListResult

	for kernelID, metadata := range stored {
		// Filter by program type if specified
		if req.ProgramType != nil && *req.ProgramType != uint32(metadata.LoadSpec.ProgramType) {
			continue
		}

		// Filter by metadata if specified
		if len(req.MatchMetadata) > 0 {
			match := true
			for k, v := range req.MatchMetadata {
				if metadata.UserMetadata[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		results = append(results, &pb.ListResponse_ListResult{
			Info: &pb.ProgramInfo{
				Name:       metadata.LoadSpec.ProgramName,
				Bytecode:   &pb.BytecodeLocation{Location: &pb.BytecodeLocation_File{File: metadata.LoadSpec.ObjectPath}},
				Metadata:   metadata.UserMetadata,
				GlobalData: metadata.LoadSpec.GlobalData,
				MapPinPath: metadata.LoadSpec.PinPath,
			},
			KernelInfo: &pb.KernelProgramInfo{
				Id:          kernelID,
				Name:        metadata.LoadSpec.ProgramName,
				ProgramType: uint32(metadata.LoadSpec.ProgramType),
			},
		})
	}

	return &pb.ListResponse{Results: results}, nil
}

// Get implements the Get RPC method.
func (s *Server) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	metadata, err := s.store.Get(ctx, req.Id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get program: %v", err)
	}

	return &pb.GetResponse{
		Info: &pb.ProgramInfo{
			Name:       metadata.LoadSpec.ProgramName,
			Bytecode:   &pb.BytecodeLocation{Location: &pb.BytecodeLocation_File{File: metadata.LoadSpec.ObjectPath}},
			Metadata:   metadata.UserMetadata,
			GlobalData: metadata.LoadSpec.GlobalData,
			MapPinPath: metadata.LoadSpec.PinPath,
		},
		KernelInfo: &pb.KernelProgramInfo{
			Id:          req.Id,
			Name:        metadata.LoadSpec.ProgramName,
			ProgramType: uint32(metadata.LoadSpec.ProgramType),
		},
	}, nil
}

// PullBytecode implements the PullBytecode RPC method.
func (s *Server) PullBytecode(ctx context.Context, req *pb.PullBytecodeRequest) (*pb.PullBytecodeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "PullBytecode not yet implemented")
}

// serve starts the gRPC server on the given socket path and optionally on TCP.
func (s *Server) serve(ctx context.Context, socketPath, tcpAddr string) error {
	// Open SQLite store if not already set (e.g., when using newWithStore)
	closeStore := false
	if s.store == nil {
		st, err := sqlite.New(s.dirs.DBPath(), s.logger)
		if err != nil {
			return fmt.Errorf("failed to open store: %w", err)
		}
		s.store = st
		closeStore = true
	}
	if closeStore {
		if closer, ok := s.store.(interface{ Close() error }); ok {
			defer closer.Close()
		}
	}

	// Create manager for transactional load/unload operations
	s.mgr = manager.New(s.dirs, s.store, s.kernel, s.logger)

	// Ensure socket directory exists
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create socket directory: %w", err)
	}

	// Remove existing socket file
	if err := os.RemoveAll(socketPath); err != nil {
		return fmt.Errorf("failed to remove existing socket: %w", err)
	}

	// Create Unix socket listener
	unixListener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", socketPath, err)
	}
	defer unixListener.Close()

	// Set socket permissions
	if err := os.Chmod(socketPath, 0660); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	// Create gRPC server with logging interceptor
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(s.loggingInterceptor()),
	)
	pb.RegisterBpfmanServer(grpcServer, s)

	// Track errors from serving goroutines
	errChan := make(chan error, 2)

	// Start Unix socket server
	go func() {
		s.logger.Info("bpfman gRPC server listening", "socket", socketPath)
		if err := grpcServer.Serve(unixListener); err != nil {
			errChan <- fmt.Errorf("unix socket server: %w", err)
		}
	}()

	// Optionally start TCP listener for remote access
	if tcpAddr != "" {
		tcpListener, err := net.Listen("tcp", tcpAddr)
		if err != nil {
			grpcServer.GracefulStop()
			return fmt.Errorf("failed to listen on TCP %s: %w", tcpAddr, err)
		}

		go func() {
			s.logger.Info("bpfman gRPC server listening", "tcp", tcpAddr)
			if err := grpcServer.Serve(tcpListener); err != nil {
				errChan <- fmt.Errorf("tcp server: %w", err)
			}
		}()
	}

	// Handle context cancellation for graceful shutdown
	go func() {
		<-ctx.Done()
		s.logger.Info("shutting down gRPC server")
		grpcServer.GracefulStop()
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return nil
	case err := <-errChan:
		return err
	}
}

// loggingInterceptor returns a gRPC unary interceptor that logs incoming requests.
func (s *Server) loggingInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		s.logger.Info("grpc request", "method", info.FullMethod)
		resp, err := handler(ctx, req)
		if err != nil {
			s.logger.Info("grpc response", "method", info.FullMethod, "error", err)
		}
		return resp, err
	}
}

// protoToBpfmanType converts proto program type to bpfman type.
func protoToBpfmanType(pt pb.BpfmanProgramType) bpfman.ProgramType {
	switch pt {
	case pb.BpfmanProgramType_XDP:
		return bpfman.ProgramTypeXDP
	case pb.BpfmanProgramType_TC:
		return bpfman.ProgramTypeTC
	case pb.BpfmanProgramType_TRACEPOINT:
		return bpfman.ProgramTypeTracepoint
	case pb.BpfmanProgramType_KPROBE:
		return bpfman.ProgramTypeKprobe
	case pb.BpfmanProgramType_UPROBE:
		return bpfman.ProgramTypeUprobe
	case pb.BpfmanProgramType_FENTRY:
		return bpfman.ProgramTypeFentry
	case pb.BpfmanProgramType_FEXIT:
		return bpfman.ProgramTypeFexit
	case pb.BpfmanProgramType_TCX:
		return bpfman.ProgramTypeTCX
	default:
		return bpfman.ProgramTypeUnspecified
	}
}
