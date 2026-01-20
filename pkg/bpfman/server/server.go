// Package server implements the bpfman gRPC server.
package server

import (
	"context"
	"errors"
	"fmt"
	"log"
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
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/ebpf"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	pb "github.com/frobware/go-bpfman/pkg/bpfman/server/pb"
	"github.com/frobware/go-bpfman/pkg/csi/driver"
)

const (
	// DefaultSocketPath is the default Unix socket path for the gRPC server.
	DefaultSocketPath = "/run/bpfman-sock/bpfman.sock"
	// DefaultDBPath is the default path for the SQLite database.
	DefaultDBPath = "/run/bpfman/state.db"
	// DefaultBpfmanRoot is the default root directory for bpfman pins.
	DefaultBpfmanRoot = "/sys/fs/bpf/bpfman"
	// DefaultCSISocketPath is the default Unix socket path for the CSI driver.
	DefaultCSISocketPath = "/run/bpfman/csi/csi.sock"
	// DefaultCSIDriverName is the default CSI driver name.
	DefaultCSIDriverName = "csi.go-bpfman.io"
	// DefaultCSIVersion is the default CSI driver version.
	DefaultCSIVersion = "0.1.0"
)

// RunConfig configures the server daemon.
type RunConfig struct {
	SocketPath    string
	DBPath        string
	CSISupport    bool
	CSISocketPath string
}

// Run starts the bpfman daemon with the given configuration.
// This is the main entry point for the serve command.
// The context is used for cancellation - when cancelled, the server shuts down gracefully.
func Run(ctx context.Context, cfg RunConfig) error {
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocketPath
	}
	if cfg.DBPath == "" {
		cfg.DBPath = DefaultDBPath
	}
	if cfg.CSISocketPath == "" {
		cfg.CSISocketPath = DefaultCSISocketPath
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Open shared SQLite store
	st, err := sqlite.New(cfg.DBPath, logger)
	if err != nil {
		return fmt.Errorf("failed to open store at %s: %w", cfg.DBPath, err)
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

		csiDriver = driver.New(
			DefaultCSIDriverName,
			DefaultCSIVersion,
			nodeID,
			"unix://"+cfg.CSISocketPath,
			logger,
			driver.WithStore(st),
			driver.WithKernel(kernel),
		)

		go func() {
			logger.Info("starting CSI driver",
				"socket", cfg.CSISocketPath,
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
	srv := newWithStore(st, logger)
	return srv.serve(ctx, cfg.SocketPath)
}

// Server implements the bpfman gRPC service.
type Server struct {
	pb.UnimplementedBpfmanServer

	mu     sync.RWMutex
	kernel *ebpf.Kernel
	store  *sqlite.Store
	mgr    *manager.Manager
	root   string
	logger *slog.Logger
}

// newWithStore creates a new bpfman gRPC server with a pre-configured store.
func newWithStore(store *sqlite.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		kernel: ebpf.New(),
		store:  store,
		root:   DefaultBpfmanRoot,
		logger: logger.With("component", "server"),
	}
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

	// Determine UUID from request or metadata
	uuid := ""
	if req.Uuid != nil && *req.Uuid != "" {
		uuid = *req.Uuid
	} else if u, ok := req.Metadata["bpfman.io/uuid"]; ok {
		uuid = u
	}

	// Determine pin directory
	var pinDir string
	if uuid != "" {
		pinDir = filepath.Join(s.root, uuid)
	} else {
		pinDir = filepath.Join(s.root, fmt.Sprintf("%d", time.Now().UnixNano()))
	}

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
			UUID:         uuid,
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

		log.Printf("Loaded program %q (ID: %d) pinned at %s", info.Name, loaded.ID, pinDir)
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

	log.Printf("Unloaded program ID %d", req.Id)
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

// serve starts the gRPC server on the given socket path.
func (s *Server) serve(ctx context.Context, socketPath string) error {
	// Open SQLite store if not already set (e.g., when using newWithStore)
	closeStore := false
	if s.store == nil {
		st, err := sqlite.New(DefaultDBPath, s.logger)
		if err != nil {
			return fmt.Errorf("failed to open store: %w", err)
		}
		s.store = st
		closeStore = true
	}
	if closeStore {
		defer s.store.Close()
	}

	// Create manager for transactional load/unload operations
	s.mgr = manager.New(s.store, s.kernel, s.logger)

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
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", socketPath, err)
	}
	defer listener.Close()

	// Set socket permissions
	if err := os.Chmod(socketPath, 0660); err != nil {
		return fmt.Errorf("failed to set socket permissions: %w", err)
	}

	// Create gRPC server
	grpcServer := grpc.NewServer()
	pb.RegisterBpfmanServer(grpcServer, s)

	// Handle context cancellation for graceful shutdown
	go func() {
		<-ctx.Done()
		log.Printf("shutting down gRPC server")
		grpcServer.GracefulStop()
	}()

	log.Printf("bpfman gRPC server listening on %s", socketPath)
	return grpcServer.Serve(listener)
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
