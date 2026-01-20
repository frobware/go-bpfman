// Package server implements the bpfman gRPC server.
package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frobware/go-bpfman/pkg/bpfman/domain"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/kernel/ebpf"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	pb "github.com/frobware/go-bpfman/pkg/bpfman/server/pb"
)

const (
	// DefaultSocketPath is the default Unix socket path for the gRPC server.
	DefaultSocketPath = "/run/bpfman-sock/bpfman.sock"
	// DefaultDBPath is the default path for the SQLite database.
	DefaultDBPath = "/run/bpfman/state.db"
	// DefaultBpfmanRoot is the default root directory for bpfman pins.
	DefaultBpfmanRoot = "/sys/fs/bpf/bpfman"
)

// Server implements the bpfman gRPC service.
type Server struct {
	pb.UnimplementedBpfmanServer

	mu     sync.RWMutex
	kernel *ebpf.Kernel
	store  *sqlite.Store
	mgr    *manager.Manager
	root   string
}

// New creates a new bpfman gRPC server.
func New() *Server {
	return &Server{
		kernel: ebpf.New(),
		root:   DefaultBpfmanRoot,
	}
}

// NewWithStore creates a new bpfman gRPC server with a pre-configured store.
// This is used when running with --csi-support to share the store between
// bpfman and the CSI driver.
func NewWithStore(store *sqlite.Store) *Server {
	return &Server{
		kernel: ebpf.New(),
		store:  store,
		root:   DefaultBpfmanRoot,
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
		spec := domain.LoadSpec{
			ObjectPath:  objectPath,
			ProgramName: info.Name,
			ProgramType: protoToDomainType(info.ProgramType),
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

// Serve starts the gRPC server on the given socket path.
func (s *Server) Serve(socketPath string) error {
	// Open SQLite store if not already set (e.g., when using NewWithStore)
	closeStore := false
	if s.store == nil {
		st, err := sqlite.New(DefaultDBPath)
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
	s.mgr = manager.New(s.store, s.kernel)

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

	// Create and start gRPC server
	grpcServer := grpc.NewServer()
	pb.RegisterBpfmanServer(grpcServer, s)

	log.Printf("bpfman gRPC server listening on %s", socketPath)
	return grpcServer.Serve(listener)
}

// protoToDomainType converts proto program type to domain type.
func protoToDomainType(pt pb.BpfmanProgramType) domain.ProgramType {
	switch pt {
	case pb.BpfmanProgramType_XDP:
		return domain.ProgramTypeXDP
	case pb.BpfmanProgramType_TC:
		return domain.ProgramTypeTC
	case pb.BpfmanProgramType_TRACEPOINT:
		return domain.ProgramTypeTracepoint
	case pb.BpfmanProgramType_KPROBE:
		return domain.ProgramTypeKprobe
	case pb.BpfmanProgramType_UPROBE:
		return domain.ProgramTypeUprobe
	case pb.BpfmanProgramType_FENTRY:
		return domain.ProgramTypeFentry
	case pb.BpfmanProgramType_FEXIT:
		return domain.ProgramTypeFexit
	case pb.BpfmanProgramType_TCX:
		return domain.ProgramTypeTCX
	default:
		return domain.ProgramTypeUnspecified
	}
}
