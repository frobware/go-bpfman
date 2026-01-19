// Package server implements the bpfman gRPC server.
package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/frobware/bpffs-csi-driver/bpfman/internal/bpf"
	pb "github.com/frobware/bpffs-csi-driver/bpfman/internal/gobpfman"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// DefaultSocketPath is the default Unix socket path for the gRPC server.
	DefaultSocketPath = "/run/bpfman-sock/bpfman.sock"
)

// programState tracks loaded programs with their metadata.
type programState struct {
	kernelID   uint32
	name       string
	progType   pb.BpfmanProgramType
	bytecode   *pb.BytecodeLocation
	metadata   map[string]string
	globalData map[string][]byte
	mapPinPath string
	links      []uint32 // link IDs for attachments
}

// Server implements the bpfman gRPC service.
type Server struct {
	pb.UnimplementedBpfmanServer

	mu       sync.RWMutex
	manager  *bpf.Manager
	programs map[uint32]*programState // keyed by kernel program ID
	links    map[uint32]uint32        // link ID -> program ID
	nextLink uint32
}

// New creates a new bpfman gRPC server.
func New() *Server {
	return &Server{
		manager:  bpf.NewManager(),
		programs: make(map[uint32]*programState),
		links:    make(map[uint32]uint32),
		nextLink: 1,
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
		// TODO: implement OCI image pulling
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

	// Convert proto program infos to library format
	programs := make([]bpf.ProgramLoadInfo, len(req.Info))
	for i, info := range req.Info {
		programs[i] = bpf.ProgramLoadInfo{
			Name:       info.Name,
			Type:       protoToBpfmanType(info.ProgramType),
			AttachFunc: getAttachFunc(info),
		}
	}

	// Load programs using our manager
	loadReq := &bpf.LoadRequest{
		ObjectPath: objectPath,
		Programs:   programs,
		Metadata:   req.Metadata,
		GlobalData: req.GlobalData,
		UUID:       uuid,
	}

	result, err := s.manager.Load(loadReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to load program: %v", err)
	}

	// Build response and store state
	resp := &pb.LoadResponse{
		Programs: make([]*pb.LoadResponseInfo, len(result.Programs)),
	}

	for i, prog := range result.Programs {
		// Store program state
		state := &programState{
			kernelID:   prog.KernelInfo.ID,
			name:       prog.Info.Name,
			progType:   req.Info[i].ProgramType,
			bytecode:   req.Bytecode,
			metadata:   req.Metadata,
			globalData: req.GlobalData,
			mapPinPath: prog.Info.MapPinPath,
			links:      []uint32{},
		}
		s.programs[prog.KernelInfo.ID] = state

		resp.Programs[i] = &pb.LoadResponseInfo{
			Info: &pb.ProgramInfo{
				Name:       prog.Info.Name,
				Bytecode:   req.Bytecode,
				Metadata:   req.Metadata,
				GlobalData: req.GlobalData,
				MapPinPath: prog.Info.MapPinPath,
			},
			KernelInfo: &pb.KernelProgramInfo{
				Id:            prog.KernelInfo.ID,
				Name:          prog.KernelInfo.Name,
				ProgramType:   prog.KernelInfo.ProgramType,
				GplCompatible: prog.KernelInfo.GplCompatible,
				Jited:         prog.KernelInfo.Jited,
				MapIds:        prog.KernelInfo.MapIDs,
			},
		}

		log.Printf("Loaded program %q (ID: %d) pinned at %s", prog.Info.Name, prog.KernelInfo.ID, prog.Info.MapPinPath)
	}

	return resp, nil
}

// getAttachFunc extracts the attach function name from LoadInfo.
func getAttachFunc(info *pb.LoadInfo) string {
	if info.Info == nil {
		return ""
	}
	if fentry := info.Info.GetFentryLoadInfo(); fentry != nil {
		return fentry.FnName
	}
	if fexit := info.Info.GetFexitLoadInfo(); fexit != nil {
		return fexit.FnName
	}
	return ""
}

// protoToBpfmanType converts proto program type to library type.
func protoToBpfmanType(pt pb.BpfmanProgramType) bpf.BpfmanProgramType {
	switch pt {
	case pb.BpfmanProgramType_XDP:
		return bpf.ProgramTypeXDP
	case pb.BpfmanProgramType_TC:
		return bpf.ProgramTypeTC
	case pb.BpfmanProgramType_TRACEPOINT:
		return bpf.ProgramTypeTracepoint
	case pb.BpfmanProgramType_KPROBE:
		return bpf.ProgramTypeKprobe
	case pb.BpfmanProgramType_UPROBE:
		return bpf.ProgramTypeUprobe
	case pb.BpfmanProgramType_FENTRY:
		return bpf.ProgramTypeFentry
	case pb.BpfmanProgramType_FEXIT:
		return bpf.ProgramTypeFexit
	case pb.BpfmanProgramType_TCX:
		return bpf.ProgramTypeTCX
	default:
		return bpf.ProgramTypeXDP
	}
}

// Unload implements the Unload RPC method.
func (s *Server) Unload(ctx context.Context, req *pb.UnloadRequest) (*pb.UnloadResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.programs[req.Id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}

	// Unload the program using the manager
	if err := s.manager.Unload(req.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unload program: %v", err)
	}

	// Clean up state
	for _, linkID := range state.links {
		delete(s.links, linkID)
	}
	delete(s.programs, req.Id)

	log.Printf("Unloaded program ID %d", req.Id)
	return &pb.UnloadResponse{}, nil
}

// Attach implements the Attach RPC method.
func (s *Server) Attach(ctx context.Context, req *pb.AttachRequest) (*pb.AttachResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.programs[req.Id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}

	// TODO: implement actual attachment based on AttachInfo type
	// For now, we just track the link
	linkID := s.nextLink
	s.nextLink++

	state.links = append(state.links, linkID)
	s.links[linkID] = req.Id

	log.Printf("Attached program ID %d, link ID %d", req.Id, linkID)
	return &pb.AttachResponse{LinkId: linkID}, nil
}

// Detach implements the Detach RPC method.
func (s *Server) Detach(ctx context.Context, req *pb.DetachRequest) (*pb.DetachResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	progID, ok := s.links[req.LinkId]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "link with ID %d not found", req.LinkId)
	}

	state, ok := s.programs[progID]
	if !ok {
		return nil, status.Errorf(codes.Internal, "program for link %d not found", req.LinkId)
	}

	// Remove link from program state
	for i, lid := range state.links {
		if lid == req.LinkId {
			state.links = append(state.links[:i], state.links[i+1:]...)
			break
		}
	}
	delete(s.links, req.LinkId)

	log.Printf("Detached link ID %d from program ID %d", req.LinkId, progID)
	return &pb.DetachResponse{}, nil
}

// List implements the List RPC method.
func (s *Server) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []*pb.ListResponse_ListResult

	for id, state := range s.programs {
		// Filter by program type if specified
		if req.ProgramType != nil {
			// Convert bpfman program type to kernel type for comparison
			// This is a simplification - real impl needs proper mapping
			if *req.ProgramType != uint32(state.progType) {
				continue
			}
		}

		// Filter by metadata if specified
		if len(req.MatchMetadata) > 0 {
			match := true
			for k, v := range req.MatchMetadata {
				if state.metadata[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		// Skip non-bpfman programs if requested
		if req.BpfmanProgramsOnly != nil && *req.BpfmanProgramsOnly {
			// All programs in our map are bpfman-managed
		}

		results = append(results, &pb.ListResponse_ListResult{
			Info: &pb.ProgramInfo{
				Name:       state.name,
				Bytecode:   state.bytecode,
				Metadata:   state.metadata,
				GlobalData: state.globalData,
				MapPinPath: state.mapPinPath,
				Links:      state.links,
			},
			KernelInfo: &pb.KernelProgramInfo{
				Id:          id,
				Name:        state.name,
				ProgramType: uint32(state.progType),
			},
		})
	}

	return &pb.ListResponse{Results: results}, nil
}

// Get implements the Get RPC method.
func (s *Server) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, ok := s.programs[req.Id]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}

	return &pb.GetResponse{
		Info: &pb.ProgramInfo{
			Name:       state.name,
			Bytecode:   state.bytecode,
			Metadata:   state.metadata,
			GlobalData: state.globalData,
			MapPinPath: state.mapPinPath,
			Links:      state.links,
		},
		KernelInfo: &pb.KernelProgramInfo{
			Id:          req.Id,
			Name:        state.name,
			ProgramType: uint32(state.progType),
		},
	}, nil
}

// PullBytecode implements the PullBytecode RPC method.
func (s *Server) PullBytecode(ctx context.Context, req *pb.PullBytecodeRequest) (*pb.PullBytecodeResponse, error) {
	// TODO: implement OCI image pulling
	return nil, status.Error(codes.Unimplemented, "PullBytecode not yet implemented")
}

// Serve starts the gRPC server on the given socket path.
func (s *Server) Serve(socketPath string) error {
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
