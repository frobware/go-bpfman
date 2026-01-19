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
	"time"

	"github.com/frobware/bpffs-csi-driver/bpfman/internal/bpf"
	pb "github.com/frobware/bpffs-csi-driver/bpfman/internal/gobpfman"
	"github.com/frobware/bpffs-csi-driver/bpfman/internal/store"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	// DefaultSocketPath is the default Unix socket path for the gRPC server.
	DefaultSocketPath = "/run/bpfman-sock/bpfman.sock"
	// DefaultDBPath is the default path for the SQLite database.
	DefaultDBPath = "/run/bpfman/state.db"
)

// Server implements the bpfman gRPC service.
type Server struct {
	pb.UnimplementedBpfmanServer

	mu      sync.RWMutex
	manager *bpf.Manager
	store   *store.Store
}

// New creates a new bpfman gRPC server.
func New() *Server {
	return &Server{
		manager: bpf.NewManager(),
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

	// Build response and persist to SQLite
	resp := &pb.LoadResponse{
		Programs: make([]*pb.LoadResponseInfo, len(result.Programs)),
	}

	for i, prog := range result.Programs {
		now := time.Now()

		// Persist to SQLite
		record := &store.ProgramRecord{
			ID:           prog.KernelInfo.ID,
			UUID:         uuid,
			Name:         prog.Info.Name,
			FuncName:     req.Info[i].Name,
			ProgramType:  prog.KernelInfo.ProgramType,
			BytecodePath: objectPath,
			PinPath:      filepath.Join(prog.Info.MapPinPath, prog.Info.Name),
			MapPinPath:   prog.Info.MapPinPath,
			Metadata:     req.Metadata,
			GlobalData:   req.GlobalData,
			LoadedAt:     now,
			MapIDs:       prog.KernelInfo.MapIDs,
		}
		if err := s.store.SaveProgram(record); err != nil {
			log.Printf("Warning: failed to persist program %d: %v", prog.KernelInfo.ID, err)
		}

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

	// Check program exists in store
	prog, err := s.store.GetProgram(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get program: %v", err)
	}
	if prog == nil {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}

	// Unload by path (works even after restart when manager has no in-memory state)
	if err := s.manager.UnloadByPath(prog.MapPinPath); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unload program: %v", err)
	}

	// Delete links for this program
	links, _ := s.store.ListLinksByProgram(req.Id)
	for _, l := range links {
		s.store.DeleteLink(l.ID)
	}

	// Delete from store
	if err := s.store.DeleteProgram(req.Id); err != nil {
		log.Printf("Warning: failed to delete program %d from store: %v", req.Id, err)
	}

	log.Printf("Unloaded program ID %d", req.Id)
	return &pb.UnloadResponse{}, nil
}

// Attach implements the Attach RPC method.
func (s *Server) Attach(ctx context.Context, req *pb.AttachRequest) (*pb.AttachResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check program exists
	prog, err := s.store.GetProgram(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get program: %v", err)
	}
	if prog == nil {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}

	// TODO: implement actual attachment based on AttachInfo type
	// For now, generate a link ID and store it
	linkID := uint32(time.Now().UnixNano() & 0xFFFFFFFF)

	linkRecord := &store.LinkRecord{
		ID:         linkID,
		ProgramID:  req.Id,
		AttachType: 0, // TODO: extract from req.Info
		AttachInfo: "", // TODO: serialize req.Info
	}
	if err := s.store.SaveLink(linkRecord); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to save link: %v", err)
	}

	log.Printf("Attached program ID %d, link ID %d", req.Id, linkID)
	return &pb.AttachResponse{LinkId: linkID}, nil
}

// Detach implements the Detach RPC method.
func (s *Server) Detach(ctx context.Context, req *pb.DetachRequest) (*pb.DetachResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	link, err := s.store.GetLink(req.LinkId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get link: %v", err)
	}
	if link == nil {
		return nil, status.Errorf(codes.NotFound, "link with ID %d not found", req.LinkId)
	}

	// Delete link from store
	if err := s.store.DeleteLink(req.LinkId); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete link: %v", err)
	}

	log.Printf("Detached link ID %d from program ID %d", req.LinkId, link.ProgramID)
	return &pb.DetachResponse{}, nil
}

// List implements the List RPC method.
func (s *Server) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	programs, err := s.store.ListPrograms()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list programs: %v", err)
	}

	var results []*pb.ListResponse_ListResult

	for _, p := range programs {
		// Filter by program type if specified
		if req.ProgramType != nil && *req.ProgramType != p.ProgramType {
			continue
		}

		// Filter by metadata if specified
		if len(req.MatchMetadata) > 0 {
			match := true
			for k, v := range req.MatchMetadata {
				if p.Metadata[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		// Get links for this program
		links, _ := s.store.ListLinksByProgram(p.ID)
		linkIDs := make([]uint32, len(links))
		for i, l := range links {
			linkIDs[i] = l.ID
		}

		results = append(results, &pb.ListResponse_ListResult{
			Info: &pb.ProgramInfo{
				Name:       p.Name,
				Bytecode:   &pb.BytecodeLocation{Location: &pb.BytecodeLocation_File{File: p.BytecodePath}},
				Metadata:   p.Metadata,
				GlobalData: p.GlobalData,
				MapPinPath: p.MapPinPath,
				Links:      linkIDs,
			},
			KernelInfo: &pb.KernelProgramInfo{
				Id:          p.ID,
				Name:        p.Name,
				ProgramType: p.ProgramType,
				MapIds:      p.MapIDs,
			},
		})
	}

	return &pb.ListResponse{Results: results}, nil
}

// Get implements the Get RPC method.
func (s *Server) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, err := s.store.GetProgram(req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get program: %v", err)
	}
	if p == nil {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}

	// Get links for this program
	links, _ := s.store.ListLinksByProgram(p.ID)
	linkIDs := make([]uint32, len(links))
	for i, l := range links {
		linkIDs[i] = l.ID
	}

	return &pb.GetResponse{
		Info: &pb.ProgramInfo{
			Name:       p.Name,
			Bytecode:   &pb.BytecodeLocation{Location: &pb.BytecodeLocation_File{File: p.BytecodePath}},
			Metadata:   p.Metadata,
			GlobalData: p.GlobalData,
			MapPinPath: p.MapPinPath,
			Links:      linkIDs,
		},
		KernelInfo: &pb.KernelProgramInfo{
			Id:          p.ID,
			Name:        p.Name,
			ProgramType: p.ProgramType,
			MapIds:      p.MapIDs,
		},
	}, nil
}

// PullBytecode implements the PullBytecode RPC method.
func (s *Server) PullBytecode(ctx context.Context, req *pb.PullBytecodeRequest) (*pb.PullBytecodeResponse, error) {
	return nil, status.Error(codes.Unimplemented, "PullBytecode not yet implemented")
}

// Serve starts the gRPC server on the given socket path.
func (s *Server) Serve(socketPath string) error {
	// Open SQLite store
	st, err := store.Open(DefaultDBPath)
	if err != nil {
		return fmt.Errorf("failed to open store: %w", err)
	}
	s.store = st
	defer s.store.Close()

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
