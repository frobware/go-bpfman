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
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/config"
	"github.com/frobware/go-bpfman/csi"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/interpreter/ebpf"
	"github.com/frobware/go-bpfman/interpreter/image/oci"
	"github.com/frobware/go-bpfman/interpreter/image/verify"
	"github.com/frobware/go-bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/interpreter/store/sqlite"
	"github.com/frobware/go-bpfman/manager"
	pb "github.com/frobware/go-bpfman/server/pb"
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
	kernel := ebpf.New(ebpf.WithLogger(logger))

	// Build signature verifier based on config
	var verifier interpreter.SignatureVerifier
	if cfg.Config.Signing.ShouldVerify() {
		logger.Info("signature verification enabled")
		verifier = verify.Cosign(
			verify.WithLogger(logger),
			verify.WithAllowUnsigned(cfg.Config.Signing.AllowUnsigned),
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
		return fmt.Errorf("failed to create image puller: %w", err)
	}

	// Track CSI driver for graceful shutdown
	var csiDriver *driver.Driver

	// Start CSI driver if enabled
	if cfg.CSISupport {
		if err := dirs.EnsureCSIDirectories(); err != nil {
			return fmt.Errorf("CSI directory setup failed: %w", err)
		}

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
	srv := newWithStore(dirs, st, puller, logger)
	return srv.serve(ctx, dirs.SocketPath(), cfg.TCPAddress)
}

// Server implements the bpfman gRPC service.
type Server struct {
	pb.UnimplementedBpfmanServer

	mu     sync.RWMutex
	dirs   config.RuntimeDirs
	kernel interpreter.KernelOperations
	store  interpreter.Store
	puller interpreter.ImagePuller
	mgr    *manager.Manager
	logger *slog.Logger
}

// newWithStore creates a new bpfman gRPC server with a pre-configured store.
func newWithStore(dirs config.RuntimeDirs, store interpreter.Store, puller interpreter.ImagePuller, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		dirs:   dirs,
		kernel: ebpf.New(ebpf.WithLogger(logger)),
		store:  store,
		puller: puller,
		logger: logger.With("component", "server"),
	}
}

// New creates a server with the provided dependencies.
func New(dirs config.RuntimeDirs, store interpreter.Store, kernel interpreter.KernelOperations, puller interpreter.ImagePuller, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{
		dirs:   dirs,
		kernel: kernel,
		store:  store,
		puller: puller,
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

	// Get the bytecode path and optional image source
	var objectPath string
	var imageSource *bpfman.ImageSource
	switch loc := req.Bytecode.Location.(type) {
	case *pb.BytecodeLocation_File:
		objectPath = loc.File
	case *pb.BytecodeLocation_Image:
		if s.puller == nil {
			return nil, status.Error(codes.Unimplemented, "OCI image loading not configured on this server")
		}

		// Convert proto to interpreter types
		pullPolicy := protoToPullPolicy(loc.Image.ImagePullPolicy)
		ref := interpreter.ImageRef{
			URL:        loc.Image.Url,
			PullPolicy: pullPolicy,
		}
		if loc.Image.Username != nil && *loc.Image.Username != "" {
			ref.Auth = &interpreter.ImageAuth{
				Username: *loc.Image.Username,
			}
			if loc.Image.Password != nil {
				ref.Auth.Password = *loc.Image.Password
			}
		}

		// Pull the image
		pulled, err := s.puller.Pull(ctx, ref)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to pull image %s: %v", loc.Image.Url, err)
		}
		objectPath = pulled.ObjectPath
		imageSource = &bpfman.ImageSource{
			URL:        loc.Image.Url,
			Digest:     pulled.Digest,
			PullPolicy: pullPolicy,
		}
	default:
		return nil, status.Error(codes.InvalidArgument, "invalid bytecode location")
	}

	if len(req.Info) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one program info is required")
	}

	resp := &pb.LoadResponse{
		Programs: make([]*pb.LoadResponseInfo, 0, len(req.Info)),
	}

	// Load each requested program using the manager (transactional)
	// Pin paths are computed from kernel ID, following upstream convention
	for _, info := range req.Info {
		progType, err := protoToBpfmanType(info.ProgramType)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid program type for %s: %v", info.Name, err)
		}

		spec := bpfman.LoadSpec{
			ObjectPath:  objectPath,
			ProgramName: info.Name,
			ProgramType: progType,
			PinPath:     s.dirs.FS, // bpffs root - actual paths computed from kernel ID
			GlobalData:  req.GlobalData,
			ImageSource: imageSource,
		}

		opts := manager.LoadOpts{
			UserMetadata: req.Metadata,
			Owner:        "bpfman",
		}

		loaded, err := s.mgr.Load(ctx, spec, opts)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "failed to load program %s: %v", info.Name, err)
		}

		// Format LoadedAt as RFC3339 if available
		var loadedAt string
		if !loaded.Kernel.LoadedAt().IsZero() {
			loadedAt = loaded.Kernel.LoadedAt().Format(time.RFC3339)
		}

		resp.Programs = append(resp.Programs, &pb.LoadResponseInfo{
			Info: &pb.ProgramInfo{
				Name:       info.Name,
				Bytecode:   req.Bytecode,
				Metadata:   req.Metadata,
				GlobalData: req.GlobalData,
				MapPinPath: loaded.Managed.PinDir, // maps directory computed from kernel ID
			},
			KernelInfo: &pb.KernelProgramInfo{
				Id:            loaded.Kernel.ID(),
				Name:          loaded.Kernel.Name(),
				ProgramType:   uint32(loaded.Kernel.Type()),
				LoadedAt:      loadedAt,
				GplCompatible: loaded.Kernel.GPLCompatible(),
				Jited:         loaded.Kernel.BytesJited() > 0,
				MapIds:        loaded.Kernel.MapIDs(),
				BtfId:         loaded.Kernel.BTFId(),
				BytesXlated:   loaded.Kernel.BytesXlated(),
				BytesJited:    loaded.Kernel.BytesJited(),
				BytesMemlock:  uint32(loaded.Kernel.MemoryLocked()),
				VerifiedInsns: loaded.Kernel.VerifiedInstructions(),
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
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.Attach == nil {
		return nil, status.Error(codes.InvalidArgument, "attach info is required")
	}

	switch info := req.Attach.Info.(type) {
	case *pb.AttachInfo_TracepointAttachInfo:
		return s.attachTracepoint(ctx, req.Id, info.TracepointAttachInfo)
	case *pb.AttachInfo_XdpAttachInfo:
		return s.attachXDP(ctx, req.Id, info.XdpAttachInfo)
	case *pb.AttachInfo_TcAttachInfo:
		return s.attachTC(ctx, req.Id, info.TcAttachInfo)
	default:
		return nil, status.Errorf(codes.Unimplemented, "attach type %T not yet implemented", req.Attach.Info)
	}
}

// attachTracepoint handles tracepoint attachment via the manager.
func (s *Server) attachTracepoint(ctx context.Context, programID uint32, info *pb.TracepointAttachInfo) (*pb.AttachResponse, error) {
	// Parse "group/name" format from tracepoint field
	parts := strings.SplitN(info.Tracepoint, "/", 2)
	if len(parts) != 2 {
		return nil, status.Errorf(codes.InvalidArgument, "tracepoint must be in 'group/name' format, got %q", info.Tracepoint)
	}
	group, name := parts[0], parts[1]

	// Call manager with empty linkPinPath to auto-generate
	summary, err := s.mgr.AttachTracepoint(ctx, programID, group, name, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "attach tracepoint: %v", err)
	}

	return &pb.AttachResponse{
		LinkId: summary.KernelLinkID,
	}, nil
}

// attachXDP handles XDP attachment via the manager.
func (s *Server) attachXDP(ctx context.Context, programID uint32, info *pb.XDPAttachInfo) (*pb.AttachResponse, error) {
	// Get interface index from name
	iface, err := net.InterfaceByName(info.Iface)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "interface %q: %v", info.Iface, err)
	}

	// Call manager with empty linkPinPath to auto-generate
	summary, err := s.mgr.AttachXDP(ctx, programID, iface.Index, iface.Name, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "attach XDP: %v", err)
	}

	return &pb.AttachResponse{
		LinkId: summary.KernelLinkID,
	}, nil
}

// attachTC handles TC attachment via the manager.
func (s *Server) attachTC(ctx context.Context, programID uint32, info *pb.TCAttachInfo) (*pb.AttachResponse, error) {
	// Validate direction
	direction := strings.ToLower(info.Direction)
	if direction != "ingress" && direction != "egress" {
		return nil, status.Errorf(codes.InvalidArgument, "direction must be 'ingress' or 'egress', got %q", info.Direction)
	}

	// Get interface index from name
	iface, err := net.InterfaceByName(info.Iface)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "interface %q: %v", info.Iface, err)
	}

	// Use provided priority or default
	priority := int(info.Priority)
	if priority == 0 {
		priority = 50 // Default priority
	}

	// Use provided proceed-on or default
	proceedOn := info.ProceedOn
	if len(proceedOn) == 0 {
		// Default: ok (0), pipe (3), dispatcher_return (30)
		proceedOn = []int32{0, 3, 30}
	}

	// Call manager with empty linkPinPath to auto-generate
	summary, err := s.mgr.AttachTC(ctx, programID, iface.Index, iface.Name, direction, priority, proceedOn, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "attach TC: %v", err)
	}

	return &pb.AttachResponse{
		LinkId: summary.KernelLinkID,
	}, nil
}

// Detach implements the Detach RPC method.
func (s *Server) Detach(ctx context.Context, req *pb.DetachRequest) (*pb.DetachResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.mgr.Detach(ctx, req.LinkId); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "link with ID %d not found", req.LinkId)
		}
		return nil, status.Errorf(codes.Internal, "detach link: %v", err)
	}

	return &pb.DetachResponse{}, nil
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
// It pre-pulls an OCI image to the local cache without loading any programs.
func (s *Server) PullBytecode(ctx context.Context, req *pb.PullBytecodeRequest) (*pb.PullBytecodeResponse, error) {
	if s.puller == nil {
		return nil, status.Error(codes.Unimplemented, "OCI image pulling not configured on this server")
	}

	if req.Image == nil {
		return nil, status.Error(codes.InvalidArgument, "image is required")
	}

	// Convert proto to interpreter types
	pullPolicy := protoToPullPolicy(req.Image.ImagePullPolicy)
	ref := interpreter.ImageRef{
		URL:        req.Image.Url,
		PullPolicy: pullPolicy,
	}
	if req.Image.Username != nil && *req.Image.Username != "" {
		ref.Auth = &interpreter.ImageAuth{
			Username: *req.Image.Username,
		}
		if req.Image.Password != nil {
			ref.Auth.Password = *req.Image.Password
		}
	}

	// Pull the image (this caches it)
	_, err := s.puller.Pull(ctx, ref)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to pull image %s: %v", req.Image.Url, err)
	}

	return &pb.PullBytecodeResponse{}, nil
}

// ListLinks implements the ListLinks RPC method.
func (s *Server) ListLinks(ctx context.Context, req *pb.ListLinksRequest) (*pb.ListLinksResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var links []bpfman.LinkSummary
	var err error

	if req.ProgramId != nil {
		links, err = s.store.ListLinksByProgram(ctx, *req.ProgramId)
	} else {
		links, err = s.store.ListLinks(ctx)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list links: %v", err)
	}

	resp := &pb.ListLinksResponse{
		Links: make([]*pb.LinkInfo, 0, len(links)),
	}
	for _, link := range links {
		resp.Links = append(resp.Links, &pb.LinkInfo{
			Summary: linkSummaryToProto(link),
		})
	}

	return resp, nil
}

// GetLink implements the GetLink RPC method.
func (s *Server) GetLink(ctx context.Context, req *pb.GetLinkRequest) (*pb.GetLinkResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	summary, details, err := s.store.GetLink(ctx, req.KernelLinkId)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "link with ID %d not found", req.KernelLinkId)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get link: %v", err)
	}

	return &pb.GetLinkResponse{
		Link: &pb.LinkInfo{
			Summary: linkSummaryToProto(summary),
			Details: linkDetailsToProto(details),
		},
	}, nil
}

// linkSummaryToProto converts a bpfman.LinkSummary to protobuf.
func linkSummaryToProto(s bpfman.LinkSummary) *pb.LinkSummary {
	return &pb.LinkSummary{
		KernelLinkId:    s.KernelLinkID,
		LinkType:        linkTypeToProto(s.LinkType),
		KernelProgramId: s.KernelProgramID,
		PinPath:         s.PinPath,
		CreatedAt:       s.CreatedAt.Format(time.RFC3339),
	}
}

// linkTypeToProto converts a bpfman.LinkType to protobuf.
func linkTypeToProto(t bpfman.LinkType) pb.BpfmanLinkType {
	switch t {
	case bpfman.LinkTypeTracepoint:
		return pb.BpfmanLinkType_LINK_TYPE_TRACEPOINT
	case bpfman.LinkTypeKprobe:
		return pb.BpfmanLinkType_LINK_TYPE_KPROBE
	case bpfman.LinkTypeKretprobe:
		return pb.BpfmanLinkType_LINK_TYPE_KRETPROBE
	case bpfman.LinkTypeUprobe:
		return pb.BpfmanLinkType_LINK_TYPE_UPROBE
	case bpfman.LinkTypeUretprobe:
		return pb.BpfmanLinkType_LINK_TYPE_URETPROBE
	case bpfman.LinkTypeFentry:
		return pb.BpfmanLinkType_LINK_TYPE_FENTRY
	case bpfman.LinkTypeFexit:
		return pb.BpfmanLinkType_LINK_TYPE_FEXIT
	case bpfman.LinkTypeXDP:
		return pb.BpfmanLinkType_LINK_TYPE_XDP
	case bpfman.LinkTypeTC:
		return pb.BpfmanLinkType_LINK_TYPE_TC
	case bpfman.LinkTypeTCX:
		return pb.BpfmanLinkType_LINK_TYPE_TCX
	default:
		return pb.BpfmanLinkType_LINK_TYPE_UNSPECIFIED
	}
}

// linkDetailsToProto converts bpfman.LinkDetails to protobuf.
func linkDetailsToProto(d bpfman.LinkDetails) *pb.LinkDetails {
	if d == nil {
		return nil
	}

	switch details := d.(type) {
	case bpfman.TracepointDetails:
		return &pb.LinkDetails{
			Details: &pb.LinkDetails_Tracepoint{
				Tracepoint: &pb.TracepointLinkDetails{
					Group: details.Group,
					Name:  details.Name,
				},
			},
		}
	case bpfman.KprobeDetails:
		return &pb.LinkDetails{
			Details: &pb.LinkDetails_Kprobe{
				Kprobe: &pb.KprobeLinkDetails{
					FnName:   details.FnName,
					Offset:   details.Offset,
					Retprobe: details.Retprobe,
				},
			},
		}
	case bpfman.UprobeDetails:
		return &pb.LinkDetails{
			Details: &pb.LinkDetails_Uprobe{
				Uprobe: &pb.UprobeLinkDetails{
					Target:   details.Target,
					FnName:   details.FnName,
					Offset:   details.Offset,
					Pid:      details.PID,
					Retprobe: details.Retprobe,
				},
			},
		}
	case bpfman.FentryDetails:
		return &pb.LinkDetails{
			Details: &pb.LinkDetails_Fentry{
				Fentry: &pb.FentryLinkDetails{
					FnName: details.FnName,
				},
			},
		}
	case bpfman.FexitDetails:
		return &pb.LinkDetails{
			Details: &pb.LinkDetails_Fexit{
				Fexit: &pb.FexitLinkDetails{
					FnName: details.FnName,
				},
			},
		}
	case bpfman.XDPDetails:
		return &pb.LinkDetails{
			Details: &pb.LinkDetails_Xdp{
				Xdp: &pb.XDPLinkDetails{
					Interface:    details.Interface,
					Ifindex:      details.Ifindex,
					Priority:     details.Priority,
					Position:     details.Position,
					ProceedOn:    details.ProceedOn,
					Netns:        details.Netns,
					Nsid:         details.Nsid,
					DispatcherId: details.DispatcherID,
					Revision:     details.Revision,
				},
			},
		}
	case bpfman.TCDetails:
		return &pb.LinkDetails{
			Details: &pb.LinkDetails_Tc{
				Tc: &pb.TCLinkDetails{
					Interface:    details.Interface,
					Ifindex:      details.Ifindex,
					Direction:    details.Direction,
					Priority:     details.Priority,
					Position:     details.Position,
					ProceedOn:    details.ProceedOn,
					Netns:        details.Netns,
					Nsid:         details.Nsid,
					DispatcherId: details.DispatcherID,
					Revision:     details.Revision,
				},
			},
		}
	case bpfman.TCXDetails:
		return &pb.LinkDetails{
			Details: &pb.LinkDetails_Tcx{
				Tcx: &pb.TCXLinkDetails{
					Interface: details.Interface,
					Ifindex:   details.Ifindex,
					Direction: details.Direction,
					Priority:  details.Priority,
					Netns:     details.Netns,
					Nsid:      details.Nsid,
				},
			},
		}
	default:
		return nil
	}
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
// Returns an error for unknown or unspecified types (parse, don't validate).
func protoToBpfmanType(pt pb.BpfmanProgramType) (bpfman.ProgramType, error) {
	switch pt {
	case pb.BpfmanProgramType_XDP:
		return bpfman.ProgramTypeXDP, nil
	case pb.BpfmanProgramType_TC:
		return bpfman.ProgramTypeTC, nil
	case pb.BpfmanProgramType_TRACEPOINT:
		return bpfman.ProgramTypeTracepoint, nil
	case pb.BpfmanProgramType_KPROBE:
		return bpfman.ProgramTypeKprobe, nil
	case pb.BpfmanProgramType_UPROBE:
		return bpfman.ProgramTypeUprobe, nil
	case pb.BpfmanProgramType_FENTRY:
		return bpfman.ProgramTypeFentry, nil
	case pb.BpfmanProgramType_FEXIT:
		return bpfman.ProgramTypeFexit, nil
	case pb.BpfmanProgramType_TCX:
		return bpfman.ProgramTypeTCX, nil
	default:
		return bpfman.ProgramTypeUnspecified, fmt.Errorf("unknown program type: %d", pt)
	}
}

// protoToPullPolicy converts a proto image pull policy to managed type.
// Proto values: 0=Always, 1=IfNotPresent, 2=Never (matches bpfman.ImagePullPolicy iota).
func protoToPullPolicy(policy int32) bpfman.ImagePullPolicy {
	switch policy {
	case 0:
		return bpfman.PullAlways
	case 1:
		return bpfman.PullIfNotPresent
	case 2:
		return bpfman.PullNever
	default:
		return bpfman.PullIfNotPresent
	}
}
