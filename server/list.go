package server

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/bpffs"
	"github.com/frobware/go-bpfman/inspect"
	"github.com/frobware/go-bpfman/interpreter/store"
	pb "github.com/frobware/go-bpfman/server/pb"
)

// List implements the List RPC method.
func (s *Server) List(ctx context.Context, req *pb.ListRequest) (*pb.ListResponse, error) {
	if err := s.mgr.GCIfNeeded(ctx, false); err != nil {
		return nil, status.Errorf(codes.Internal, "gc: %v", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	scanner := bpffs.NewScanner(s.dirs.ScannerDirs())
	world, err := inspect.Snapshot(ctx, s.store, s.kernel, scanner)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to snapshot: %v", err)
	}

	var results []*pb.ListResponse_ListResult

	for _, row := range world.ManagedPrograms() {
		// Only include programs that are also in kernel
		if !row.Presence.InKernel {
			continue
		}

		prog := row.StoreProgram
		kp := row.KernelProgram

		// Filter by program type if specified
		if req.ProgramType != nil && *req.ProgramType != uint32(prog.ProgramType) {
			continue
		}

		// Filter by metadata if specified
		if len(req.MatchMetadata) > 0 {
			match := true
			for k, v := range req.MatchMetadata {
				if prog.UserMetadata[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		info := &pb.ProgramInfo{
			Name:       prog.ProgramName,
			Bytecode:   &pb.BytecodeLocation{Location: &pb.BytecodeLocation_File{File: prog.ObjectPath}},
			Metadata:   prog.UserMetadata,
			GlobalData: prog.GlobalData,
			MapPinPath: prog.MapPinPath,
		}
		if prog.MapOwnerID != 0 {
			info.MapOwnerId = &prog.MapOwnerID
		}

		results = append(results, &pb.ListResponse_ListResult{
			Info: info,
			KernelInfo: &pb.KernelProgramInfo{
				Id:          row.KernelID,
				Name:        kp.Name,
				ProgramType: uint32(prog.ProgramType),
				Tag:         kp.Tag,
				LoadedAt:    kp.LoadedAt.Format(time.RFC3339),
				MapIds:      kp.MapIDs,
				BtfId:       kp.BTFId,
				BytesXlated: kp.XlatedSize,
				BytesJited:  kp.JitedSize,
			},
		})
	}

	s.logger.InfoContext(ctx, "List", "programs", len(results))

	return &pb.ListResponse{Results: results}, nil
}

// Get implements the Get RPC method.
func (s *Server) Get(ctx context.Context, req *pb.GetRequest) (*pb.GetResponse, error) {
	if err := s.mgr.GCIfNeeded(ctx, false); err != nil {
		return nil, status.Errorf(codes.Internal, "gc: %v", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	scanner := bpffs.NewScanner(s.dirs.ScannerDirs())
	row, err := inspect.GetProgram(ctx, s.store, s.kernel, scanner, req.Id)
	if errors.Is(err, inspect.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get program: %v", err)
	}

	// Require program to be managed (in store)
	if !row.Presence.InStore {
		return nil, status.Errorf(codes.NotFound, "program %d not managed by bpfman", req.Id)
	}

	// Require program to be alive in kernel
	if !row.Presence.InKernel {
		return nil, status.Errorf(codes.Internal, "program %d exists in store but not in kernel (requires reconciliation)", req.Id)
	}

	prog := row.StoreProgram
	kp := row.KernelProgram

	// Query store for links associated with this program
	links, err := s.store.ListLinksByProgram(ctx, req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list links for program %d: %v", req.Id, err)
	}
	linkIDs := make([]uint32, 0, len(links))
	for _, link := range links {
		linkIDs = append(linkIDs, link.KernelLinkID)
	}

	s.logger.InfoContext(ctx, "Get", "program_id", req.Id, "program_name", prog.ProgramName, "links", len(linkIDs))

	info := &pb.ProgramInfo{
		Name:       prog.ProgramName,
		Bytecode:   &pb.BytecodeLocation{Location: &pb.BytecodeLocation_File{File: prog.ObjectPath}},
		Metadata:   prog.UserMetadata,
		GlobalData: prog.GlobalData,
		MapPinPath: prog.MapPinPath,
		Links:      linkIDs,
	}
	if prog.MapOwnerID != 0 {
		info.MapOwnerId = &prog.MapOwnerID
	}

	// Note: GplCompatible is stored in the database at load time (from the
	// ELF license section) and retrieved here from metadata, not from the
	// kernel. The kernel doesn't expose GPL compatibility after load. The
	// field is in KernelProgramInfo because the protobuf schema is a stable
	// API that we cannot modify.
	return &pb.GetResponse{
		Info: info,
		KernelInfo: &pb.KernelProgramInfo{
			Id:            req.Id,
			Name:          kp.Name,
			ProgramType:   uint32(prog.ProgramType),
			Tag:           kp.Tag,
			LoadedAt:      kp.LoadedAt.Format(time.RFC3339),
			GplCompatible: prog.GPLCompatible,
			MapIds:        kp.MapIDs,
			BtfId:         kp.BTFId,
			BytesXlated:   kp.XlatedSize,
			BytesJited:    kp.JitedSize,
		},
	}, nil
}

// ListLinks implements the ListLinks RPC method.
func (s *Server) ListLinks(ctx context.Context, req *pb.ListLinksRequest) (*pb.ListLinksResponse, error) {
	if err := s.mgr.GCIfNeeded(ctx, false); err != nil {
		return nil, status.Errorf(codes.Internal, "gc: %v", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	scanner := bpffs.NewScanner(s.dirs.ScannerDirs())
	world, err := inspect.Snapshot(ctx, s.store, s.kernel, scanner)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to snapshot: %v", err)
	}

	resp := &pb.ListLinksResponse{
		Links: make([]*pb.LinkInfo, 0),
	}

	for _, row := range world.ManagedLinks() {
		// Filter by program ID if specified
		if req.ProgramId != nil && row.KernelProgramID != *req.ProgramId {
			continue
		}

		resp.Links = append(resp.Links, &pb.LinkInfo{
			Summary: &pb.LinkSummary{
				KernelLinkId:    row.KernelLinkID,
				LinkType:        linkTypeStringToProto(row.LinkType),
				KernelProgramId: row.KernelProgramID,
				PinPath:         row.PinPath,
			},
		})
	}

	s.logger.InfoContext(ctx, "ListLinks", "links", len(resp.Links))

	return resp, nil
}

// GetLink implements the GetLink RPC method.
func (s *Server) GetLink(ctx context.Context, req *pb.GetLinkRequest) (*pb.GetLinkResponse, error) {
	if err := s.mgr.GCIfNeeded(ctx, false); err != nil {
		return nil, status.Errorf(codes.Internal, "gc: %v", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	scanner := bpffs.NewScanner(s.dirs.ScannerDirs())
	info, err := inspect.GetLink(ctx, s.store, s.kernel, scanner, req.KernelLinkId)
	if errors.Is(err, inspect.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "link with ID %d not found", req.KernelLinkId)
	}
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "link with ID %d not found", req.KernelLinkId)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get link: %v", err)
	}

	// Require link to be managed (in store)
	if !info.Presence.InStore {
		return nil, status.Errorf(codes.NotFound, "link %d not managed by bpfman", req.KernelLinkId)
	}

	s.logger.InfoContext(ctx, "GetLink", "link_id", req.KernelLinkId, "type", info.Summary.LinkType, "program_id", info.Summary.KernelProgramID)

	return &pb.GetLinkResponse{
		Link: &pb.LinkInfo{
			Summary: linkSummaryToProto(info.Summary),
			Details: linkDetailsToProto(info.Details),
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

// linkTypeStringToProto converts a link type string to protobuf.
// Used when working with inspect.LinkRow which stores type as string.
func linkTypeStringToProto(t string) pb.BpfmanLinkType {
	return linkTypeToProto(bpfman.LinkType(t))
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
