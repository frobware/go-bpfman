package server

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/frobware/go-bpfman"
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

	// Get reconciled list (programs in both DB and kernel)
	loaded, err := s.mgr.ListLoadedPrograms(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list programs: %v", err)
	}

	var results []*pb.ListResponse_ListResult

	for _, lp := range loaded {
		// Filter by program type if specified
		if req.ProgramType != nil && *req.ProgramType != uint32(lp.Program.ProgramType) {
			continue
		}

		// Filter by metadata if specified
		if len(req.MatchMetadata) > 0 {
			match := true
			for k, v := range req.MatchMetadata {
				if lp.Program.UserMetadata[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		info := &pb.ProgramInfo{
			Name:       lp.Program.ProgramName,
			Bytecode:   &pb.BytecodeLocation{Location: &pb.BytecodeLocation_File{File: lp.Program.ObjectPath}},
			Metadata:   lp.Program.UserMetadata,
			GlobalData: lp.Program.GlobalData,
			MapPinPath: lp.Program.MapPinPath,
		}
		if lp.Program.MapOwnerID != 0 {
			info.MapOwnerId = &lp.Program.MapOwnerID
		}

		results = append(results, &pb.ListResponse_ListResult{
			Info: info,
			KernelInfo: &pb.KernelProgramInfo{
				Id:          lp.KernelID,
				Name:        lp.KernelInfo.Name,
				ProgramType: uint32(lp.Program.ProgramType),
				Tag:         lp.KernelInfo.Tag,
				LoadedAt:    lp.KernelInfo.LoadedAt.Format(time.RFC3339),
				MapIds:      lp.KernelInfo.MapIDs,
				BtfId:       lp.KernelInfo.BTFId,
				BytesXlated: lp.KernelInfo.XlatedSize,
				BytesJited:  lp.KernelInfo.JitedSize,
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

	metadata, err := s.store.Get(ctx, req.Id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "program with ID %d not found", req.Id)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get program: %v", err)
	}

	// Query kernel for actual program info
	kp, err := s.kernel.GetProgramByID(ctx, req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "program %d exists in store but not in kernel: %v", req.Id, err)
	}

	// Query store for links associated with this program
	links, err := s.store.ListLinksByProgram(ctx, req.Id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list links for program %d: %v", req.Id, err)
	}
	linkIDs := make([]uint32, 0, len(links))
	for _, link := range links {
		linkIDs = append(linkIDs, link.KernelLinkID)
	}

	s.logger.InfoContext(ctx, "Get", "program_id", req.Id, "program_name", metadata.ProgramName, "links", len(linkIDs))

	info := &pb.ProgramInfo{
		Name:       metadata.ProgramName,
		Bytecode:   &pb.BytecodeLocation{Location: &pb.BytecodeLocation_File{File: metadata.ObjectPath}},
		Metadata:   metadata.UserMetadata,
		GlobalData: metadata.GlobalData,
		MapPinPath: metadata.MapPinPath,
		Links:      linkIDs,
	}
	if metadata.MapOwnerID != 0 {
		info.MapOwnerId = &metadata.MapOwnerID
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
			ProgramType:   uint32(metadata.ProgramType),
			Tag:           kp.Tag,
			LoadedAt:      kp.LoadedAt.Format(time.RFC3339),
			GplCompatible: metadata.GPLCompatible,
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

	s.logger.InfoContext(ctx, "ListLinks", "links", len(links))

	return resp, nil
}

// GetLink implements the GetLink RPC method.
func (s *Server) GetLink(ctx context.Context, req *pb.GetLinkRequest) (*pb.GetLinkResponse, error) {
	if err := s.mgr.GCIfNeeded(ctx, false); err != nil {
		return nil, status.Errorf(codes.Internal, "gc: %v", err)
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	summary, details, err := s.store.GetLink(ctx, req.KernelLinkId)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "link with ID %d not found", req.KernelLinkId)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get link: %v", err)
	}

	s.logger.InfoContext(ctx, "GetLink", "link_id", req.KernelLinkId, "type", summary.LinkType, "program_id", summary.KernelProgramID)

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
