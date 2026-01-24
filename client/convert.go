package client

import (
	"time"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/kernel"
	"github.com/frobware/go-bpfman/manager"
	pb "github.com/frobware/go-bpfman/server/pb"
)

// domainTypeToProto converts a bpfman.ProgramType to protobuf.
// Note: kretprobe/uretprobe map to KPROBE/UPROBE since the proto enum
// doesn't have separate values. Use ActualTypeMetadataKey to preserve
// the distinction.
func domainTypeToProto(pt bpfman.ProgramType) pb.BpfmanProgramType {
	switch pt {
	case bpfman.ProgramTypeXDP:
		return pb.BpfmanProgramType_XDP
	case bpfman.ProgramTypeTC:
		return pb.BpfmanProgramType_TC
	case bpfman.ProgramTypeTracepoint:
		return pb.BpfmanProgramType_TRACEPOINT
	case bpfman.ProgramTypeKprobe, bpfman.ProgramTypeKretprobe:
		return pb.BpfmanProgramType_KPROBE
	case bpfman.ProgramTypeUprobe, bpfman.ProgramTypeUretprobe:
		return pb.BpfmanProgramType_UPROBE
	case bpfman.ProgramTypeFentry:
		return pb.BpfmanProgramType_FENTRY
	case bpfman.ProgramTypeFexit:
		return pb.BpfmanProgramType_FEXIT
	case bpfman.ProgramTypeTCX:
		return pb.BpfmanProgramType_TCX
	default:
		return pb.BpfmanProgramType_XDP
	}
}

// ActualTypeMetadataKey returns the metadata key used to preserve the actual
// program type when the proto enum doesn't distinguish (e.g., kretprobe vs kprobe).
// Format: "bpfman.io/actual-type:<program-name>"
func ActualTypeMetadataKey(programName string) string {
	return "bpfman.io/actual-type:" + programName
}

// NeedsTypeMetadata returns true if the program type requires metadata to
// preserve its distinction (kretprobe, uretprobe).
func NeedsTypeMetadata(pt bpfman.ProgramType) bool {
	return pt == bpfman.ProgramTypeKretprobe || pt == bpfman.ProgramTypeUretprobe
}

// protoTypeToDomain converts a protobuf program type to bpfman.ProgramType.
func protoTypeToDomain(pt pb.BpfmanProgramType) bpfman.ProgramType {
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

// remoteKernelInfo implements bpfman.KernelProgramInfo for remote responses.
type remoteKernelInfo struct {
	id                   uint32
	name                 string
	programType          bpfman.ProgramType
	tag                  string
	mapIDs               []uint32
	btfID                uint32
	bytesXlated          uint32
	bytesJited           uint32
	verifiedInstructions uint32
	loadedAt             time.Time
	memoryLocked         uint64
	gplCompatible        bool
}

func (r *remoteKernelInfo) ID() uint32                   { return r.id }
func (r *remoteKernelInfo) Name() string                 { return r.name }
func (r *remoteKernelInfo) Type() bpfman.ProgramType     { return r.programType }
func (r *remoteKernelInfo) Tag() string                  { return r.tag }
func (r *remoteKernelInfo) MapIDs() []uint32             { return r.mapIDs }
func (r *remoteKernelInfo) BTFId() uint32                { return r.btfID }
func (r *remoteKernelInfo) BytesXlated() uint32          { return r.bytesXlated }
func (r *remoteKernelInfo) BytesJited() uint32           { return r.bytesJited }
func (r *remoteKernelInfo) VerifiedInstructions() uint32 { return r.verifiedInstructions }
func (r *remoteKernelInfo) LoadedAt() time.Time          { return r.loadedAt }
func (r *remoteKernelInfo) MemoryLocked() uint64         { return r.memoryLocked }
func (r *remoteKernelInfo) GPLCompatible() bool          { return r.gplCompatible }

// protoLoadResponseToManagedProgram converts a LoadResponseInfo to bpfman.ManagedProgram.
func protoLoadResponseToManagedProgram(resp *pb.LoadResponseInfo) bpfman.ManagedProgram {
	var progType bpfman.ProgramType
	var name, objectPath, pinPath, pinDir string

	if resp.KernelInfo != nil {
		progType = bpfman.ProgramType(resp.KernelInfo.ProgramType)
		name = resp.KernelInfo.Name
	}

	if resp.Info != nil {
		pinDir = resp.Info.MapPinPath
		pinPath = resp.Info.MapPinPath + "/" + resp.Info.Name
		if name == "" {
			name = resp.Info.Name
		}
		if resp.Info.Bytecode != nil {
			if file, ok := resp.Info.Bytecode.Location.(*pb.BytecodeLocation_File); ok {
				objectPath = file.File
			}
		}
	}

	managedInfo := &bpfman.ProgramInfo{
		Name:       name,
		Type:       progType,
		ObjectPath: objectPath,
		PinPath:    pinPath,
		PinDir:     pinDir,
	}

	kernelInfo := &remoteKernelInfo{
		programType:   progType,
		gplCompatible: true, // Default to true
	}
	if resp.KernelInfo != nil {
		kernelInfo.id = resp.KernelInfo.Id
		kernelInfo.name = resp.KernelInfo.Name
		kernelInfo.tag = resp.KernelInfo.Tag
		kernelInfo.mapIDs = resp.KernelInfo.MapIds
		kernelInfo.btfID = resp.KernelInfo.BtfId
		kernelInfo.bytesXlated = resp.KernelInfo.BytesXlated
		kernelInfo.bytesJited = resp.KernelInfo.BytesJited
		kernelInfo.verifiedInstructions = resp.KernelInfo.VerifiedInsns
		kernelInfo.gplCompatible = resp.KernelInfo.GplCompatible
		kernelInfo.memoryLocked = uint64(resp.KernelInfo.BytesMemlock)
		if resp.KernelInfo.LoadedAt != "" {
			kernelInfo.loadedAt, _ = time.Parse(time.RFC3339, resp.KernelInfo.LoadedAt)
		}
	}

	return bpfman.ManagedProgram{
		Managed: managedInfo,
		Kernel:  kernelInfo,
	}
}

// protoListResponseToPrograms converts a ListResponse to []manager.ManagedProgram.
func protoListResponseToPrograms(resp *pb.ListResponse) []manager.ManagedProgram {
	if resp == nil || len(resp.Results) == 0 {
		return nil
	}

	result := make([]manager.ManagedProgram, 0, len(resp.Results))
	for _, r := range resp.Results {
		mp := manager.ManagedProgram{}

		var progType bpfman.ProgramType
		if r.KernelInfo != nil {
			progType = bpfman.ProgramType(r.KernelInfo.ProgramType)
			mp.KernelProgram = kernel.Program{
				ID:          r.KernelInfo.Id,
				Name:        r.KernelInfo.Name,
				ProgramType: progType.String(),
				Tag:         r.KernelInfo.Tag,
				MapIDs:      r.KernelInfo.MapIds,
				BTFId:       r.KernelInfo.BtfId,
				XlatedSize:  r.KernelInfo.BytesXlated,
				JitedSize:   r.KernelInfo.BytesJited,
			}
			// Parse LoadedAt time if provided
			if r.KernelInfo.LoadedAt != "" {
				if loadedAt, err := time.Parse(time.RFC3339, r.KernelInfo.LoadedAt); err == nil {
					mp.KernelProgram.LoadedAt = loadedAt
				}
			}
		}

		if r.Info != nil {
			objectPath := ""
			if r.Info.Bytecode != nil {
				if file, ok := r.Info.Bytecode.Location.(*pb.BytecodeLocation_File); ok {
					objectPath = file.File
				}
			}

			mp.Metadata = &bpfman.Program{
				LoadSpec: bpfman.LoadSpec{
					ObjectPath:  objectPath,
					ProgramName: r.Info.Name,
					ProgramType: progType,
					PinPath:     r.Info.MapPinPath,
					GlobalData:  r.Info.GlobalData,
				},
				UserMetadata: r.Info.Metadata,
			}
		}

		result = append(result, mp)
	}

	return result
}

// protoGetResponseToInfo converts a GetResponse to manager.ProgramInfo.
func protoGetResponseToInfo(resp *pb.GetResponse, kernelID uint32) manager.ProgramInfo {
	info := manager.ProgramInfo{}

	var progType bpfman.ProgramType
	if resp.KernelInfo != nil {
		progType = bpfman.ProgramType(resp.KernelInfo.ProgramType)
		kp := kernel.Program{
			ID:          resp.KernelInfo.Id,
			Name:        resp.KernelInfo.Name,
			ProgramType: progType.String(),
			Tag:         resp.KernelInfo.Tag,
			MapIDs:      resp.KernelInfo.MapIds,
			BTFId:       resp.KernelInfo.BtfId,
			XlatedSize:  resp.KernelInfo.BytesXlated,
			JitedSize:   resp.KernelInfo.BytesJited,
		}
		// Parse LoadedAt time if provided
		if resp.KernelInfo.LoadedAt != "" {
			if loadedAt, err := time.Parse(time.RFC3339, resp.KernelInfo.LoadedAt); err == nil {
				kp.LoadedAt = loadedAt
			}
		}
		info.Kernel = &manager.KernelInfo{
			Program: &kp,
		}
	}

	if resp.Info != nil {
		objectPath := ""
		if resp.Info.Bytecode != nil {
			if file, ok := resp.Info.Bytecode.Location.(*pb.BytecodeLocation_File); ok {
				objectPath = file.File
			}
		}

		prog := &bpfman.Program{
			LoadSpec: bpfman.LoadSpec{
				ObjectPath:  objectPath,
				ProgramName: resp.Info.Name,
				ProgramType: progType,
				PinPath:     resp.Info.MapPinPath,
				GlobalData:  resp.Info.GlobalData,
			},
			UserMetadata: resp.Info.Metadata,
		}

		// Convert link IDs to LinkWithDetails (summary only, no details from this RPC)
		var linksWithDetails []manager.LinkWithDetails
		for _, linkID := range resp.Info.Links {
			linksWithDetails = append(linksWithDetails, manager.LinkWithDetails{
				Summary: bpfman.LinkSummary{
					KernelLinkID:    linkID,
					KernelProgramID: kernelID,
				},
				Details: nil, // Details not available from Get RPC
			})
		}

		info.Bpfman = &manager.BpfmanInfo{
			Program: prog,
			Links:   linksWithDetails,
		}
	}

	return info
}

// protoLinkTypeToManaged converts a protobuf link type to bpfman.LinkType.
func protoLinkTypeToManaged(t pb.BpfmanLinkType) bpfman.LinkType {
	switch t {
	case pb.BpfmanLinkType_LINK_TYPE_TRACEPOINT:
		return bpfman.LinkTypeTracepoint
	case pb.BpfmanLinkType_LINK_TYPE_KPROBE:
		return bpfman.LinkTypeKprobe
	case pb.BpfmanLinkType_LINK_TYPE_KRETPROBE:
		return bpfman.LinkTypeKretprobe
	case pb.BpfmanLinkType_LINK_TYPE_UPROBE:
		return bpfman.LinkTypeUprobe
	case pb.BpfmanLinkType_LINK_TYPE_URETPROBE:
		return bpfman.LinkTypeUretprobe
	case pb.BpfmanLinkType_LINK_TYPE_FENTRY:
		return bpfman.LinkTypeFentry
	case pb.BpfmanLinkType_LINK_TYPE_FEXIT:
		return bpfman.LinkTypeFexit
	case pb.BpfmanLinkType_LINK_TYPE_XDP:
		return bpfman.LinkTypeXDP
	case pb.BpfmanLinkType_LINK_TYPE_TC:
		return bpfman.LinkTypeTC
	case pb.BpfmanLinkType_LINK_TYPE_TCX:
		return bpfman.LinkTypeTCX
	default:
		return ""
	}
}

// protoLinkSummaryToManaged converts a protobuf LinkSummary to bpfman.LinkSummary.
func protoLinkSummaryToManaged(s *pb.LinkSummary) bpfman.LinkSummary {
	if s == nil {
		return bpfman.LinkSummary{}
	}

	createdAt, _ := time.Parse(time.RFC3339, s.CreatedAt)

	return bpfman.LinkSummary{
		KernelLinkID:    s.KernelLinkId,
		LinkType:        protoLinkTypeToManaged(s.LinkType),
		KernelProgramID: s.KernelProgramId,
		PinPath:         s.PinPath,
		CreatedAt:       createdAt,
	}
}

// protoLinkDetailsToManaged converts a protobuf LinkDetails to bpfman.LinkDetails.
func protoLinkDetailsToManaged(d *pb.LinkDetails) bpfman.LinkDetails {
	if d == nil {
		return nil
	}

	switch details := d.Details.(type) {
	case *pb.LinkDetails_Tracepoint:
		return bpfman.TracepointDetails{
			Group: details.Tracepoint.Group,
			Name:  details.Tracepoint.Name,
		}
	case *pb.LinkDetails_Kprobe:
		return bpfman.KprobeDetails{
			FnName:   details.Kprobe.FnName,
			Offset:   details.Kprobe.Offset,
			Retprobe: details.Kprobe.Retprobe,
		}
	case *pb.LinkDetails_Uprobe:
		return bpfman.UprobeDetails{
			Target:   details.Uprobe.Target,
			FnName:   details.Uprobe.FnName,
			Offset:   details.Uprobe.Offset,
			PID:      details.Uprobe.Pid,
			Retprobe: details.Uprobe.Retprobe,
		}
	case *pb.LinkDetails_Fentry:
		return bpfman.FentryDetails{
			FnName: details.Fentry.FnName,
		}
	case *pb.LinkDetails_Fexit:
		return bpfman.FexitDetails{
			FnName: details.Fexit.FnName,
		}
	case *pb.LinkDetails_Xdp:
		return bpfman.XDPDetails{
			Interface:    details.Xdp.Interface,
			Ifindex:      details.Xdp.Ifindex,
			Priority:     details.Xdp.Priority,
			Position:     details.Xdp.Position,
			ProceedOn:    details.Xdp.ProceedOn,
			Netns:        details.Xdp.Netns,
			Nsid:         details.Xdp.Nsid,
			DispatcherID: details.Xdp.DispatcherId,
			Revision:     details.Xdp.Revision,
		}
	case *pb.LinkDetails_Tc:
		return bpfman.TCDetails{
			Interface:    details.Tc.Interface,
			Ifindex:      details.Tc.Ifindex,
			Direction:    details.Tc.Direction,
			Priority:     details.Tc.Priority,
			Position:     details.Tc.Position,
			ProceedOn:    details.Tc.ProceedOn,
			Netns:        details.Tc.Netns,
			Nsid:         details.Tc.Nsid,
			DispatcherID: details.Tc.DispatcherId,
			Revision:     details.Tc.Revision,
		}
	case *pb.LinkDetails_Tcx:
		return bpfman.TCXDetails{
			Interface: details.Tcx.Interface,
			Ifindex:   details.Tcx.Ifindex,
			Direction: details.Tcx.Direction,
			Priority:  details.Tcx.Priority,
			Netns:     details.Tcx.Netns,
			Nsid:      details.Tcx.Nsid,
		}
	default:
		return nil
	}
}

// protoListLinksResponseToSummaries converts a ListLinksResponse to []bpfman.LinkSummary.
func protoListLinksResponseToSummaries(resp *pb.ListLinksResponse) []bpfman.LinkSummary {
	if resp == nil || len(resp.Links) == 0 {
		return nil
	}

	result := make([]bpfman.LinkSummary, 0, len(resp.Links))
	for _, link := range resp.Links {
		if link.Summary != nil {
			result = append(result, protoLinkSummaryToManaged(link.Summary))
		}
	}
	return result
}
