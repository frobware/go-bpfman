package client

import (
	"time"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/kernel"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/manager"
	pb "github.com/frobware/go-bpfman/pkg/bpfman/server/pb"
)

// domainTypeToProto converts a bpfman.ProgramType to protobuf.
func domainTypeToProto(pt bpfman.ProgramType) pb.BpfmanProgramType {
	switch pt {
	case bpfman.ProgramTypeXDP:
		return pb.BpfmanProgramType_XDP
	case bpfman.ProgramTypeTC:
		return pb.BpfmanProgramType_TC
	case bpfman.ProgramTypeTracepoint:
		return pb.BpfmanProgramType_TRACEPOINT
	case bpfman.ProgramTypeKprobe:
		return pb.BpfmanProgramType_KPROBE
	case bpfman.ProgramTypeUprobe:
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

	managedInfo := managed.NewProgramInfo(name, progType, objectPath, pinPath, pinDir)

	kernelInfo := &remoteKernelInfo{
		programType:   progType,
		gplCompatible: true, // Default to true
	}
	if resp.KernelInfo != nil {
		kernelInfo.id = resp.KernelInfo.Id
		kernelInfo.name = resp.KernelInfo.Name
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
			}
		}

		if r.Info != nil {
			objectPath := ""
			if r.Info.Bytecode != nil {
				if file, ok := r.Info.Bytecode.Location.(*pb.BytecodeLocation_File); ok {
					objectPath = file.File
				}
			}

			mp.Metadata = &managed.Program{
				LoadSpec: managed.LoadSpec{
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

		prog := &managed.Program{
			LoadSpec: managed.LoadSpec{
				ObjectPath:  objectPath,
				ProgramName: resp.Info.Name,
				ProgramType: progType,
				PinPath:     resp.Info.MapPinPath,
				GlobalData:  resp.Info.GlobalData,
			},
			UserMetadata: resp.Info.Metadata,
		}
		info.Bpfman = &manager.BpfmanInfo{
			Program: prog,
		}
	}

	return info
}

// protoLinkTypeToManaged converts a protobuf link type to managed.LinkType.
func protoLinkTypeToManaged(t pb.BpfmanLinkType) managed.LinkType {
	switch t {
	case pb.BpfmanLinkType_LINK_TYPE_TRACEPOINT:
		return managed.LinkTypeTracepoint
	case pb.BpfmanLinkType_LINK_TYPE_KPROBE:
		return managed.LinkTypeKprobe
	case pb.BpfmanLinkType_LINK_TYPE_KRETPROBE:
		return managed.LinkTypeKretprobe
	case pb.BpfmanLinkType_LINK_TYPE_UPROBE:
		return managed.LinkTypeUprobe
	case pb.BpfmanLinkType_LINK_TYPE_URETPROBE:
		return managed.LinkTypeUretprobe
	case pb.BpfmanLinkType_LINK_TYPE_FENTRY:
		return managed.LinkTypeFentry
	case pb.BpfmanLinkType_LINK_TYPE_FEXIT:
		return managed.LinkTypeFexit
	case pb.BpfmanLinkType_LINK_TYPE_XDP:
		return managed.LinkTypeXDP
	case pb.BpfmanLinkType_LINK_TYPE_TC:
		return managed.LinkTypeTC
	case pb.BpfmanLinkType_LINK_TYPE_TCX:
		return managed.LinkTypeTCX
	default:
		return ""
	}
}

// protoLinkSummaryToManaged converts a protobuf LinkSummary to managed.LinkSummary.
func protoLinkSummaryToManaged(s *pb.LinkSummary) managed.LinkSummary {
	if s == nil {
		return managed.LinkSummary{}
	}

	createdAt, _ := time.Parse(time.RFC3339, s.CreatedAt)

	return managed.LinkSummary{
		KernelLinkID:    s.KernelLinkId,
		LinkType:        protoLinkTypeToManaged(s.LinkType),
		KernelProgramID: s.KernelProgramId,
		PinPath:         s.PinPath,
		CreatedAt:       createdAt,
	}
}

// protoLinkDetailsToManaged converts a protobuf LinkDetails to managed.LinkDetails.
func protoLinkDetailsToManaged(d *pb.LinkDetails) managed.LinkDetails {
	if d == nil {
		return nil
	}

	switch details := d.Details.(type) {
	case *pb.LinkDetails_Tracepoint:
		return managed.TracepointDetails{
			Group: details.Tracepoint.Group,
			Name:  details.Tracepoint.Name,
		}
	case *pb.LinkDetails_Kprobe:
		return managed.KprobeDetails{
			FnName:   details.Kprobe.FnName,
			Offset:   details.Kprobe.Offset,
			Retprobe: details.Kprobe.Retprobe,
		}
	case *pb.LinkDetails_Uprobe:
		return managed.UprobeDetails{
			Target:   details.Uprobe.Target,
			FnName:   details.Uprobe.FnName,
			Offset:   details.Uprobe.Offset,
			PID:      details.Uprobe.Pid,
			Retprobe: details.Uprobe.Retprobe,
		}
	case *pb.LinkDetails_Fentry:
		return managed.FentryDetails{
			FnName: details.Fentry.FnName,
		}
	case *pb.LinkDetails_Fexit:
		return managed.FexitDetails{
			FnName: details.Fexit.FnName,
		}
	case *pb.LinkDetails_Xdp:
		return managed.XDPDetails{
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
		return managed.TCDetails{
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
		return managed.TCXDetails{
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

// protoListLinksResponseToSummaries converts a ListLinksResponse to []managed.LinkSummary.
func protoListLinksResponseToSummaries(resp *pb.ListLinksResponse) []managed.LinkSummary {
	if resp == nil || len(resp.Links) == 0 {
		return nil
	}

	result := make([]managed.LinkSummary, 0, len(resp.Links))
	for _, link := range resp.Links {
		if link.Summary != nil {
			result = append(result, protoLinkSummaryToManaged(link.Summary))
		}
	}
	return result
}
