package client

import (
	"fmt"
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
func domainTypeToProto(pt bpfman.ProgramType) (pb.BpfmanProgramType, error) {
	switch pt {
	case bpfman.ProgramTypeXDP:
		return pb.BpfmanProgramType_XDP, nil
	case bpfman.ProgramTypeTC:
		return pb.BpfmanProgramType_TC, nil
	case bpfman.ProgramTypeTracepoint:
		return pb.BpfmanProgramType_TRACEPOINT, nil
	case bpfman.ProgramTypeKprobe, bpfman.ProgramTypeKretprobe:
		return pb.BpfmanProgramType_KPROBE, nil
	case bpfman.ProgramTypeUprobe, bpfman.ProgramTypeUretprobe:
		return pb.BpfmanProgramType_UPROBE, nil
	case bpfman.ProgramTypeFentry:
		return pb.BpfmanProgramType_FENTRY, nil
	case bpfman.ProgramTypeFexit:
		return pb.BpfmanProgramType_FEXIT, nil
	case bpfman.ProgramTypeTCX:
		return pb.BpfmanProgramType_TCX, nil
	default:
		return 0, fmt.Errorf("unsupported program type: %v", pt)
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
func protoTypeToDomain(pt pb.BpfmanProgramType) (bpfman.ProgramType, error) {
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
		return bpfman.ProgramTypeUnspecified, fmt.Errorf("unknown proto program type: %d", pt)
	}
}

// validateProgramType validates a raw uint32 value as a bpfman.ProgramType.
// The KernelProgramInfo.program_type field stores domain type values directly,
// not proto enum values.
func validateProgramType(raw uint32) (bpfman.ProgramType, error) {
	pt := bpfman.ProgramType(raw)
	switch pt {
	case bpfman.ProgramTypeUnspecified,
		bpfman.ProgramTypeXDP,
		bpfman.ProgramTypeTC,
		bpfman.ProgramTypeTCX,
		bpfman.ProgramTypeTracepoint,
		bpfman.ProgramTypeKprobe,
		bpfman.ProgramTypeKretprobe,
		bpfman.ProgramTypeUprobe,
		bpfman.ProgramTypeUretprobe,
		bpfman.ProgramTypeFentry,
		bpfman.ProgramTypeFexit:
		return pt, nil
	default:
		return bpfman.ProgramTypeUnspecified, fmt.Errorf("invalid program type: %d", raw)
	}
}

// protoLoadResponseToManagedProgram converts a LoadResponseInfo to bpfman.ManagedProgram.
func protoLoadResponseToManagedProgram(resp *pb.LoadResponseInfo) (bpfman.ManagedProgram, error) {
	var progType bpfman.ProgramType
	var name, objectPath, pinPath, pinDir string

	if resp.KernelInfo != nil {
		var err error
		progType, err = validateProgramType(resp.KernelInfo.ProgramType)
		if err != nil {
			return bpfman.ManagedProgram{}, fmt.Errorf("convert program type: %w", err)
		}
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

	managedInfo := &bpfman.LoadedProgramInfo{
		Name:       name,
		Type:       progType,
		ObjectPath: objectPath,
		PinPath:    pinPath,
		PinDir:     pinDir,
	}

	kernelProg := &kernel.Program{
		ProgramType:   progType.String(),
		GPLCompatible: true, // Default to true
	}
	if resp.KernelInfo != nil {
		kernelProg.ID = resp.KernelInfo.Id
		kernelProg.Name = resp.KernelInfo.Name
		kernelProg.Tag = resp.KernelInfo.Tag
		kernelProg.MapIDs = resp.KernelInfo.MapIds
		kernelProg.HasMapIDs = len(resp.KernelInfo.MapIds) > 0
		kernelProg.BTFId = resp.KernelInfo.BtfId
		kernelProg.HasBTFId = resp.KernelInfo.BtfId > 0
		kernelProg.XlatedSize = resp.KernelInfo.BytesXlated
		kernelProg.JitedSize = resp.KernelInfo.BytesJited
		kernelProg.VerifiedInstructions = resp.KernelInfo.VerifiedInsns
		kernelProg.GPLCompatible = resp.KernelInfo.GplCompatible
		kernelProg.Memlock = uint64(resp.KernelInfo.BytesMemlock)
		kernelProg.HasMemlock = resp.KernelInfo.BytesMemlock > 0
		if resp.KernelInfo.LoadedAt != "" {
			kernelProg.LoadedAt, _ = time.Parse(time.RFC3339, resp.KernelInfo.LoadedAt)
		}
	}

	return bpfman.ManagedProgram{
		Managed: managedInfo,
		Kernel:  kernelProg,
	}, nil
}

// protoListResponseToPrograms converts a ListResponse to []manager.ManagedProgram.
func protoListResponseToPrograms(resp *pb.ListResponse) ([]manager.ManagedProgram, error) {
	if resp == nil || len(resp.Results) == 0 {
		return nil, nil
	}

	result := make([]manager.ManagedProgram, 0, len(resp.Results))
	for _, r := range resp.Results {
		mp := manager.ManagedProgram{}

		var progType bpfman.ProgramType
		if r.KernelInfo != nil {
			var err error
			progType, err = validateProgramType(r.KernelInfo.ProgramType)
			if err != nil {
				return nil, fmt.Errorf("convert program type for ID %d: %w", r.KernelInfo.Id, err)
			}
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

			mp.Metadata = &bpfman.ProgramRecord{
				Name:         r.Info.Name,
				ProgramType:  progType,
				ObjectPath:   objectPath,
				PinPath:      r.Info.MapPinPath,
				GlobalData:   r.Info.GlobalData,
				UserMetadata: r.Info.Metadata,
			}
		}

		result = append(result, mp)
	}

	return result, nil
}

// protoGetResponseToInfo converts a GetResponse to manager.ProgramInfo.
func protoGetResponseToInfo(resp *pb.GetResponse, kernelID uint32) (manager.ProgramInfo, error) {
	info := manager.ProgramInfo{}

	var progType bpfman.ProgramType
	if resp.KernelInfo != nil {
		var err error
		progType, err = validateProgramType(resp.KernelInfo.ProgramType)
		if err != nil {
			return manager.ProgramInfo{}, fmt.Errorf("convert program type: %w", err)
		}
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

		prog := &bpfman.ProgramRecord{
			Name:         resp.Info.Name,
			ProgramType:  progType,
			ObjectPath:   objectPath,
			PinPath:      resp.Info.MapPinPath,
			GlobalData:   resp.Info.GlobalData,
			UserMetadata: resp.Info.Metadata,
		}
		// GPL compatibility is stored in the database at load time (from the
		// ELF license section). Despite the field name, KernelInfo.GplCompatible
		// contains store-derived data, not live kernel data. The kernel doesn't
		// expose GPL compatibility after load. The field is in KernelProgramInfo
		// because the protobuf schema is a stable API that we cannot modify.
		if resp.KernelInfo != nil {
			prog.GPLCompatible = resp.KernelInfo.GplCompatible
		}

		// Convert link IDs to LinkRecord (summary only, no details from this RPC)
		var links []bpfman.LinkRecord
		for _, linkID := range resp.Info.Links {
			links = append(links, bpfman.LinkRecord{
				ID: bpfman.LinkID(linkID),
				// Details not available from Get RPC
			})
		}

		info.Bpfman = &manager.BpfmanInfo{
			Program: prog,
			Links:   links,
		}
	}

	return info, nil
}

// protoLinkKindToManaged converts a protobuf link type to bpfman.LinkKind.
func protoLinkKindToManaged(t pb.BpfmanLinkType) bpfman.LinkKind {
	switch t {
	case pb.BpfmanLinkType_LINK_TYPE_TRACEPOINT:
		return bpfman.LinkKindTracepoint
	case pb.BpfmanLinkType_LINK_TYPE_KPROBE:
		return bpfman.LinkKindKprobe
	case pb.BpfmanLinkType_LINK_TYPE_KRETPROBE:
		return bpfman.LinkKindKretprobe
	case pb.BpfmanLinkType_LINK_TYPE_UPROBE:
		return bpfman.LinkKindUprobe
	case pb.BpfmanLinkType_LINK_TYPE_URETPROBE:
		return bpfman.LinkKindUretprobe
	case pb.BpfmanLinkType_LINK_TYPE_FENTRY:
		return bpfman.LinkKindFentry
	case pb.BpfmanLinkType_LINK_TYPE_FEXIT:
		return bpfman.LinkKindFexit
	case pb.BpfmanLinkType_LINK_TYPE_XDP:
		return bpfman.LinkKindXDP
	case pb.BpfmanLinkType_LINK_TYPE_TC:
		return bpfman.LinkKindTC
	case pb.BpfmanLinkType_LINK_TYPE_TCX:
		return bpfman.LinkKindTCX
	default:
		return ""
	}
}

// protoLinkSummaryToRecord converts a protobuf LinkSummary to bpfman.LinkRecord.
func protoLinkSummaryToRecord(s *pb.LinkSummary) bpfman.LinkRecord {
	if s == nil {
		return bpfman.LinkRecord{}
	}

	createdAt, _ := time.Parse(time.RFC3339, s.CreatedAt)

	var kernelLinkID *uint32
	if s.KernelLinkId != 0 {
		kernelLinkID = &s.KernelLinkId
	}

	return bpfman.LinkRecord{
		ID:              bpfman.LinkID(s.KernelLinkId),
		Kind:            protoLinkKindToManaged(s.LinkType),
		KernelLinkID:    kernelLinkID,
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

// protoListLinksResponseToRecords converts a ListLinksResponse to []bpfman.LinkRecord.
func protoListLinksResponseToRecords(resp *pb.ListLinksResponse) []bpfman.LinkRecord {
	if resp == nil || len(resp.Links) == 0 {
		return nil
	}

	result := make([]bpfman.LinkRecord, 0, len(resp.Links))
	for _, link := range resp.Links {
		if link.Summary != nil {
			result = append(result, protoLinkSummaryToRecord(link.Summary))
		}
	}
	return result
}
