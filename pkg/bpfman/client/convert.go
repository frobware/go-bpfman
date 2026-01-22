package client

import (
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

// protoLoadResponseToLoaded converts a LoadResponseInfo to managed.Loaded.
func protoLoadResponseToLoaded(resp *pb.LoadResponseInfo, uuid string) managed.Loaded {
	loaded := managed.Loaded{
		UUID: uuid,
	}

	if resp.KernelInfo != nil {
		loaded.ID = resp.KernelInfo.Id
		loaded.Name = resp.KernelInfo.Name
		loaded.ProgramType = bpfman.ProgramType(resp.KernelInfo.ProgramType)
		loaded.MapIDs = resp.KernelInfo.MapIds
	}

	if resp.Info != nil {
		loaded.PinDir = resp.Info.MapPinPath
		loaded.PinPath = resp.Info.MapPinPath + "/" + resp.Info.Name
	}

	return loaded
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
