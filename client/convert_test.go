package client

import (
	"testing"

	"github.com/frobware/go-bpfman"
	pb "github.com/frobware/go-bpfman/server/pb"
)

// TestDomainTypeToProto verifies that domain types are correctly converted
// to proto types for outgoing gRPC requests (e.g., Load requests).
func TestDomainTypeToProto(t *testing.T) {
	tests := []struct {
		name      string
		input     bpfman.ProgramType
		want      pb.BpfmanProgramType
		wantError bool
	}{
		{"XDP", bpfman.ProgramTypeXDP, pb.BpfmanProgramType_XDP, false},
		{"TC", bpfman.ProgramTypeTC, pb.BpfmanProgramType_TC, false},
		{"TCX", bpfman.ProgramTypeTCX, pb.BpfmanProgramType_TCX, false},
		{"Tracepoint", bpfman.ProgramTypeTracepoint, pb.BpfmanProgramType_TRACEPOINT, false},
		{"Kprobe", bpfman.ProgramTypeKprobe, pb.BpfmanProgramType_KPROBE, false},
		{"Kretprobe maps to KPROBE", bpfman.ProgramTypeKretprobe, pb.BpfmanProgramType_KPROBE, false},
		{"Uprobe", bpfman.ProgramTypeUprobe, pb.BpfmanProgramType_UPROBE, false},
		{"Uretprobe maps to UPROBE", bpfman.ProgramTypeUretprobe, pb.BpfmanProgramType_UPROBE, false},
		{"Fentry", bpfman.ProgramTypeFentry, pb.BpfmanProgramType_FENTRY, false},
		{"Fexit", bpfman.ProgramTypeFexit, pb.BpfmanProgramType_FEXIT, false},
		{"Unspecified returns error", bpfman.ProgramTypeUnspecified, 0, true},
		{"Unknown type returns error", bpfman.ProgramType(999), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := domainTypeToProto(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("domainTypeToProto(%v) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("domainTypeToProto(%v) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("domainTypeToProto(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestProtoTypeToDomain(t *testing.T) {
	tests := []struct {
		name      string
		input     pb.BpfmanProgramType
		want      bpfman.ProgramType
		wantError bool
	}{
		{"XDP", pb.BpfmanProgramType_XDP, bpfman.ProgramTypeXDP, false},
		{"TC", pb.BpfmanProgramType_TC, bpfman.ProgramTypeTC, false},
		{"TCX", pb.BpfmanProgramType_TCX, bpfman.ProgramTypeTCX, false},
		{"TRACEPOINT", pb.BpfmanProgramType_TRACEPOINT, bpfman.ProgramTypeTracepoint, false},
		{"KPROBE", pb.BpfmanProgramType_KPROBE, bpfman.ProgramTypeKprobe, false},
		{"UPROBE", pb.BpfmanProgramType_UPROBE, bpfman.ProgramTypeUprobe, false},
		{"FENTRY", pb.BpfmanProgramType_FENTRY, bpfman.ProgramTypeFentry, false},
		{"FEXIT", pb.BpfmanProgramType_FEXIT, bpfman.ProgramTypeFexit, false},
		{"Unknown proto type returns error", pb.BpfmanProgramType(999), bpfman.ProgramTypeUnspecified, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := protoTypeToDomain(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("protoTypeToDomain(%v) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("protoTypeToDomain(%v) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("protoTypeToDomain(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestValidateProgramType verifies validation of raw uint32 values from
// KernelProgramInfo.program_type in gRPC responses. This field stores
// domain type values directly (not proto enum values).
func TestValidateProgramType(t *testing.T) {
	tests := []struct {
		name      string
		input     uint32
		want      bpfman.ProgramType
		wantError bool
	}{
		{"Unspecified is valid", 0, bpfman.ProgramTypeUnspecified, false},
		{"XDP", uint32(bpfman.ProgramTypeXDP), bpfman.ProgramTypeXDP, false},
		{"TC", uint32(bpfman.ProgramTypeTC), bpfman.ProgramTypeTC, false},
		{"TCX", uint32(bpfman.ProgramTypeTCX), bpfman.ProgramTypeTCX, false},
		{"Tracepoint", uint32(bpfman.ProgramTypeTracepoint), bpfman.ProgramTypeTracepoint, false},
		{"Kprobe", uint32(bpfman.ProgramTypeKprobe), bpfman.ProgramTypeKprobe, false},
		{"Kretprobe", uint32(bpfman.ProgramTypeKretprobe), bpfman.ProgramTypeKretprobe, false},
		{"Uprobe", uint32(bpfman.ProgramTypeUprobe), bpfman.ProgramTypeUprobe, false},
		{"Uretprobe", uint32(bpfman.ProgramTypeUretprobe), bpfman.ProgramTypeUretprobe, false},
		{"Fentry", uint32(bpfman.ProgramTypeFentry), bpfman.ProgramTypeFentry, false},
		{"Fexit", uint32(bpfman.ProgramTypeFexit), bpfman.ProgramTypeFexit, false},
		{"Invalid type 100", 100, bpfman.ProgramTypeUnspecified, true},
		{"Invalid type 999", 999, bpfman.ProgramTypeUnspecified, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validateProgramType(tt.input)
			if tt.wantError {
				if err == nil {
					t.Errorf("validateProgramType(%v) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("validateProgramType(%v) unexpected error: %v", tt.input, err)
				return
			}
			if got != tt.want {
				t.Errorf("validateProgramType(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestProtoLoadResponseConversion_WithValidTypes verifies that proto Load
// responses are correctly converted to domain types for all valid program types.
func TestProtoLoadResponseConversion_WithValidTypes(t *testing.T) {
	tests := []struct {
		name         string
		programType  uint32
		expectedType bpfman.ProgramType
	}{
		{"XDP program", uint32(bpfman.ProgramTypeXDP), bpfman.ProgramTypeXDP},
		{"TC program", uint32(bpfman.ProgramTypeTC), bpfman.ProgramTypeTC},
		{"TCX program", uint32(bpfman.ProgramTypeTCX), bpfman.ProgramTypeTCX},
		{"Tracepoint program", uint32(bpfman.ProgramTypeTracepoint), bpfman.ProgramTypeTracepoint},
		{"Kprobe program", uint32(bpfman.ProgramTypeKprobe), bpfman.ProgramTypeKprobe},
		{"Kretprobe program", uint32(bpfman.ProgramTypeKretprobe), bpfman.ProgramTypeKretprobe},
		{"Uprobe program", uint32(bpfman.ProgramTypeUprobe), bpfman.ProgramTypeUprobe},
		{"Uretprobe program", uint32(bpfman.ProgramTypeUretprobe), bpfman.ProgramTypeUretprobe},
		{"Fentry program", uint32(bpfman.ProgramTypeFentry), bpfman.ProgramTypeFentry},
		{"Fexit program", uint32(bpfman.ProgramTypeFexit), bpfman.ProgramTypeFexit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate a proto response from the server
			resp := &pb.LoadResponseInfo{
				KernelInfo: &pb.KernelProgramInfo{
					Id:          123,
					Name:        "test_prog",
					ProgramType: tt.programType,
				},
				Info: &pb.ProgramInfo{
					Name:       "test_prog",
					MapPinPath: "/run/bpfman/fs",
				},
			}

			mp, err := protoLoadResponseToManagedProgram(resp)
			if err != nil {
				t.Fatalf("protoLoadResponseToManagedProgram() unexpected error: %v", err)
			}

			if mp.Managed.Type != tt.expectedType {
				t.Errorf("Managed.Type = %v, want %v", mp.Managed.Type, tt.expectedType)
			}
			if mp.Kernel.Type() != tt.expectedType {
				t.Errorf("Kernel.Type() = %v, want %v", mp.Kernel.Type(), tt.expectedType)
			}
		})
	}
}

// TestProtoLoadResponseConversion_WithInvalidType verifies that proto responses
// with invalid program types are rejected with an error.
func TestProtoLoadResponseConversion_WithInvalidType(t *testing.T) {
	resp := &pb.LoadResponseInfo{
		KernelInfo: &pb.KernelProgramInfo{
			Id:          123,
			Name:        "test_prog",
			ProgramType: 999, // Invalid type
		},
		Info: &pb.ProgramInfo{
			Name:       "test_prog",
			MapPinPath: "/run/bpfman/fs",
		},
	}

	_, err := protoLoadResponseToManagedProgram(resp)
	if err == nil {
		t.Fatal("protoLoadResponseToManagedProgram() expected error for invalid type, got nil")
	}
}

// TestProtoListResponseConversion_WithInvalidType verifies that List responses
// with invalid program types are rejected with an error.
func TestProtoListResponseConversion_WithInvalidType(t *testing.T) {
	resp := &pb.ListResponse{
		Results: []*pb.ListResponse_ListResult{
			{
				KernelInfo: &pb.KernelProgramInfo{
					Id:          123,
					Name:        "test_prog",
					ProgramType: 999, // Invalid type
				},
				Info: &pb.ProgramInfo{
					Name:       "test_prog",
					MapPinPath: "/run/bpfman/fs",
				},
			},
		},
	}

	_, err := protoListResponseToPrograms(resp)
	if err == nil {
		t.Fatal("protoListResponseToPrograms() expected error for invalid type, got nil")
	}
}

// TestProtoGetResponseConversion_WithInvalidType verifies that Get responses
// with invalid program types are rejected with an error.
func TestProtoGetResponseConversion_WithInvalidType(t *testing.T) {
	resp := &pb.GetResponse{
		KernelInfo: &pb.KernelProgramInfo{
			Id:          123,
			Name:        "test_prog",
			ProgramType: 999, // Invalid type
		},
		Info: &pb.ProgramInfo{
			Name:       "test_prog",
			MapPinPath: "/run/bpfman/fs",
		},
	}

	_, err := protoGetResponseToInfo(resp, 123)
	if err == nil {
		t.Fatal("protoGetResponseToInfo() expected error for invalid type, got nil")
	}
}
