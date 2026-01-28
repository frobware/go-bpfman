// Package bpfman provides types and interfaces for BPF program management.
// This is the root package containing shared domain types used across
// the client, manager, and server components.
package bpfman

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"time"
)

// ProgramType represents the type of BPF program.
type ProgramType uint32

const (
	ProgramTypeUnspecified ProgramType = iota
	ProgramTypeXDP
	ProgramTypeTC
	ProgramTypeTCX
	ProgramTypeTracepoint
	ProgramTypeKprobe
	ProgramTypeKretprobe
	ProgramTypeUprobe
	ProgramTypeUretprobe
	ProgramTypeFentry
	ProgramTypeFexit
)

// String returns the string representation of the program type.
func (t ProgramType) String() string {
	switch t {
	case ProgramTypeXDP:
		return "xdp"
	case ProgramTypeTC:
		return "tc"
	case ProgramTypeTCX:
		return "tcx"
	case ProgramTypeTracepoint:
		return "tracepoint"
	case ProgramTypeKprobe:
		return "kprobe"
	case ProgramTypeKretprobe:
		return "kretprobe"
	case ProgramTypeUprobe:
		return "uprobe"
	case ProgramTypeUretprobe:
		return "uretprobe"
	case ProgramTypeFentry:
		return "fentry"
	case ProgramTypeFexit:
		return "fexit"
	default:
		return "unspecified"
	}
}

// MarshalText implements encoding.TextMarshaler so ProgramType
// serialises as its string name in JSON.
func (t ProgramType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler so ProgramType
// can be parsed from its string name in JSON.
func (t *ProgramType) UnmarshalText(text []byte) error {
	parsed, ok := ParseProgramType(string(text))
	if !ok {
		return fmt.Errorf("invalid program type: %q", string(text))
	}
	*t = parsed
	return nil
}

// ParseProgramType parses a string into a ProgramType.
// Returns the program type and true if valid, or ProgramTypeUnspecified and false if not.
func ParseProgramType(s string) (ProgramType, bool) {
	switch s {
	case "xdp":
		return ProgramTypeXDP, true
	case "tc":
		return ProgramTypeTC, true
	case "tcx":
		return ProgramTypeTCX, true
	case "tracepoint":
		return ProgramTypeTracepoint, true
	case "kprobe":
		return ProgramTypeKprobe, true
	case "kretprobe":
		return ProgramTypeKretprobe, true
	case "uprobe":
		return ProgramTypeUprobe, true
	case "uretprobe":
		return ProgramTypeUretprobe, true
	case "fentry":
		return ProgramTypeFentry, true
	case "fexit":
		return ProgramTypeFexit, true
	default:
		return ProgramTypeUnspecified, false
	}
}

// Program contains metadata for programs managed by bpfman.
// This is what we store - the kernel is the source of truth for runtime state.
// A Program only exists in the store after successful load.
//
// Note: Program is distinct from LoadSpec. LoadSpec describes how to load a
// program (validated input), while Program describes a loaded program's state
// (stored output). They share some fields but serve different purposes.
type Program struct {
	// Core identity - what was loaded
	ProgramName string      `json:"program_name"`
	ProgramType ProgramType `json:"program_type"`
	ObjectPath  string      `json:"object_path,omitempty"`
	PinPath     string      `json:"pin_path"`

	// Load-time configuration (stored for reference/potential reload)
	GlobalData  map[string][]byte `json:"global_data,omitempty"`
	ImageSource *ImageSource      `json:"image_source,omitempty"`
	AttachFunc  string            `json:"attach_func,omitempty"`  // For fentry/fexit
	MapOwnerID  uint32            `json:"map_owner_id,omitempty"` // Program that owns shared maps (0 = self)
	MapPinPath  string            `json:"map_pin_path,omitempty"` // Directory where maps are pinned

	// Management metadata
	Tags         []string          `json:"tags,omitempty"`
	UserMetadata map[string]string `json:"user_metadata,omitempty"`
	Description  string            `json:"description,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// WithTag returns a new Program with the tag added.
func (p Program) WithTag(tag string) Program {
	cp := p
	cp.Tags = append(slices.Clone(p.Tags), tag)
	cp.UserMetadata = cloneMap(p.UserMetadata)
	cp.GlobalData = cloneMap(p.GlobalData)
	return cp
}

// WithDescription returns a new Program with the description set.
func (p Program) WithDescription(desc string) Program {
	cp := p
	cp.Description = desc
	cp.Tags = slices.Clone(p.Tags)
	cp.UserMetadata = cloneMap(p.UserMetadata)
	cp.GlobalData = cloneMap(p.GlobalData)
	return cp
}

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return nil
	}
	result := make(map[K]V, len(m))
	maps.Copy(result, m)
	return result
}

// ProgramInfo holds what bpfman tracks about a loaded program.
type ProgramInfo struct {
	Name       string      `json:"name"`
	Type       ProgramType `json:"type"`
	ObjectPath string      `json:"object_path,omitempty"`
	PinPath    string      `json:"pin_path"`
	PinDir     string      `json:"pin_dir,omitempty"`
}

// ManagedProgram is the result of loading a BPF program.
// It combines bpfman-managed state with kernel-reported info.
type ManagedProgram struct {
	Managed *ProgramInfo
	Kernel  KernelProgramInfo
}

// KernelProgramInfo describes what the kernel reports about a loaded program.
type KernelProgramInfo interface {
	ID() uint32
	Name() string
	Type() ProgramType
	Tag() string
	MapIDs() []uint32
	BTFId() uint32
	BytesXlated() uint32
	BytesJited() uint32
	VerifiedInstructions() uint32
	LoadedAt() time.Time
	MemoryLocked() uint64
	GPLCompatible() bool
}

// MarshalJSON implements json.Marshaler for ManagedProgram.
func (p ManagedProgram) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Managed *ProgramInfo      `json:"managed"`
		Kernel  kernelProgramView `json:"kernel"`
	}{
		Managed: p.Managed,
		Kernel:  kernelProgramView{p.Kernel},
	})
}

// kernelProgramView is a JSON-serializable view of KernelProgramInfo.
type kernelProgramView struct {
	info KernelProgramInfo
}

func (v kernelProgramView) MarshalJSON() ([]byte, error) {
	var loadedAt string
	if !v.info.LoadedAt().IsZero() {
		loadedAt = v.info.LoadedAt().Format(time.RFC3339)
	}

	return json.Marshal(struct {
		ID                   uint32      `json:"id"`
		Name                 string      `json:"name"`
		Type                 ProgramType `json:"type"`
		Tag                  string      `json:"tag,omitempty"`
		GPLCompatible        bool        `json:"gpl_compatible"`
		LoadedAt             string      `json:"loaded_at,omitempty"`
		MapIDs               []uint32    `json:"map_ids,omitempty"`
		BTFId                uint32      `json:"btf_id,omitempty"`
		BytesXlated          uint32      `json:"bytes_xlated,omitempty"`
		BytesJited           uint32      `json:"bytes_jited,omitempty"`
		MemoryLocked         uint64      `json:"memory_locked,omitempty"`
		VerifiedInstructions uint32      `json:"verified_insns,omitempty"`
	}{
		ID:                   v.info.ID(),
		Name:                 v.info.Name(),
		Type:                 v.info.Type(),
		Tag:                  v.info.Tag(),
		GPLCompatible:        v.info.GPLCompatible(),
		LoadedAt:             loadedAt,
		MapIDs:               v.info.MapIDs(),
		BTFId:                v.info.BTFId(),
		BytesXlated:          v.info.BytesXlated(),
		BytesJited:           v.info.BytesJited(),
		MemoryLocked:         v.info.MemoryLocked(),
		VerifiedInstructions: v.info.VerifiedInstructions(),
	})
}
