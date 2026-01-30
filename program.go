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

	"github.com/frobware/go-bpfman/kernel"
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

// ProgramSpec is what bpfman intends to manage (DB-backed).
// This is the "desired state" - what was loaded.
// KernelID is the DB primary key and user-facing identity.
//
// Note: ProgramSpec is distinct from LoadSpec. LoadSpec describes how to load
// a program (validated input), while ProgramSpec describes a loaded program's
// state (stored output). They share some fields but serve different purposes.
type ProgramSpec struct {
	// Identity - KernelID is the DB primary key and user-facing ID
	KernelID    uint32      `json:"kernel_id"`
	Name        string      `json:"name"` // human-readable label (not identity)
	ProgramType ProgramType `json:"program_type"`
	ObjectPath  string      `json:"object_path,omitempty"`
	PinPath     string      `json:"pin_path"`               // stable handle
	MapPinPath  string      `json:"map_pin_path,omitempty"` // directory where maps are pinned

	// Load-time configuration (stored for reference/potential reload)
	GlobalData    map[string][]byte `json:"global_data,omitempty"`
	ImageSource   *ImageSource      `json:"image_source,omitempty"`
	AttachFunc    string            `json:"attach_func,omitempty"`  // For fentry/fexit
	MapOwnerID    *uint32           `json:"map_owner_id,omitempty"` // nil means self/no owner (matches DB NULL)
	GPLCompatible bool              `json:"gpl_compatible"`         // Whether program has GPL-compatible license

	// Management metadata
	Tags         []string          `json:"tags,omitempty"`
	UserMetadata map[string]string `json:"user_metadata,omitempty"`
	Description  string            `json:"description,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// ProgramStatus is observed state (kernel + filesystem).
// This is "what actually exists right now".
type ProgramStatus struct {
	Kernel      *kernel.Program // nil if not in kernel
	KernelSeen  bool            // true if kernel enumeration succeeded
	PinPresent  bool            // true if Spec.PinPath exists on filesystem
	MapsPresent bool            // true if Spec.MapPinPath dir exists
}

// Program is the canonical domain object combining spec and status.
// Spec comes from the store (what bpfman manages).
// Status comes from observation (kernel enumeration + filesystem checks).
type Program struct {
	Spec   ProgramSpec
	Status ProgramStatus
}

// ProgramRecord is an alias for ProgramSpec for backwards compatibility.
// Deprecated: Use ProgramSpec instead.
type ProgramRecord = ProgramSpec

// WithTag returns a new ProgramSpec with the tag added.
func (p ProgramSpec) WithTag(tag string) ProgramSpec {
	cp := p
	cp.Tags = append(slices.Clone(p.Tags), tag)
	cp.UserMetadata = cloneMap(p.UserMetadata)
	cp.GlobalData = cloneMap(p.GlobalData)
	return cp
}

// WithDescription returns a new ProgramSpec with the description set.
func (p ProgramSpec) WithDescription(desc string) ProgramSpec {
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

// LoadedProgramInfo holds transient information about a just-loaded program.
// This is returned by the kernel Load operation and contains pin paths
// that are used to construct the ProgramRecord for persistence.
type LoadedProgramInfo struct {
	Name       string      `json:"name"`
	Type       ProgramType `json:"type"`
	ObjectPath string      `json:"object_path,omitempty"`
	PinPath    string      `json:"pin_path"`
	PinDir     string      `json:"pin_dir,omitempty"`
}

// ManagedProgram is the result of loading a BPF program.
// It combines bpfman-managed state with kernel-reported info.
type ManagedProgram struct {
	Managed *LoadedProgramInfo
	Kernel  *kernel.Program
}

// ExtractGPLCompatible extracts GPL compatibility from a kernel.Program.
// Returns false if the program is nil or GPLCompatible is not set.
func ExtractGPLCompatible(prog *kernel.Program) bool {
	if prog == nil {
		return false
	}
	return prog.GPLCompatible
}

// MarshalJSON implements json.Marshaler for ManagedProgram.
// The kernel.Program is serialized directly as it has JSON tags.
func (p ManagedProgram) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Managed *LoadedProgramInfo `json:"managed"`
		Kernel  *kernel.Program    `json:"kernel"`
	}{
		Managed: p.Managed,
		Kernel:  p.Kernel,
	})
}
