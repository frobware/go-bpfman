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

// ProgramRecord is what bpfman persists/manages about a program.
// Contains only durable identifiers we control - no kernel IDs.
// This is what we store - the kernel is the source of truth for runtime state.
// A ProgramRecord only exists in the store after successful load.
//
// Note: ProgramRecord is distinct from LoadSpec. LoadSpec describes how to load
// a program (validated input), while ProgramRecord describes a loaded program's
// state (stored output). They share some fields but serve different purposes.
type ProgramRecord struct {
	// Core identity - what was loaded (bpfman-level, not kernel)
	Name        string      `json:"name"`
	ProgramType ProgramType `json:"program_type"`
	ObjectPath  string      `json:"object_path,omitempty"`
	PinPath     string      `json:"pin_path"` // stable handle

	// Load-time configuration (stored for reference/potential reload)
	GlobalData    map[string][]byte `json:"global_data,omitempty"`
	ImageSource   *ImageSource      `json:"image_source,omitempty"`
	AttachFunc    string            `json:"attach_func,omitempty"`  // For fentry/fexit
	MapOwnerID    uint32            `json:"map_owner_id,omitempty"` // Program that owns shared maps (0 = self)
	MapPinPath    string            `json:"map_pin_path,omitempty"` // Directory where maps are pinned
	GPLCompatible bool              `json:"gpl_compatible"`         // Whether program has GPL-compatible license

	// Management metadata
	Tags         []string          `json:"tags,omitempty"`
	UserMetadata map[string]string `json:"user_metadata,omitempty"`
	Description  string            `json:"description,omitempty"`
	Owner        string            `json:"owner,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
	UpdatedAt    time.Time         `json:"updated_at"`
}

// Program is the canonical domain object - managed state + kernel state.
// Kernel.ID and Kernel.Name come from the kernel, not duplicated in Managed.
type Program struct {
	Managed ProgramRecord
	Kernel  *kernel.Program
}

// WithTag returns a new ProgramRecord with the tag added.
func (p ProgramRecord) WithTag(tag string) ProgramRecord {
	cp := p
	cp.Tags = append(slices.Clone(p.Tags), tag)
	cp.UserMetadata = cloneMap(p.UserMetadata)
	cp.GlobalData = cloneMap(p.GlobalData)
	return cp
}

// WithDescription returns a new ProgramRecord with the description set.
func (p ProgramRecord) WithDescription(desc string) ProgramRecord {
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
