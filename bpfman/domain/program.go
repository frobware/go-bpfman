package domain

import (
	"slices"
	"time"
)

// ProgramMetadata contains metadata for programs managed by bpfman.
// This is what we store - the kernel is the source of truth for runtime state.
type ProgramMetadata struct {
	// Original load specification
	LoadSpec LoadSpec
	// UUID for gRPC API identification
	UUID string
	// User-defined tags for categorisation
	Tags []string
	// User-supplied key-value metadata
	UserMetadata map[string]string
	// Human-readable description
	Description Option[string]
	// User or system that loaded this program
	Owner string
	// When bpfman loaded this program
	CreatedAt time.Time
}

// WithTag returns a new ProgramMetadata with the tag added.
func (p ProgramMetadata) WithTag(tag string) ProgramMetadata {
	return ProgramMetadata{
		LoadSpec:     p.LoadSpec,
		UUID:         p.UUID,
		Tags:         append(slices.Clone(p.Tags), tag),
		UserMetadata: cloneMap(p.UserMetadata),
		Description:  p.Description,
		Owner:        p.Owner,
		CreatedAt:    p.CreatedAt,
	}
}

// WithDescription returns a new ProgramMetadata with the description set.
func (p ProgramMetadata) WithDescription(desc string) ProgramMetadata {
	return ProgramMetadata{
		LoadSpec:     p.LoadSpec,
		UUID:         p.UUID,
		Tags:         slices.Clone(p.Tags),
		UserMetadata: cloneMap(p.UserMetadata),
		Description:  Some(desc),
		Owner:        p.Owner,
		CreatedAt:    p.CreatedAt,
	}
}

func cloneMap[K comparable, V any](m map[K]V) map[K]V {
	if m == nil {
		return nil
	}
	result := make(map[K]V, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// LoadSpec describes how to load a BPF program.
type LoadSpec struct {
	// Path to the BPF object file
	ObjectPath string
	// Name of the program within the object file
	ProgramName string
	// Type of program
	ProgramType ProgramType
	// Directory where maps and programs are pinned
	PinPath string
	// Global data to set before loading
	GlobalData map[string][]byte
}

// KernelProgram represents a BPF program loaded in the kernel.
// This is read from the kernel - we don't create these, we observe them.
type KernelProgram struct {
	ID          uint32
	Name        string
	ProgramType string
	Tag         string // SHA1 hash of bytecode
	LoadedAt    time.Time
	UID         uint32
	MapIDs      []uint32
	BTFId       uint32
	JitedSize   uint32
	XlatedSize  uint32
}

// LoadedProgram is the result of successfully loading a program.
type LoadedProgram struct {
	ID          uint32
	Name        string
	ProgramType ProgramType
	PinPath     string
	MapIDs      []uint32
}
