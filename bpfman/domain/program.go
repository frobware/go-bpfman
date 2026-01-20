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
	// User-defined tags for categorisation
	Tags []string
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
		LoadSpec:    p.LoadSpec,
		Tags:        append(slices.Clone(p.Tags), tag),
		Description: p.Description,
		Owner:       p.Owner,
		CreatedAt:   p.CreatedAt,
	}
}

// WithDescription returns a new ProgramMetadata with the description set.
func (p ProgramMetadata) WithDescription(desc string) ProgramMetadata {
	return ProgramMetadata{
		LoadSpec:    p.LoadSpec,
		Tags:        slices.Clone(p.Tags),
		Description: Some(desc),
		Owner:       p.Owner,
		CreatedAt:   p.CreatedAt,
	}
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
