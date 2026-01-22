package bpfman

import (
	"encoding/json"
	"time"
)

// ManagedProgram is the result of loading a BPF program.
// It combines bpfman-managed state with kernel-reported info.
type ManagedProgram struct {
	Managed ManagedProgramInfo
	Kernel  KernelProgramInfo
}

// ManagedProgramInfo describes what bpfman tracks about a loaded program.
type ManagedProgramInfo interface {
	Name() string
	ProgramType() ProgramType
	PinPath() string
	PinDir() string
	ObjectPath() string
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
		Managed managedProgramView `json:"managed"`
		Kernel  kernelProgramView  `json:"kernel"`
	}{
		Managed: managedProgramView{p.Managed},
		Kernel:  kernelProgramView{p.Kernel},
	})
}

// managedProgramView is a JSON-serializable view of ManagedProgramInfo.
type managedProgramView struct {
	info ManagedProgramInfo
}

func (v managedProgramView) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name        string      `json:"name"`
		ProgramType ProgramType `json:"type"`
		ObjectPath  string      `json:"object_path,omitempty"`
		PinPath     string      `json:"pin_path"`
		PinDir      string      `json:"pin_dir,omitempty"`
	}{
		Name:        v.info.Name(),
		ProgramType: v.info.ProgramType(),
		ObjectPath:  v.info.ObjectPath(),
		PinPath:     v.info.PinPath(),
		PinDir:      v.info.PinDir(),
	})
}

// kernelProgramView is a JSON-serializable view of KernelProgramInfo.
type kernelProgramView struct {
	info KernelProgramInfo
}

func (v kernelProgramView) MarshalJSON() ([]byte, error) {
	// Format LoadedAt as RFC3339 if non-zero
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
