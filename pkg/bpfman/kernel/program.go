package kernel

import "time"

// Program represents a BPF program loaded in the kernel.
// This is read from the kernel - we don't create these, we observe them.
type Program struct {
	ID          uint32    `json:"id"`
	Name        string    `json:"name"`
	ProgramType string    `json:"program_type"`
	Tag         string    `json:"tag,omitempty"`
	LoadedAt    time.Time `json:"loaded_at"`
	UID         uint32    `json:"uid"`
	MapIDs      []uint32  `json:"map_ids,omitempty"`
	BTFId       uint32    `json:"btf_id,omitempty"`
	JitedSize   uint32    `json:"jited_size,omitempty"`
	XlatedSize  uint32    `json:"xlated_size,omitempty"`
}

// PinnedProgram represents a BPF program pinned on the filesystem.
// Used for CLI output when scanning bpffs directories.
type PinnedProgram struct {
	ID         uint32   `json:"id"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Tag        string   `json:"tag,omitempty"`
	PinnedPath string   `json:"pinned_path"`
	MapIDs     []uint32 `json:"map_ids,omitempty"`
}
