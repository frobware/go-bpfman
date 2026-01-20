package domain

// PinnedProgram represents a BPF program pinned on the filesystem.
// Used for CLI output when scanning bpffs directories.
type PinnedProgram struct {
	ID         uint32 `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Tag        string `json:"tag,omitempty"`
	PinnedPath string `json:"pinned_path"`
	MapIDs     []uint32 `json:"map_ids,omitempty"`
}

// PinnedMap represents a BPF map pinned on the filesystem.
type PinnedMap struct {
	ID         uint32 `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
	PinnedPath string `json:"pinned_path"`
}

// PinDirContents holds all BPF objects found in a pin directory.
type PinDirContents struct {
	Programs []PinnedProgram `json:"programs,omitempty"`
	Maps     []PinnedMap     `json:"maps,omitempty"`
}

// LoadResult contains the result of loading a program via CLI.
type LoadResult struct {
	Program PinnedProgram `json:"program"`
	Maps    []PinnedMap   `json:"maps,omitempty"`
	PinDir  string        `json:"pin_dir"`
}
