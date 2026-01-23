package kernel

// Map represents a BPF map in the kernel.
type Map struct {
	ID         uint32  `json:"id"`
	Name       string  `json:"name"`
	MapType    string  `json:"map_type"`
	KeySize    uint32  `json:"key_size"`
	ValueSize  uint32  `json:"value_size"`
	MaxEntries uint32  `json:"max_entries"`
	Flags      uint32  `json:"flags,omitempty"`
	BTFId      uint32  `json:"btf_id,omitempty"`
	Memlock    *uint64 `json:"memlock,omitempty"`
	Frozen     bool    `json:"frozen,omitempty"`
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
