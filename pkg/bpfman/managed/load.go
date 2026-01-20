package managed

import "github.com/frobware/go-bpfman/pkg/bpfman"

// LoadSpec describes how to load a BPF program.
type LoadSpec struct {
	ObjectPath  string             `json:"object_path"`
	ProgramName string             `json:"program_name"`
	ProgramType bpfman.ProgramType `json:"program_type"`
	PinPath     string             `json:"pin_path"`
	GlobalData  map[string][]byte  `json:"global_data,omitempty"`
}

// Loaded is the result of successfully loading a program.
type Loaded struct {
	ID          uint32             `json:"id"`
	UUID        string             `json:"uuid,omitempty"`
	Name        string             `json:"name"`
	ProgramType bpfman.ProgramType `json:"type"`
	PinPath     string             `json:"pin_path"`
	PinDir      string             `json:"pin_dir,omitempty"`
	MapIDs      []uint32           `json:"map_ids,omitempty"`
}
