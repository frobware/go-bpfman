package bpfman

// LoadSpec describes how to load a BPF program.
type LoadSpec struct {
	ObjectPath  string            `json:"object_path"`
	ProgramName string            `json:"program_name"`
	ProgramType ProgramType       `json:"program_type"`
	PinPath     string            `json:"pin_path"`
	GlobalData  map[string][]byte `json:"global_data,omitempty"`
	ImageSource *ImageSource      `json:"image_source,omitempty"`
}
