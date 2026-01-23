package kernel

// Link represents a BPF link in the kernel.
type Link struct {
	ID          uint32 `json:"id"`
	ProgramID   uint32 `json:"program_id"`
	LinkType    string `json:"link_type"`
	AttachType  string `json:"attach_type,omitempty"`
	TargetIface string `json:"target_iface,omitempty"`
	TargetObjID uint32 `json:"target_obj_id,omitempty"`
	TargetBTFId uint32 `json:"target_btf_id,omitempty"`
}
