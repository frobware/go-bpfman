package bpfman

import (
	"encoding/json"
	"time"
)

// ManagedLink combines bpfman-managed state with kernel-reported info for a link.
type ManagedLink struct {
	Managed ManagedLinkInfo
	Kernel  KernelLinkInfo
}

// ManagedLinkInfo describes what bpfman tracks about a link.
type ManagedLinkInfo interface {
	KernelLinkID() uint32
	KernelProgramID() uint32
	LinkType() string
	PinPath() string
	CreatedAt() time.Time
	Details() any // Type-specific details (TracepointDetails, KprobeDetails, etc.)
}

// KernelLinkInfo describes what the kernel reports about a link.
type KernelLinkInfo interface {
	ID() uint32
	ProgramID() uint32
	LinkType() string
	AttachType() string
	TargetObjID() uint32
	TargetBTFId() uint32
}

// MarshalJSON implements json.Marshaler for ManagedLink.
func (l ManagedLink) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Managed managedLinkView `json:"managed"`
		Kernel  kernelLinkView  `json:"kernel"`
	}{
		Managed: managedLinkView{l.Managed},
		Kernel:  kernelLinkView{l.Kernel},
	})
}

// managedLinkView is a JSON-serializable view of ManagedLinkInfo.
type managedLinkView struct {
	info ManagedLinkInfo
}

func (v managedLinkView) MarshalJSON() ([]byte, error) {
	var createdAt string
	if !v.info.CreatedAt().IsZero() {
		createdAt = v.info.CreatedAt().Format(time.RFC3339)
	}

	return json.Marshal(struct {
		KernelLinkID    uint32 `json:"kernel_link_id"`
		KernelProgramID uint32 `json:"kernel_program_id"`
		LinkType        string `json:"link_type"`
		PinPath         string `json:"pin_path,omitempty"`
		CreatedAt       string `json:"created_at,omitempty"`
		Details         any    `json:"details,omitempty"`
	}{
		KernelLinkID:    v.info.KernelLinkID(),
		KernelProgramID: v.info.KernelProgramID(),
		LinkType:        v.info.LinkType(),
		PinPath:         v.info.PinPath(),
		CreatedAt:       createdAt,
		Details:         v.info.Details(),
	})
}

// kernelLinkView is a JSON-serializable view of KernelLinkInfo.
type kernelLinkView struct {
	info KernelLinkInfo
}

func (v kernelLinkView) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ID          uint32 `json:"id"`
		ProgramID   uint32 `json:"program_id"`
		LinkType    string `json:"link_type"`
		AttachType  string `json:"attach_type,omitempty"`
		TargetObjID uint32 `json:"target_obj_id,omitempty"`
		TargetBTFId uint32 `json:"target_btf_id,omitempty"`
	}{
		ID:          v.info.ID(),
		ProgramID:   v.info.ProgramID(),
		LinkType:    v.info.LinkType(),
		AttachType:  v.info.AttachType(),
		TargetObjID: v.info.TargetObjID(),
		TargetBTFId: v.info.TargetBTFId(),
	})
}
