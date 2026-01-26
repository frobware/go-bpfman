package bpfman

import (
	"encoding/json"
	"time"
)

// AttachType specifies the type of BPF program attachment.
type AttachType string

const (
	AttachTracepoint AttachType = "tracepoint"
	AttachKprobe     AttachType = "kprobe"
	AttachKretprobe  AttachType = "kretprobe"
	AttachUprobe     AttachType = "uprobe"
	AttachUretprobe  AttachType = "uretprobe"
	AttachFentry     AttachType = "fentry"
	AttachFexit      AttachType = "fexit"
	AttachXDP        AttachType = "xdp"
	AttachTC         AttachType = "tc"
	AttachTCX        AttachType = "tcx"
)

// AttachInfo describes how to attach a BPF program.
type AttachInfo struct {
	Type            AttachType `json:"type"`
	TracepointGroup string     `json:"tracepoint_group,omitempty"`
	TracepointName  string     `json:"tracepoint_name,omitempty"`
	KprobeFunc      string     `json:"kprobe_func,omitempty"`
	LinkPinPath     string     `json:"link_pin_path,omitempty"`
}

// AttachedLink is the result of successfully attaching a program.
type AttachedLink struct {
	ID      uint32     `json:"id,omitempty"`
	PinPath string     `json:"pin_path,omitempty"`
	Type    AttachType `json:"type"`
}

// LinkType represents the type of BPF link/attachment.
type LinkType string

const (
	LinkTypeTracepoint LinkType = "tracepoint"
	LinkTypeKprobe     LinkType = "kprobe"
	LinkTypeKretprobe  LinkType = "kretprobe"
	LinkTypeUprobe     LinkType = "uprobe"
	LinkTypeUretprobe  LinkType = "uretprobe"
	LinkTypeFentry     LinkType = "fentry"
	LinkTypeFexit      LinkType = "fexit"
	LinkTypeXDP        LinkType = "xdp"
	LinkTypeTC         LinkType = "tc"
	LinkTypeTCX        LinkType = "tcx"
)

// ParseLinkType parses a string into a LinkType.
// Returns the LinkType and true if valid, or empty string and false if invalid.
func ParseLinkType(s string) (LinkType, bool) {
	switch s {
	case "tracepoint":
		return LinkTypeTracepoint, true
	case "kprobe":
		return LinkTypeKprobe, true
	case "kretprobe":
		return LinkTypeKretprobe, true
	case "uprobe":
		return LinkTypeUprobe, true
	case "uretprobe":
		return LinkTypeUretprobe, true
	case "fentry":
		return LinkTypeFentry, true
	case "fexit":
		return LinkTypeFexit, true
	case "xdp":
		return LinkTypeXDP, true
	case "tc":
		return LinkTypeTC, true
	case "tcx":
		return LinkTypeTCX, true
	default:
		return "", false
	}
}

// ToAttachType converts LinkType to AttachType for backward compatibility.
func (t LinkType) ToAttachType() AttachType {
	switch t {
	case LinkTypeTracepoint:
		return AttachTracepoint
	case LinkTypeKprobe:
		return AttachKprobe
	case LinkTypeKretprobe:
		return AttachKretprobe
	default:
		return AttachType(t)
	}
}

// TCXAttachOrder specifies where to insert a TCX program in the chain.
// Programs are ordered by priority, with lower priority values running first.
// This type maps to cilium/ebpf's link.Anchor for kernel attachment.
type TCXAttachOrder struct {
	// First attaches at the head of the chain (runs before all others).
	First bool
	// Last attaches at the tail of the chain (runs after all others).
	Last bool
	// BeforeProgID attaches before the program with this kernel ID.
	// Zero means not set.
	BeforeProgID uint32
	// AfterProgID attaches after the program with this kernel ID.
	// Zero means not set.
	AfterProgID uint32
}

// TCXAttachFirst returns an order that attaches at the head of the chain.
func TCXAttachFirst() TCXAttachOrder {
	return TCXAttachOrder{First: true}
}

// TCXAttachLast returns an order that attaches at the tail of the chain.
func TCXAttachLast() TCXAttachOrder {
	return TCXAttachOrder{Last: true}
}

// TCXAttachBefore returns an order that attaches before the given program.
func TCXAttachBefore(progID uint32) TCXAttachOrder {
	return TCXAttachOrder{BeforeProgID: progID}
}

// TCXAttachAfter returns an order that attaches after the given program.
func TCXAttachAfter(progID uint32) TCXAttachOrder {
	return TCXAttachOrder{AfterProgID: progID}
}

// LinkSummary contains the common fields from link_registry.
// This is the primary polymorphic type for links - most operations
// only need these fields without type-specific details.
// KernelLinkID is the primary identifier (kernel-assigned link ID).
type LinkSummary struct {
	KernelLinkID    uint32    `json:"kernel_link_id"`
	LinkType        LinkType  `json:"link_type"`
	KernelProgramID uint32    `json:"kernel_program_id"`
	PinPath         string    `json:"pin_path,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// LinkDetails is a marker interface for type-specific link details.
// Use type assertion or type switch to access the concrete type.
type LinkDetails interface {
	linkDetails()
}

// TracepointDetails contains fields specific to tracepoint attachments.
type TracepointDetails struct {
	Group string `json:"group"`
	Name  string `json:"name"`
}

func (TracepointDetails) linkDetails() {}

// KprobeDetails contains fields specific to kprobe/kretprobe attachments.
type KprobeDetails struct {
	FnName   string `json:"fn_name"`
	Offset   uint64 `json:"offset,omitempty"`
	Retprobe bool   `json:"retprobe,omitempty"`
}

func (KprobeDetails) linkDetails() {}

// UprobeDetails contains fields specific to uprobe/uretprobe attachments.
type UprobeDetails struct {
	Target       string `json:"target"`
	FnName       string `json:"fn_name,omitempty"`
	Offset       uint64 `json:"offset,omitempty"`
	PID          int32  `json:"pid,omitempty"`
	Retprobe     bool   `json:"retprobe,omitempty"`
	ContainerPid int32  `json:"container_pid,omitempty"`
}

func (UprobeDetails) linkDetails() {}

// FentryDetails contains fields specific to fentry attachments.
type FentryDetails struct {
	FnName string `json:"fn_name"`
}

func (FentryDetails) linkDetails() {}

// FexitDetails contains fields specific to fexit attachments.
type FexitDetails struct {
	FnName string `json:"fn_name"`
}

func (FexitDetails) linkDetails() {}

// XDPDetails contains fields specific to XDP attachments.
type XDPDetails struct {
	Interface    string  `json:"interface"`
	Ifindex      uint32  `json:"ifindex"`
	Priority     int32   `json:"priority"`
	Position     int32   `json:"position"`
	ProceedOn    []int32 `json:"proceed_on"`
	Netns        string  `json:"netns,omitempty"`
	Nsid         uint64  `json:"nsid"`
	DispatcherID uint32  `json:"dispatcher_id"`
	Revision     uint32  `json:"revision"`
}

func (XDPDetails) linkDetails() {}

// TCDetails contains fields specific to TC attachments.
type TCDetails struct {
	Interface    string  `json:"interface"`
	Ifindex      uint32  `json:"ifindex"`
	Direction    string  `json:"direction"` // "ingress" or "egress"
	Priority     int32   `json:"priority"`
	Position     int32   `json:"position"`
	ProceedOn    []int32 `json:"proceed_on"`
	Netns        string  `json:"netns,omitempty"`
	Nsid         uint64  `json:"nsid"`
	DispatcherID uint32  `json:"dispatcher_id"`
	Revision     uint32  `json:"revision"`
}

func (TCDetails) linkDetails() {}

// TCXDetails contains fields specific to TCX attachments.
type TCXDetails struct {
	Interface string `json:"interface"`
	Ifindex   uint32 `json:"ifindex"`
	Direction string `json:"direction"` // "ingress" or "egress"
	Priority  int32  `json:"priority"`
	Netns     string `json:"netns,omitempty"`
	Nsid      uint64 `json:"nsid,omitempty"`
}

func (TCXDetails) linkDetails() {}

// TCXLinkInfo combines link summary with TCX-specific details.
// Used for computing attach order based on priority.
type TCXLinkInfo struct {
	KernelLinkID    uint32 `json:"kernel_link_id"`
	KernelProgramID uint32 `json:"kernel_program_id"`
	Priority        int32  `json:"priority"`
}

// LinkInfo holds what bpfman tracks about a link.
type LinkInfo struct {
	KernelLinkID    uint32      `json:"kernel_link_id"`
	KernelProgramID uint32      `json:"kernel_program_id"`
	Type            LinkType    `json:"link_type"`
	PinPath         string      `json:"pin_path,omitempty"`
	CreatedAt       time.Time   `json:"created_at,omitempty"`
	Details         LinkDetails `json:"details,omitempty"`
}

// ManagedLink combines bpfman-managed state with kernel-reported info for a link.
type ManagedLink struct {
	Managed *LinkInfo
	Kernel  KernelLinkInfo
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
		Managed *LinkInfo      `json:"managed"`
		Kernel  kernelLinkView `json:"kernel"`
	}{
		Managed: l.Managed,
		Kernel:  kernelLinkView{l.Kernel},
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
