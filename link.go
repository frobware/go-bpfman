package bpfman

import (
	"encoding/json"
	"time"

	"github.com/frobware/go-bpfman/dispatcher"
)

// AttachType specifies the type of BPF program attachment.
type AttachType string

const (
	AttachTracepoint AttachType = "tracepoint"
	AttachKprobe     AttachType = "kprobe"
	AttachKretprobe  AttachType = "kretprobe"
	AttachXDP        AttachType = "xdp"
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
	Target   string `json:"target"`
	FnName   string `json:"fn_name,omitempty"`
	Offset   uint64 `json:"offset,omitempty"`
	PID      int32  `json:"pid,omitempty"`
	Retprobe bool   `json:"retprobe,omitempty"`
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

// LinkInfo is the concrete implementation of ManagedLinkInfo.
// It holds what bpfman tracks about a link.
type LinkInfo struct {
	kernelLinkID    uint32
	kernelProgramID uint32
	linkType        LinkType
	pinPath         string
	createdAt       time.Time
	details         LinkDetails
}

// NewLinkInfo creates a new LinkInfo.
func NewLinkInfo(kernelLinkID, kernelProgramID uint32, linkType LinkType, pinPath string, createdAt time.Time, details LinkDetails) *LinkInfo {
	return &LinkInfo{
		kernelLinkID:    kernelLinkID,
		kernelProgramID: kernelProgramID,
		linkType:        linkType,
		pinPath:         pinPath,
		createdAt:       createdAt,
		details:         details,
	}
}

// NewLinkInfoFromSummary creates a LinkInfo from a LinkSummary and optional details.
func NewLinkInfoFromSummary(summary LinkSummary, details LinkDetails) *LinkInfo {
	return &LinkInfo{
		kernelLinkID:    summary.KernelLinkID,
		kernelProgramID: summary.KernelProgramID,
		linkType:        summary.LinkType,
		pinPath:         summary.PinPath,
		createdAt:       summary.CreatedAt,
		details:         details,
	}
}

func (l *LinkInfo) KernelLinkID() uint32    { return l.kernelLinkID }
func (l *LinkInfo) KernelProgramID() uint32 { return l.kernelProgramID }
func (l *LinkInfo) LinkType() string        { return string(l.linkType) }
func (l *LinkInfo) PinPath() string         { return l.pinPath }
func (l *LinkInfo) CreatedAt() time.Time    { return l.createdAt }
func (l *LinkInfo) Details() any            { return l.details }

// Verify interface compliance at compile time.
var _ ManagedLinkInfo = (*LinkInfo)(nil)

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

// DispatcherState represents the persistent state of a dispatcher.
// A dispatcher manages multi-program chaining for XDP or TC attachments.
type DispatcherState struct {
	// Type is the dispatcher type (xdp, tc-ingress, tc-egress).
	Type dispatcher.DispatcherType `json:"type"`

	// Nsid is the network namespace inode number.
	// This uniquely identifies the network namespace.
	Nsid uint64 `json:"nsid"`

	// Ifindex is the network interface index.
	Ifindex uint32 `json:"ifindex"`

	// Revision is the current dispatcher revision.
	// Incremented on each atomic update, wraps at MaxUint32.
	Revision uint32 `json:"revision"`

	// KernelID is the kernel program ID of the dispatcher.
	KernelID uint32 `json:"kernel_id"`

	// LinkID is the kernel link ID (XDP link for XDP dispatchers).
	LinkID uint32 `json:"link_id"`

	// LinkPinPath is the stable path for the dispatcher link.
	// This path remains constant across revisions.
	LinkPinPath string `json:"link_pin_path"`

	// ProgPinPath is the path for the dispatcher program.
	// This changes with each revision.
	ProgPinPath string `json:"prog_pin_path"`

	// NumExtensions is the number of extension programs attached.
	NumExtensions uint8 `json:"num_extensions"`
}
