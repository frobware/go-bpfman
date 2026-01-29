package bpfman

import (
	"encoding/json"
	"math"
	"time"

	"github.com/frobware/go-bpfman/kernel"
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

// SyntheticLinkIDBase is the base value for synthetic link IDs.
// Synthetic IDs are generated in the range 0x80000000-0xFFFFFFFF for
// perf_event-based links (e.g., container uprobes) that lack kernel link IDs.
// Real kernel link IDs are small sequential numbers, so this range avoids
// collision. GC should skip links with synthetic IDs since they can't be
// enumerated via the kernel's link iterator.
const SyntheticLinkIDBase = 0x80000000

// IsSyntheticLinkID returns true if the link ID is synthetic (not from kernel).
// Synthetic IDs are used for perf_event-based links that cannot be pinned
// and don't have real kernel link IDs.
func IsSyntheticLinkID(id uint32) bool {
	return id >= SyntheticLinkIDBase
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

// LinkDetails is a sealed interface for type-specific link details.
// Use type assertion or type switch to access the concrete type.
// The interface is sealed via the unexported linkDetails() method -
// only types in this package can implement it.
type LinkDetails interface {
	linkDetails()   // unexported - only our types can implement
	Kind() LinkKind // returns the kind for this detail type
}

// TracepointDetails contains fields specific to tracepoint attachments.
type TracepointDetails struct {
	Group string `json:"group"`
	Name  string `json:"name"`
}

func (TracepointDetails) linkDetails()   {}
func (TracepointDetails) Kind() LinkKind { return LinkKindTracepoint }

// KprobeDetails contains fields specific to kprobe/kretprobe attachments.
type KprobeDetails struct {
	FnName   string `json:"fn_name"`
	Offset   uint64 `json:"offset,omitempty"`
	Retprobe bool   `json:"retprobe,omitempty"`
}

func (KprobeDetails) linkDetails() {}
func (d KprobeDetails) Kind() LinkKind {
	if d.Retprobe {
		return LinkKindKretprobe
	}
	return LinkKindKprobe
}

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
func (d UprobeDetails) Kind() LinkKind {
	if d.Retprobe {
		return LinkKindUretprobe
	}
	return LinkKindUprobe
}

// FentryDetails contains fields specific to fentry attachments.
type FentryDetails struct {
	FnName string `json:"fn_name"`
}

func (FentryDetails) linkDetails()   {}
func (FentryDetails) Kind() LinkKind { return LinkKindFentry }

// FexitDetails contains fields specific to fexit attachments.
type FexitDetails struct {
	FnName string `json:"fn_name"`
}

func (FexitDetails) linkDetails()   {}
func (FexitDetails) Kind() LinkKind { return LinkKindFexit }

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

func (XDPDetails) linkDetails()   {}
func (XDPDetails) Kind() LinkKind { return LinkKindXDP }

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

func (TCDetails) linkDetails()   {}
func (TCDetails) Kind() LinkKind { return LinkKindTC }

// TCXDetails contains fields specific to TCX attachments.
type TCXDetails struct {
	Interface string `json:"interface"`
	Ifindex   uint32 `json:"ifindex"`
	Direction string `json:"direction"` // "ingress" or "egress"
	Priority  int32  `json:"priority"`
	Netns     string `json:"netns,omitempty"`
	Nsid      uint64 `json:"nsid,omitempty"`
}

func (TCXDetails) linkDetails()   {}
func (TCXDetails) Kind() LinkKind { return LinkKindTCX }

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
	Kernel  *kernel.Link
}

// MarshalJSON implements json.Marshaler for ManagedLink.
// The kernel.Link is serialized directly as it has JSON tags.
func (l ManagedLink) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Managed *LinkInfo    `json:"managed"`
		Kernel  *kernel.Link `json:"kernel"`
	}{
		Managed: l.Managed,
		Kernel:  l.Kernel,
	})
}

// ----------------------------------------------------------------------------
// New domain types (Commit 1 refactoring)
// ----------------------------------------------------------------------------

// LinkKind is bpfman's discriminator for link types.
// Distinct from kernel.Link.LinkType which is kernel-reported.
type LinkKind string

const (
	LinkKindTracepoint LinkKind = "tracepoint"
	LinkKindKprobe     LinkKind = "kprobe"
	LinkKindKretprobe  LinkKind = "kretprobe"
	LinkKindUprobe     LinkKind = "uprobe"
	LinkKindUretprobe  LinkKind = "uretprobe"
	LinkKindFentry     LinkKind = "fentry"
	LinkKindFexit      LinkKind = "fexit"
	LinkKindXDP        LinkKind = "xdp"
	LinkKindTC         LinkKind = "tc"
	LinkKindTCX        LinkKind = "tcx"
)

// ParseLinkKind parses a string into a LinkKind.
// Returns the LinkKind and true if valid, or empty string and false if invalid.
func ParseLinkKind(s string) (LinkKind, bool) {
	switch s {
	case "tracepoint":
		return LinkKindTracepoint, true
	case "kprobe":
		return LinkKindKprobe, true
	case "kretprobe":
		return LinkKindKretprobe, true
	case "uprobe":
		return LinkKindUprobe, true
	case "uretprobe":
		return LinkKindUretprobe, true
	case "fentry":
		return LinkKindFentry, true
	case "fexit":
		return LinkKindFexit, true
	case "xdp":
		return LinkKindXDP, true
	case "tc":
		return LinkKindTC, true
	case "tcx":
		return LinkKindTCX, true
	default:
		return "", false
	}
}

// LinkTypeToKind converts a LinkType to a LinkKind.
// This provides a migration path from the old LinkType to the new LinkKind.
func LinkTypeToKind(t LinkType) LinkKind {
	return LinkKind(t)
}

// LinkID is bpfman's identifier for a link.
// Opaque to callers; currently backed by kernel/synthetic link ID.
// uint64 to accommodate a future independent autoincrement id.
//
// Implementation note: The current schema uses kernel_link_id as the primary
// key. During this refactor, LinkID is populated from kernel_link_id for
// compatibility. Callers must treat LinkID as opaque; it must not be used
// as a kernel correlation key outside inspect/store internals.
type LinkID uint64

// IsSynthetic returns true if this ID was minted by bpfman (not a kernel-assigned link ID).
// Future-safe: returns false for ids > MaxUint32 (future autoincrement range).
func (id LinkID) IsSynthetic() bool {
	if id > math.MaxUint32 {
		return false // future autoincrement ids are not synthetic
	}
	return IsSyntheticLinkID(uint32(id))
}

// LinkRecord is what bpfman persists/manages about a link.
// NO kernel IDs - those are ephemeral. Use composite Link for kernel state.
type LinkRecord struct {
	ID        LinkID      `json:"id"`
	Kind      LinkKind    `json:"kind"`
	PinPath   string      `json:"pin_path,omitempty"`
	CreatedAt time.Time   `json:"created_at"`
	Details   LinkDetails `json:"details,omitempty"`
	// owner, metadata, etc. as needed
	// Note: Synthetic is derived via ID.IsSynthetic(), not stored
	// Note: When Details is non-nil, Kind must equal Details.Kind(); constructors enforce this
}

// IsSynthetic returns true if this is a synthetic link (perf_event-based, no kernel link).
func (r LinkRecord) IsSynthetic() bool { return r.ID.IsSynthetic() }

// HasPin returns true if this link has a pin path.
func (r LinkRecord) HasPin() bool { return r.PinPath != "" }

// Link is the canonical domain object - managed state + kernel state.
// Kernel.ID, Kernel.ProgramID come from kernel.Link.
type Link struct {
	Managed LinkRecord
	Kernel  kernel.Link
}

// NewLinkRecordSummary creates a summary-only record (no details).
// Used by inspect when details are loaded lazily.
func NewLinkRecordSummary(id LinkID, kind LinkKind, pinPath string, createdAt time.Time) LinkRecord {
	return LinkRecord{
		ID:        id,
		Kind:      kind,
		PinPath:   pinPath,
		CreatedAt: createdAt,
	}
}

// NewLinkRecord creates a fully-detailed record.
// Kind is derived from details to enforce the invariant.
func NewLinkRecord(id LinkID, details LinkDetails, pinPath string, createdAt time.Time) LinkRecord {
	return LinkRecord{
		ID:        id,
		Kind:      details.Kind(),
		PinPath:   pinPath,
		CreatedAt: createdAt,
		Details:   details,
	}
}
