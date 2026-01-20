package managed

import (
	"time"

	"github.com/frobware/go-bpfman/pkg/bpfman"
)

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

// AttachSpec describes how to attach a BPF program.
type AttachSpec struct {
	Type LinkType `json:"type"`

	// Tracepoint fields
	TracepointGroup string `json:"tracepoint_group,omitempty"`
	TracepointName  string `json:"tracepoint_name,omitempty"`

	// Kprobe/Uprobe fields
	FnName   string `json:"fn_name,omitempty"`
	Offset   uint64 `json:"offset,omitempty"`
	RetProbe bool   `json:"ret_probe,omitempty"`
	Target   string `json:"target,omitempty"` // Binary path for uprobe
	PID      int32  `json:"pid,omitempty"`    // Filter by PID for uprobe

	// XDP/TC/TCX fields
	Interface string `json:"interface,omitempty"`
	Priority  int32  `json:"priority,omitempty"`
	Direction string `json:"direction,omitempty"` // ingress/egress for TC
}

// Link contains metadata for a managed link/attachment.
type Link struct {
	ID          uint32     `json:"id"`           // Kernel link ID (if available)
	UUID        string     `json:"uuid"`         // Our unique identifier
	ProgramID   uint32     `json:"program_id"`   // Kernel program ID this is attached to
	ProgramUUID string     `json:"program_uuid"` // UUID of the managed program
	Type        LinkType   `json:"type"`
	PinPath     string     `json:"pin_path,omitempty"`
	AttachSpec  AttachSpec `json:"attach_spec"`
	CreatedAt   time.Time  `json:"created_at"`
}

// Attached is the result of successfully attaching a program.
type Attached struct {
	LinkID      uint32     `json:"link_id,omitempty"` // Kernel link ID (0 if not supported)
	UUID        string     `json:"uuid"`
	ProgramID   uint32     `json:"program_id"`
	ProgramUUID string     `json:"program_uuid"`
	Type        LinkType   `json:"type"`
	PinPath     string     `json:"pin_path,omitempty"`
	AttachSpec  AttachSpec `json:"attach_spec"`
}

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

// ToAttachType converts LinkType to bpfman.AttachType for backward compatibility.
func (t LinkType) ToAttachType() bpfman.AttachType {
	switch t {
	case LinkTypeTracepoint:
		return bpfman.AttachTracepoint
	case LinkTypeKprobe:
		return bpfman.AttachKprobe
	case LinkTypeKretprobe:
		return bpfman.AttachKretprobe
	default:
		return bpfman.AttachType(t)
	}
}
