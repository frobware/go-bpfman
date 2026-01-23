package bpfman

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
