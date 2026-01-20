package domain

// ProgramType represents the type of BPF program.
type ProgramType uint32

const (
	ProgramTypeUnspecified ProgramType = iota
	ProgramTypeXDP
	ProgramTypeTC
	ProgramTypeTCX
	ProgramTypeTracepoint
	ProgramTypeKprobe
	ProgramTypeKretprobe
	ProgramTypeUprobe
	ProgramTypeUretprobe
	ProgramTypeFentry
	ProgramTypeFexit
)

// String returns the string representation of the program type.
func (t ProgramType) String() string {
	switch t {
	case ProgramTypeXDP:
		return "xdp"
	case ProgramTypeTC:
		return "tc"
	case ProgramTypeTCX:
		return "tcx"
	case ProgramTypeTracepoint:
		return "tracepoint"
	case ProgramTypeKprobe:
		return "kprobe"
	case ProgramTypeKretprobe:
		return "kretprobe"
	case ProgramTypeUprobe:
		return "uprobe"
	case ProgramTypeUretprobe:
		return "uretprobe"
	case ProgramTypeFentry:
		return "fentry"
	case ProgramTypeFexit:
		return "fexit"
	default:
		return "unspecified"
	}
}

// ParseProgramType parses a string into a ProgramType.
func ParseProgramType(s string) Option[ProgramType] {
	switch s {
	case "xdp":
		return Some(ProgramTypeXDP)
	case "tc":
		return Some(ProgramTypeTC)
	case "tcx":
		return Some(ProgramTypeTCX)
	case "tracepoint":
		return Some(ProgramTypeTracepoint)
	case "kprobe":
		return Some(ProgramTypeKprobe)
	case "kretprobe":
		return Some(ProgramTypeKretprobe)
	case "uprobe":
		return Some(ProgramTypeUprobe)
	case "uretprobe":
		return Some(ProgramTypeUretprobe)
	case "fentry":
		return Some(ProgramTypeFentry)
	case "fexit":
		return Some(ProgramTypeFexit)
	default:
		return None[ProgramType]()
	}
}
