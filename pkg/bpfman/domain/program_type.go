package domain

// ProgramType represents the type of BPF program.
type ProgramType uint32

// MarshalText implements encoding.TextMarshaler so ProgramType
// serialises as its string name in JSON.
func (t ProgramType) MarshalText() ([]byte, error) {
	return []byte(t.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler so ProgramType
// can be parsed from its string name in JSON.
func (t *ProgramType) UnmarshalText(text []byte) error {
	parsed, _ := ParseProgramType(string(text))
	*t = parsed
	return nil
}

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
// Returns the program type and true if valid, or ProgramTypeUnspecified and false if not.
func ParseProgramType(s string) (ProgramType, bool) {
	switch s {
	case "xdp":
		return ProgramTypeXDP, true
	case "tc":
		return ProgramTypeTC, true
	case "tcx":
		return ProgramTypeTCX, true
	case "tracepoint":
		return ProgramTypeTracepoint, true
	case "kprobe":
		return ProgramTypeKprobe, true
	case "kretprobe":
		return ProgramTypeKretprobe, true
	case "uprobe":
		return ProgramTypeUprobe, true
	case "uretprobe":
		return ProgramTypeUretprobe, true
	case "fentry":
		return ProgramTypeFentry, true
	case "fexit":
		return ProgramTypeFexit, true
	default:
		return ProgramTypeUnspecified, false
	}
}
