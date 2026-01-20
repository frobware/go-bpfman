package domain

// AttachType specifies the type of BPF program attachment.
type AttachType string

const (
	AttachTracepoint AttachType = "tracepoint"
	AttachKprobe     AttachType = "kprobe"
	AttachKretprobe  AttachType = "kretprobe"
)

// AttachInfo describes how to attach a BPF program.
type AttachInfo struct {
	Type AttachType

	// For tracepoint attachments
	TracepointGroup string
	TracepointName  string

	// For kprobe/kretprobe attachments
	KprobeFunc string

	// Path to pin the link (optional)
	LinkPinPath string
}

// AttachedLink is the result of successfully attaching a program.
type AttachedLink struct {
	// Kernel link ID (if available)
	ID uint32
	// Path where the link is pinned (if pinned)
	PinPath string
	// Type of attachment
	Type AttachType
}
