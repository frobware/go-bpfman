package managed

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
	Nsid         uint32  `json:"nsid,omitempty"`
	DispatcherID uint32  `json:"dispatcher_id"`
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
	Nsid         uint32  `json:"nsid,omitempty"`
	DispatcherID uint32  `json:"dispatcher_id"`
}

func (TCDetails) linkDetails() {}

// TCXDetails contains fields specific to TCX attachments.
type TCXDetails struct {
	Interface string `json:"interface"`
	Ifindex   uint32 `json:"ifindex"`
	Direction string `json:"direction"` // "ingress" or "egress"
	Priority  int32  `json:"priority"`
	Netns     string `json:"netns,omitempty"`
	Nsid      uint32 `json:"nsid,omitempty"`
}

func (TCXDetails) linkDetails() {}
