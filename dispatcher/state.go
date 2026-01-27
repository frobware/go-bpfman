package dispatcher

// State represents the persistent state of a dispatcher.
// A dispatcher manages multi-program chaining for XDP or TC attachments.
type State struct {
	// Type is the dispatcher type (xdp, tc-ingress, tc-egress).
	Type DispatcherType `json:"type"`

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
	// Zero for TC dispatchers which use legacy netlink instead of BPF links.
	LinkID uint32 `json:"link_id"`

	// LinkPinPath is the stable path for the dispatcher link.
	// This path remains constant across revisions.
	// Empty for TC dispatchers which use legacy netlink.
	LinkPinPath string `json:"link_pin_path"`

	// Handle is the kernel-assigned tc filter handle.
	// Only set for TC dispatchers (legacy netlink). Zero for XDP.
	Handle uint32 `json:"handle,omitempty"`

	// Priority is the tc filter priority.
	// Only set for TC dispatchers (legacy netlink). Zero for XDP.
	Priority uint16 `json:"priority,omitempty"`

	// ProgPinPath is the path for the dispatcher program.
	// This changes with each revision.
	ProgPinPath string `json:"prog_pin_path"`

	// NumExtensions is the number of extension programs attached.
	NumExtensions uint8 `json:"num_extensions"`
}
