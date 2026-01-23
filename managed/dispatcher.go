package managed

import "github.com/frobware/go-bpfman/internal/dispatcher"

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
