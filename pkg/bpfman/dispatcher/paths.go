package dispatcher

import (
	"fmt"
	"path/filepath"
)

// BpffsRoot is the root directory for all bpfman pins.
const BpffsRoot = "/sys/fs/bpf/bpfman"

// DispatcherType represents the type of dispatcher (XDP or TC).
type DispatcherType string

const (
	DispatcherTypeXDP       DispatcherType = "xdp"
	DispatcherTypeTCIngress DispatcherType = "tc-ingress"
	DispatcherTypeTCEgress  DispatcherType = "tc-egress"
)

// DispatcherLinkPath returns the stable path for the dispatcher link.
// This path remains constant across revisions, enabling atomic updates.
//
// Format: /sys/fs/bpf/bpfman/{type}/dispatcher_{nsid}_{ifindex}_link
//
// Example: /sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_link
func DispatcherLinkPath(dispType DispatcherType, nsid uint64, ifindex uint32) string {
	return filepath.Join(
		BpffsRoot,
		string(dispType),
		fmt.Sprintf("dispatcher_%d_%d_link", nsid, ifindex),
	)
}

// DispatcherRevisionDir returns the directory for a specific dispatcher revision.
// Each revision contains the dispatcher program and extension links.
//
// Format: /sys/fs/bpf/bpfman/{type}/dispatcher_{nsid}_{ifindex}_{revision}
//
// Example: /sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1
func DispatcherRevisionDir(dispType DispatcherType, nsid uint64, ifindex uint32, revision uint32) string {
	return filepath.Join(
		BpffsRoot,
		string(dispType),
		fmt.Sprintf("dispatcher_%d_%d_%d", nsid, ifindex, revision),
	)
}

// DispatcherProgPath returns the path for the dispatcher program within a revision directory.
//
// Format: {revisionDir}/dispatcher
//
// Example: /sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/dispatcher
func DispatcherProgPath(revisionDir string) string {
	return filepath.Join(revisionDir, "dispatcher")
}

// ExtensionLinkPath returns the path for an extension link within a revision directory.
// Each extension is attached to a dispatcher slot identified by position (0-9).
//
// Format: {revisionDir}/link_{position}
//
// Example: /sys/fs/bpf/bpfman/xdp/dispatcher_4026531840_1_1/link_0
func ExtensionLinkPath(revisionDir string, position int) string {
	return filepath.Join(revisionDir, fmt.Sprintf("link_%d", position))
}

// TypeDir returns the base directory for a dispatcher type.
//
// Format: /sys/fs/bpf/bpfman/{type}
//
// Example: /sys/fs/bpf/bpfman/xdp
func TypeDir(dispType DispatcherType) string {
	return filepath.Join(BpffsRoot, string(dispType))
}
