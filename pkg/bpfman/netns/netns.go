// Package netns provides network namespace identification functions.
package netns

import (
	"fmt"
	"syscall"
)

// GetCurrentNsid returns the inode number of the current network namespace.
// This inode uniquely identifies the network namespace and is used to
// construct dispatcher paths that match the Rust bpfman convention.
func GetCurrentNsid() (uint64, error) {
	var stat syscall.Stat_t
	if err := syscall.Stat("/proc/self/ns/net", &stat); err != nil {
		return 0, fmt.Errorf("stat /proc/self/ns/net: %w", err)
	}
	return stat.Ino, nil
}
