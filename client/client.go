// Package client provides types for BPF program management.
//
// Note: Local BPF program management is now done directly through the
// manager package. This package contains shared types and errors.
package client

import "errors"

// ErrNotSupported is returned when an operation is not available.
var ErrNotSupported = errors.New("operation not supported")

// DefaultSocketPath returns the default Unix socket path for the bpfman daemon.
func DefaultSocketPath() string {
	return "/run/bpfman-sock/bpfman.sock"
}
