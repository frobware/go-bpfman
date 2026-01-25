// Package netns provides network namespace identification and switching functions.
package netns

import (
	"fmt"
	"os"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
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

// GetNsid returns the inode number of the network namespace at the given path.
// If path is empty, returns the current namespace's inode.
func GetNsid(path string) (uint64, error) {
	if path == "" {
		return GetCurrentNsid()
	}
	var stat syscall.Stat_t
	if err := syscall.Stat(path, &stat); err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return stat.Ino, nil
}

// Guard holds the original network namespace file descriptor and restores
// it when Close() is called. This implements the RAII pattern used by
// the Rust bpfman implementation.
//
// Usage:
//
//	guard, err := netns.Enter("/var/run/netns/target")
//	if err != nil {
//	    return err
//	}
//	defer guard.Close()
//	// ... operations in target namespace ...
type Guard struct {
	originalNS *os.File
}

// Close restores the original network namespace, closes the file descriptor,
// and unlocks the OS thread that was locked by Enter().
// It is safe to call Close multiple times.
func (g *Guard) Close() error {
	if g.originalNS == nil {
		return nil
	}

	// Switch back to the original namespace
	// Note: We're already locked to this thread from Enter()
	err := unix.Setns(int(g.originalNS.Fd()), unix.CLONE_NEWNET)
	closeErr := g.originalNS.Close()
	g.originalNS = nil

	// Unlock the thread that was locked in Enter()
	runtime.UnlockOSThread()

	if err != nil {
		return fmt.Errorf("setns to restore original namespace: %w", err)
	}
	return closeErr
}

// Enter switches to the network namespace specified by path and returns a Guard
// that will restore the original namespace when Close() is called.
//
// The path should be a network namespace file, typically:
//   - /proc/<pid>/ns/net for a process's namespace
//   - /var/run/netns/<name> for a named namespace
//
// The caller must call Guard.Close() to restore the original namespace,
// typically using defer.
//
// Note: This function locks the current goroutine to its OS thread for the
// duration of the namespace switch. The Guard.Close() will unlock it.
func Enter(path string) (*Guard, error) {
	// Lock to this OS thread - namespace switching is per-thread
	runtime.LockOSThread()

	// Open our current namespace to restore later
	originalNS, err := os.Open(fmt.Sprintf("/proc/%d/ns/net", os.Getpid()))
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("open current network namespace: %w", err)
	}

	// Open target namespace
	targetNS, err := os.Open(path)
	if err != nil {
		originalNS.Close()
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("open target network namespace %s: %w", path, err)
	}
	defer targetNS.Close()

	// Switch to target namespace
	if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNET); err != nil {
		originalNS.Close()
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("setns to target namespace: %w", err)
	}

	// Note: We don't unlock the thread here. The Guard.Close() will do that
	// after restoring the original namespace. This ensures all operations
	// between Enter() and Close() happen in the target namespace.

	return &Guard{originalNS: originalNS}, nil
}
