// Package mntns provides mount namespace switching functions for attaching
// uprobes to binaries in other containers.
package mntns

import (
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// Guard holds the original mount namespace file descriptor and restores
// it when Close() is called. This implements the RAII pattern.
//
// Usage:
//
//	guard, err := mntns.Enter(containerPid)
//	if err != nil {
//	    return err
//	}
//	defer guard.Close()
//	// ... operations in target mount namespace ...
//	// e.g., open("/go-target") now resolves in container's filesystem
type Guard struct {
	originalNS *os.File
}

// Close restores the original mount namespace, closes the file descriptor,
// and unlocks the OS thread that was locked by Enter().
// It is safe to call Close multiple times.
func (g *Guard) Close() error {
	if g.originalNS == nil {
		return nil
	}

	// Switch back to the original namespace
	// Note: We're already locked to this thread from Enter()
	err := unix.Setns(int(g.originalNS.Fd()), unix.CLONE_NEWNS)
	closeErr := g.originalNS.Close()
	g.originalNS = nil

	// Unlock the thread that was locked in Enter()
	runtime.UnlockOSThread()

	if err != nil {
		return fmt.Errorf("setns to restore original mount namespace: %w", err)
	}
	return closeErr
}

// Enter switches to the mount namespace of the process with the given PID
// and returns a Guard that will restore the original namespace when Close()
// is called.
//
// This is used for uprobe attachment to binaries in other containers.
// The target binary path (e.g., "/go-target") will resolve within the
// target container's filesystem after entering its mount namespace.
//
// The caller must call Guard.Close() to restore the original namespace,
// typically using defer.
//
// Note: This function locks the current goroutine to its OS thread for the
// duration of the namespace switch. The Guard.Close() will unlock it.
func Enter(pid int32) (*Guard, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid: %d", pid)
	}

	// Lock to this OS thread - namespace switching is per-thread
	runtime.LockOSThread()

	// Open our current namespace to restore later
	originalNS, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", os.Getpid()))
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("open current mount namespace: %w", err)
	}

	// Try /proc/<pid>/ns/mnt first (native Linux)
	// Fall back to /host/proc/<pid>/ns/mnt (Kubernetes with hostPID)
	var targetNS *os.File
	targetPath := fmt.Sprintf("/proc/%d/ns/mnt", pid)
	targetNS, err = os.Open(targetPath)
	if err != nil {
		// Try /host/proc path for Kubernetes deployments
		targetPath = fmt.Sprintf("/host/proc/%d/ns/mnt", pid)
		targetNS, err = os.Open(targetPath)
		if err != nil {
			originalNS.Close()
			runtime.UnlockOSThread()
			return nil, fmt.Errorf("open target mount namespace (tried /proc and /host/proc): %w", err)
		}
	}
	defer targetNS.Close()

	// Switch to target namespace
	if err := unix.Setns(int(targetNS.Fd()), unix.CLONE_NEWNS); err != nil {
		originalNS.Close()
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("setns to target mount namespace: %w", err)
	}

	return &Guard{originalNS: originalNS}, nil
}
