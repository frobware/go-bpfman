// Package compute contains pure functions for business logic.
// Functions in this package perform no I/O - they transform data into actions.
package compute

import (
	"github.com/frobware/go-bpfman/pkg/bpfman/action"
	"github.com/frobware/go-bpfman/pkg/bpfman/kernel"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

// ReconcileActions computes the actions needed to reconcile store state
// with kernel state. This is a pure function - no I/O.
func ReconcileActions(
	stored map[uint32]managed.Program,
	kps []kernel.Program,
) []action.Action {
	var actions []action.Action

	// Build set of kernel program IDs
	kernelIDs := make(map[uint32]bool, len(kps))
	for _, kp := range kps {
		kernelIDs[kp.ID] = true
	}

	// Programs in store but not in kernel should be removed from store
	for id := range stored {
		if !kernelIDs[id] {
			actions = append(actions, action.DeleteProgram{KernelID: id})
		}
	}

	return actions
}

// OrphanedPrograms returns IDs of programs in store that no longer exist in kernel.
// Pure function.
func OrphanedPrograms(
	stored map[uint32]managed.Program,
	kps []kernel.Program,
) []uint32 {
	kernelIDs := make(map[uint32]bool, len(kps))
	for _, kp := range kps {
		kernelIDs[kp.ID] = true
	}

	var orphaned []uint32
	for id := range stored {
		if !kernelIDs[id] {
			orphaned = append(orphaned, id)
		}
	}
	return orphaned
}

// UnmanagedPrograms returns kernel programs not tracked in the store.
// Pure function.
func UnmanagedPrograms(
	stored map[uint32]managed.Program,
	kps []kernel.Program,
) []kernel.Program {
	var unmanaged []kernel.Program
	for _, kp := range kps {
		if _, exists := stored[kp.ID]; !exists {
			unmanaged = append(unmanaged, kp)
		}
	}
	return unmanaged
}
