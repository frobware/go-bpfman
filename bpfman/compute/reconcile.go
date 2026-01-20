// Package compute contains pure functions for business logic.
// Functions in this package perform no I/O - they transform data into actions.
package compute

import (
	"github.com/frobware/bpffs-csi-driver/bpfman/action"
	"github.com/frobware/bpffs-csi-driver/bpfman/domain"
)

// ReconcileActions computes the actions needed to reconcile store state
// with kernel state. This is a pure function - no I/O.
func ReconcileActions(
	stored map[uint32]domain.ProgramMetadata,
	kernel []domain.KernelProgram,
) []action.Action {
	var actions []action.Action

	// Build set of kernel program IDs
	kernelIDs := make(map[uint32]bool, len(kernel))
	for _, kp := range kernel {
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
	stored map[uint32]domain.ProgramMetadata,
	kernel []domain.KernelProgram,
) []uint32 {
	kernelIDs := make(map[uint32]bool, len(kernel))
	for _, kp := range kernel {
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
	stored map[uint32]domain.ProgramMetadata,
	kernel []domain.KernelProgram,
) []domain.KernelProgram {
	var unmanaged []domain.KernelProgram
	for _, kp := range kernel {
		if _, exists := stored[kp.ID]; !exists {
			unmanaged = append(unmanaged, kp)
		}
	}
	return unmanaged
}
