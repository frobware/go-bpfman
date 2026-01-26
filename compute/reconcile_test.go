package compute_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/action"
	"github.com/frobware/go-bpfman/compute"
	"github.com/frobware/go-bpfman/kernel"
)

func TestReconcileActions_OrphanedPrograms(t *testing.T) {
	// Programs in store but not in kernel should be deleted
	stored := map[uint32]bpfman.Program{
		1: {Owner: "bpfman"},
		2: {Owner: "bpfman"},
		3: {Owner: "bpfman"},
	}

	kps := []kernel.Program{
		{ID: 1, Name: "prog1"},
		// ID 2 and 3 are gone from kernel
	}

	actions := compute.ReconcileActions(stored, kps)

	// Should have 2 delete actions for IDs 2 and 3
	require.Len(t, actions, 2, "expected 2 actions")

	deleteIDs := make(map[uint32]bool)
	for _, a := range actions {
		da, ok := a.(action.DeleteProgram)
		require.True(t, ok, "expected DeleteProgram action, got %T", a)
		deleteIDs[da.KernelID] = true
	}

	assert.True(t, deleteIDs[2], "expected delete action for ID 2")
	assert.True(t, deleteIDs[3], "expected delete action for ID 3")
}

func TestReconcileActions_NoOrphans(t *testing.T) {
	stored := map[uint32]bpfman.Program{
		1: {Owner: "bpfman"},
	}

	kps := []kernel.Program{
		{ID: 1, Name: "prog1"},
		{ID: 2, Name: "prog2"}, // Unmanaged, not in store
	}

	actions := compute.ReconcileActions(stored, kps)

	assert.Empty(t, actions, "expected 0 actions")
}

func TestReconcileActions_EmptyStore(t *testing.T) {
	stored := map[uint32]bpfman.Program{}

	kps := []kernel.Program{
		{ID: 1, Name: "prog1"},
	}

	actions := compute.ReconcileActions(stored, kps)

	assert.Empty(t, actions, "expected 0 actions")
}

func TestOrphanedPrograms(t *testing.T) {
	stored := map[uint32]bpfman.Program{
		1: {Owner: "bpfman"},
		2: {Owner: "bpfman"},
	}

	kps := []kernel.Program{
		{ID: 1, Name: "prog1"},
	}

	orphaned := compute.OrphanedPrograms(stored, kps)

	require.Len(t, orphaned, 1, "expected 1 orphaned")
	assert.Equal(t, uint32(2), orphaned[0], "expected orphaned ID 2")
}

func TestUnmanagedPrograms(t *testing.T) {
	stored := map[uint32]bpfman.Program{
		1: {Owner: "bpfman"},
	}

	kps := []kernel.Program{
		{ID: 1, Name: "prog1"},
		{ID: 2, Name: "prog2"},
		{ID: 3, Name: "prog3"},
	}

	unmanaged := compute.UnmanagedPrograms(stored, kps)

	assert.Len(t, unmanaged, 2, "expected 2 unmanaged")
}

func TestReconcileActions_MapOwnerOrdering(t *testing.T) {
	// Test that programs with MapOwnerID (dependents) are deleted before
	// programs without MapOwnerID (owners) to satisfy FK constraints.
	//
	// Schema has: FOREIGN KEY (map_owner_id) REFERENCES managed_programs(kernel_id)
	//             ON DELETE RESTRICT
	//
	// If owner (100) is deleted before dependents (101, 102), FK fails.
	stored := map[uint32]bpfman.Program{
		100: {ProgramName: "owner", MapOwnerID: 0},  // Owner - owns maps
		101: {ProgramName: "dep1", MapOwnerID: 100}, // Dependent - uses owner's maps
		102: {ProgramName: "dep2", MapOwnerID: 100}, // Dependent - uses owner's maps
	}

	// All programs are gone from kernel
	kps := []kernel.Program{}

	actions := compute.ReconcileActions(stored, kps)

	require.Len(t, actions, 3, "expected 3 delete actions")

	// Verify ordering: dependents (101, 102) must come before owner (100)
	var order []uint32
	for _, a := range actions {
		da, ok := a.(action.DeleteProgram)
		require.True(t, ok, "expected DeleteProgram action")
		order = append(order, da.KernelID)
	}

	// Find position of owner (100) in the order
	ownerIdx := -1
	for i, id := range order {
		if id == 100 {
			ownerIdx = i
			break
		}
	}
	require.NotEqual(t, -1, ownerIdx, "owner should be in the actions")

	// All dependents must come before the owner
	for i, id := range order {
		if id == 101 || id == 102 {
			assert.Less(t, i, ownerIdx, "dependent %d (idx %d) should be deleted before owner (idx %d)", id, i, ownerIdx)
		}
	}
}
