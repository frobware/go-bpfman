package compute

import (
	"testing"

	"github.com/frobware/go-bpfman/pkg/bpfman/action"
	"github.com/frobware/go-bpfman/pkg/bpfman/domain"
)

func TestReconcileActions_OrphanedPrograms(t *testing.T) {
	// Programs in store but not in kernel should be deleted
	stored := map[uint32]domain.ProgramMetadata{
		1: {Owner: "bpfman"},
		2: {Owner: "bpfman"},
		3: {Owner: "bpfman"},
	}

	kernel := []domain.KernelProgram{
		{ID: 1, Name: "prog1"},
		// ID 2 and 3 are gone from kernel
	}

	actions := ReconcileActions(stored, kernel)

	// Should have 2 delete actions for IDs 2 and 3
	if len(actions) != 2 {
		t.Fatalf("expected 2 actions, got %d", len(actions))
	}

	deleteIDs := make(map[uint32]bool)
	for _, a := range actions {
		da, ok := a.(action.DeleteProgram)
		if !ok {
			t.Fatalf("expected DeleteProgram action, got %T", a)
		}
		deleteIDs[da.KernelID] = true
	}

	if !deleteIDs[2] || !deleteIDs[3] {
		t.Errorf("expected delete actions for IDs 2 and 3, got %v", deleteIDs)
	}
}

func TestReconcileActions_NoOrphans(t *testing.T) {
	stored := map[uint32]domain.ProgramMetadata{
		1: {Owner: "bpfman"},
	}

	kernel := []domain.KernelProgram{
		{ID: 1, Name: "prog1"},
		{ID: 2, Name: "prog2"}, // Unmanaged, not in store
	}

	actions := ReconcileActions(stored, kernel)

	if len(actions) != 0 {
		t.Fatalf("expected 0 actions, got %d", len(actions))
	}
}

func TestReconcileActions_EmptyStore(t *testing.T) {
	stored := map[uint32]domain.ProgramMetadata{}

	kernel := []domain.KernelProgram{
		{ID: 1, Name: "prog1"},
	}

	actions := ReconcileActions(stored, kernel)

	if len(actions) != 0 {
		t.Fatalf("expected 0 actions, got %d", len(actions))
	}
}

func TestOrphanedPrograms(t *testing.T) {
	stored := map[uint32]domain.ProgramMetadata{
		1: {Owner: "bpfman"},
		2: {Owner: "bpfman"},
	}

	kernel := []domain.KernelProgram{
		{ID: 1, Name: "prog1"},
	}

	orphaned := OrphanedPrograms(stored, kernel)

	if len(orphaned) != 1 {
		t.Fatalf("expected 1 orphaned, got %d", len(orphaned))
	}

	if orphaned[0] != 2 {
		t.Errorf("expected orphaned ID 2, got %d", orphaned[0])
	}
}

func TestUnmanagedPrograms(t *testing.T) {
	stored := map[uint32]domain.ProgramMetadata{
		1: {Owner: "bpfman"},
	}

	kernel := []domain.KernelProgram{
		{ID: 1, Name: "prog1"},
		{ID: 2, Name: "prog2"},
		{ID: 3, Name: "prog3"},
	}

	unmanaged := UnmanagedPrograms(stored, kernel)

	if len(unmanaged) != 2 {
		t.Fatalf("expected 2 unmanaged, got %d", len(unmanaged))
	}
}
