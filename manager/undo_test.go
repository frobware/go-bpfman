package manager

import (
	"errors"
	"log/slog"
	"testing"
)

func TestUndoStack_ReverseOrder(t *testing.T) {
	var order []int
	var undo undoStack
	for i := 0; i < 3; i++ {
		i := i
		undo.push(func() error {
			order = append(order, i)
			return nil
		})
	}
	if err := undo.rollback(slog.Default()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(order) != 3 || order[0] != 2 || order[1] != 1 || order[2] != 0 {
		t.Fatalf("expected reverse order [2 1 0], got %v", order)
	}
}

func TestUndoStack_CollectsErrors(t *testing.T) {
	errA := errors.New("a")
	errB := errors.New("b")
	var undo undoStack
	undo.push(func() error { return errA })
	undo.push(func() error { return errB })

	err := undo.rollback(slog.Default())
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, errA) || !errors.Is(err, errB) {
		t.Fatalf("expected both errors, got: %v", err)
	}
}

func TestUndoStack_EmptyIsNoop(t *testing.T) {
	var undo undoStack
	if err := undo.rollback(slog.Default()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
