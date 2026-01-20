package interpreter

import (
	"context"
	"fmt"

	"github.com/frobware/go-bpfman/pkg/bpfman/action"
)

// Executor interprets and executes actions.
type Executor struct {
	store  ProgramStore
	kernel KernelOperations
}

// NewExecutor creates a new action executor.
func NewExecutor(store ProgramStore, kernel KernelOperations) *Executor {
	return &Executor{
		store:  store,
		kernel: kernel,
	}
}

// Execute runs a single action.
func (e *Executor) Execute(ctx context.Context, a action.Action) error {
	switch a := a.(type) {
	case action.SaveProgram:
		return e.store.Save(ctx, a.KernelID, a.Metadata)

	case action.DeleteProgram:
		return e.store.Delete(ctx, a.KernelID)

	case action.LoadProgram:
		_, err := e.kernel.Load(ctx, a.Spec)
		return err

	case action.UnloadProgram:
		return e.kernel.Unload(ctx, a.PinPath)

	case action.Batch:
		return e.ExecuteAll(ctx, a.Actions)

	case action.Sequence:
		return e.ExecuteAll(ctx, a.Actions)

	default:
		return fmt.Errorf("unknown action type: %T", a)
	}
}

// ExecuteAll runs multiple actions, stopping on first error.
func (e *Executor) ExecuteAll(ctx context.Context, actions []action.Action) error {
	for _, a := range actions {
		if err := e.Execute(ctx, a); err != nil {
			return err
		}
	}
	return nil
}
