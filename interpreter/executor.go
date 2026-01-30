package interpreter

import (
	"context"
	"fmt"

	"github.com/frobware/go-bpfman/action"
)

// ActionExecutor executes reified actions.
type ActionExecutor interface {
	Execute(ctx context.Context, a action.Action) error
	ExecuteAll(ctx context.Context, actions []action.Action) error
}

// executor interprets and executes actions.
type executor struct {
	store  Store
	kernel KernelOperations
}

// NewExecutor creates a new action executor.
func NewExecutor(store Store, kernel KernelOperations) ActionExecutor {
	return &executor{
		store:  store,
		kernel: kernel,
	}
}

// Execute runs a single action.
func (e *executor) Execute(ctx context.Context, a action.Action) error {
	switch a := a.(type) {
	case action.SaveProgram:
		return e.store.Save(ctx, a.KernelID, a.Metadata)

	case action.DeleteProgram:
		return e.store.Delete(ctx, a.KernelID)

	case action.SaveLink:
		return e.store.SaveLink(ctx, a.LinkID, a.Record, a.KernelProgramID)

	case action.DeleteLink:
		return e.store.DeleteLink(ctx, a.LinkID)

	case action.LoadProgram:
		_, err := e.kernel.Load(ctx, a.Spec)
		return err

	case action.UnloadProgram:
		return e.kernel.Unload(ctx, a.PinPath)

	case action.Batch:
		return e.ExecuteAll(ctx, a.Actions)

	case action.Sequence:
		return e.ExecuteAll(ctx, a.Actions)

	case action.SaveDispatcher:
		return e.store.SaveDispatcher(ctx, a.State)

	case action.DeleteDispatcher:
		return e.store.DeleteDispatcher(ctx, a.Type, a.Nsid, a.Ifindex)

	case action.DetachLink:
		return e.kernel.DetachLink(ctx, a.PinPath)

	case action.RemovePin:
		return e.kernel.RemovePin(ctx, a.Path)

	case action.DetachTCFilter:
		return e.kernel.DetachTCFilter(ctx, a.Ifindex, a.Ifname, a.Parent, a.Priority, a.Handle)

	default:
		return fmt.Errorf("unknown action type: %T", a)
	}
}

// ExecuteAll runs multiple actions, stopping on first error.
func (e *executor) ExecuteAll(ctx context.Context, actions []action.Action) error {
	for _, a := range actions {
		if err := e.Execute(ctx, a); err != nil {
			return err
		}
	}
	return nil
}
