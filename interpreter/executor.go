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

	case action.DeleteLink:
		return e.store.DeleteLink(ctx, a.KernelLinkID)

	case action.SaveTracepointLink:
		return e.store.SaveTracepointLink(ctx, a.Summary, a.Details)

	case action.SaveXDPLink:
		return e.store.SaveXDPLink(ctx, a.Summary, a.Details)

	case action.SaveTCLink:
		return e.store.SaveTCLink(ctx, a.Summary, a.Details)

	case action.SaveTCXLink:
		return e.store.SaveTCXLink(ctx, a.Summary, a.Details)

	case action.SaveKprobeLink:
		return e.store.SaveKprobeLink(ctx, a.Summary, a.Details)

	case action.SaveUprobeLink:
		return e.store.SaveUprobeLink(ctx, a.Summary, a.Details)

	case action.SaveFentryLink:
		return e.store.SaveFentryLink(ctx, a.Summary, a.Details)

	case action.SaveFexitLink:
		return e.store.SaveFexitLink(ctx, a.Summary, a.Details)

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
