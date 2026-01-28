package manager

import (
	"errors"
	"log/slog"
)

// undoStack accumulates rollback closures that are executed in reverse
// order when a multi-step operation fails partway through. Each
// closure should undo one kernel-side effect (detach a link, remove a
// pin, etc.).
type undoStack []func() error

// push appends a rollback closure to the stack.
func (u *undoStack) push(fn func() error) {
	*u = append(*u, fn)
}

// rollback executes all closures in reverse order, logging and
// collecting any errors. Returns nil if every closure succeeds.
func (u undoStack) rollback(logger *slog.Logger) error {
	var errs []error
	for i := len(u) - 1; i >= 0; i-- {
		if err := u[i](); err != nil {
			logger.Error("rollback step failed", "step", i, "error", err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
