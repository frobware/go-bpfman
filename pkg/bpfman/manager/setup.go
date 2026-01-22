package manager

import (
	"log/slog"

	"github.com/frobware/go-bpfman/pkg/bpfman/config"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/ebpf"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store/sqlite"
)

// Setup creates a Manager with default implementations and returns
// a cleanup function to close the store.
//
// It ensures runtime directories exist and bpffs is mounted before
// opening the database.
func Setup(dirs config.RuntimeDirs, logger *slog.Logger) (*Manager, func(), error) {
	if err := dirs.EnsureDirectories(); err != nil {
		return nil, nil, err
	}

	store, err := sqlite.New(dirs.DBPath(), logger)
	if err != nil {
		return nil, nil, err
	}

	kernel := ebpf.New()
	cleanup := func() { store.Close() }

	return New(dirs, store, kernel, logger), cleanup, nil
}
