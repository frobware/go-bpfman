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
	if logger == nil {
		logger = slog.Default()
	}
	setupLogger := logger.With("component", "setup")

	setupLogger.Debug("ensuring runtime directories",
		"base", dirs.Base,
		"fs", dirs.FS,
		"db", dirs.DB,
		"sock", dirs.Sock)

	if err := dirs.EnsureDirectories(); err != nil {
		setupLogger.Error("failed to ensure directories", "error", err)
		return nil, nil, err
	}
	setupLogger.Debug("runtime directories ready")

	setupLogger.Debug("opening database", "path", dirs.DBPath())
	store, err := sqlite.New(dirs.DBPath(), logger)
	if err != nil {
		setupLogger.Error("failed to open database", "error", err)
		return nil, nil, err
	}
	setupLogger.Debug("database opened")

	kernel := ebpf.New()
	cleanup := func() { store.Close() }

	setupLogger.Debug("manager ready")
	return New(dirs, store, kernel, logger), cleanup, nil
}
