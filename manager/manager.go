// Package manager provides high-level orchestration using
// the fetch/compute/execute pattern.
//
// # Atomic Load Model
//
// The Manager provides atomic semantics for loading BPF programs.
// The goal is to ensure that either a program is fully loaded with its
// metadata persisted, or nothing is left behind (no partial state).
//
// The atomic model:
//  1. Load program into kernel and pin to bpffs
//  2. On success: persist metadata to DB in a single transaction
//  3. On failure: cleanup kernel state, nothing in DB
//  4. GC handles orphans from crashes
//
// This is simpler than the previous 2PC reservation pattern because:
//   - Programs only exist in DB after successful load
//   - No "loading" or "error" states to manage
//   - GC only needs to handle orphan pins (crash recovery)
//
// # CSI Integration
//
// The CSI driver is a consumer of loaded programs, not part of the
// transaction. It creates per-pod views of maps via re-pinning:
//
//	canonical: /sys/fs/bpf/bpfman/<kernel_id>/<map>     (managed by bpfman)
//	per-pod:   /run/bpfman/csi/fs/<vol>/<map>          (per-pod bpffs mount)
//
// The per-pod path is a separate bpffs mount. Re-pinning creates a new
// pin from the map's file descriptor - this is not a rename across
// filesystems, so there are no cross-device issues.
//
// CSI cleanup removes the per-pod bpffs mount; canonical pins are
// unaffected and remain managed by bpfman.
package manager

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/frobware/go-bpfman/config"
	"github.com/frobware/go-bpfman/interpreter"
)

// Manager orchestrates BPF program management using fetch/compute/execute.
type Manager struct {
	dirs     config.RuntimeDirs
	store    interpreter.Store
	kernel   interpreter.KernelOperations
	executor interpreter.ActionExecutor
	logger   *slog.Logger

	// GC coordination - separate from request-level locking
	gcMu           sync.Mutex
	mutatedSinceGC bool
}

// New creates a new Manager.
func New(dirs config.RuntimeDirs, store interpreter.Store, kernel interpreter.KernelOperations, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		dirs:           dirs,
		store:          store,
		kernel:         kernel,
		executor:       interpreter.NewExecutor(store, kernel),
		logger:         logger.With("component", "manager"),
		mutatedSinceGC: true, // Force GC on first operation
	}
}

// Dirs returns the runtime directories configuration.
func (m *Manager) Dirs() config.RuntimeDirs {
	return m.dirs
}

// GCResult contains statistics from garbage collection.
type GCResult = interpreter.GCResult

// GC removes stale database entries that no longer exist in the kernel.
// This should be called at startup before accepting requests. After GC,
// the database is authoritative for the session.
//
// Stale entries can occur when:
//   - The daemon restarts but kernel state was lost (e.g., system reboot)
//   - A previous unload operation failed partway through
//   - External tools removed BPF objects without updating the database
func (m *Manager) GC(ctx context.Context) (GCResult, error) {
	start := time.Now()

	// Gather kernel state
	kernelProgramIDs := make(map[uint32]bool)
	for kp, err := range m.kernel.Programs(ctx) {
		if err != nil {
			m.logger.Warn("error iterating kernel programs", "error", err)
			continue
		}
		kernelProgramIDs[kp.ID] = true
	}

	kernelLinkIDs := make(map[uint32]bool)
	for kl, err := range m.kernel.Links(ctx) {
		if err != nil {
			m.logger.Warn("error iterating kernel links", "error", err)
			continue
		}
		kernelLinkIDs[kl.ID] = true
	}

	// Delegate to store - it handles ordering constraints internally
	result, err := m.store.GC(ctx, kernelProgramIDs, kernelLinkIDs)
	if err != nil {
		return result, err
	}

	elapsed := time.Since(start)
	if result.ProgramsRemoved > 0 || result.DispatchersRemoved > 0 || result.LinksRemoved > 0 {
		m.logger.Info("gc complete",
			"duration", elapsed,
			"programs_removed", result.ProgramsRemoved,
			"dispatchers_removed", result.DispatchersRemoved,
			"links_removed", result.LinksRemoved)
	} else {
		m.logger.Debug("gc complete", "duration", elapsed)
	}

	return result, nil
}

// GCIfNeeded runs GC if required, with its own mutex for coordination.
// For mutating operations, always runs GC. For read operations, only runs
// GC if a mutating operation occurred since the last GC.
// This allows concurrent readers at the server level while serialising GC.
func (m *Manager) GCIfNeeded(ctx context.Context, mutating bool) error {
	m.gcMu.Lock()
	defer m.gcMu.Unlock()

	if !mutating && !m.mutatedSinceGC {
		return nil // Read op and no mutations since last GC - skip
	}

	if _, err := m.GC(ctx); err != nil {
		return err
	}
	m.mutatedSinceGC = false
	return nil
}

// MarkMutated records that a mutating operation occurred.
// Call this after successful mutating operations (Load, Unload, Attach, Detach).
func (m *Manager) MarkMutated() {
	m.gcMu.Lock()
	m.mutatedSinceGC = true
	m.gcMu.Unlock()
}
