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
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/frobware/go-bpfman/config"
	"github.com/frobware/go-bpfman/dispatcher"
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

	// Post-store GC: remove dispatchers whose kernel program is
	// still alive but which have zero extension links and missing
	// filesystem artefacts. The store GC only removes dispatchers
	// whose kernel program is gone; this catches the case where the
	// program lingers in the kernel but the dispatcher is
	// functionally dead (no TC filter, no pins).
	surviving, err := m.store.ListDispatchers(ctx)
	if err != nil {
		m.logger.Warn("failed to list dispatchers for post-GC cleanup", "error", err)
	} else {
		for _, disp := range surviving {
			linkCount, err := m.store.CountDispatcherLinks(ctx, disp.KernelID)
			if err != nil {
				m.logger.Warn("failed to count dispatcher links", "kernel_id", disp.KernelID, "error", err)
				continue
			}
			if linkCount > 0 {
				continue
			}
			// Zero extension links. Check whether the dispatcher
			// is functionally dead. A dispatcher is stale if its
			// prog pin is missing, or for TC dispatchers, if the
			// netlink filter is gone (the filter is what routes
			// traffic; without it the pinned program is inert).
			revDir := dispatcher.DispatcherRevisionDir(m.dirs.FS, disp.Type, disp.Nsid, disp.Ifindex, disp.Revision)
			progPin := dispatcher.DispatcherProgPath(revDir)
			if _, err := os.Stat(progPin); os.IsNotExist(err) {
				// Prog pin missing — definitely stale.
			} else if disp.Type == dispatcher.DispatcherTypeTCIngress || disp.Type == dispatcher.DispatcherTypeTCEgress {
				// Prog pin exists, but for TC dispatchers the
				// filter must also exist.
				parent := tcParent(disp.Type)
				if _, err := m.kernel.FindTCFilterHandle(int(disp.Ifindex), parent, disp.Priority); err != nil {
					// TC filter gone — stale.
				} else {
					continue // Both pin and filter exist.
				}
			} else {
				continue // Non-TC dispatcher with prog pin present.
			}
			m.logger.Info("deleting stale dispatcher with no extensions",
				"type", disp.Type, "nsid", disp.Nsid, "ifindex", disp.Ifindex,
				"kernel_id", disp.KernelID)
			// Clean up filesystem artefacts before removing the DB row.
			os.Remove(progPin)
			os.Remove(revDir)
			if disp.Type == dispatcher.DispatcherTypeXDP {
				linkPin := dispatcher.DispatcherLinkPath(m.dirs.FS, disp.Type, disp.Nsid, disp.Ifindex)
				os.Remove(linkPin)
			}
			if err := m.store.DeleteDispatcher(ctx, string(disp.Type), disp.Nsid, disp.Ifindex); err != nil {
				m.logger.Warn("failed to delete stale dispatcher", "error", err)
				continue
			}
			result.DispatchersRemoved++
		}
	}

	// Orphan filesystem cleanup: remove pins and directories on
	// bpffs that have no corresponding DB record and no live kernel
	// object. We re-read the DB state after store GC to get the
	// post-cleanup view.
	result.OrphanPinsRemoved += m.gcOrphanPins(ctx, kernelProgramIDs)

	elapsed := time.Since(start)
	if result.ProgramsRemoved > 0 || result.DispatchersRemoved > 0 || result.LinksRemoved > 0 || result.OrphanPinsRemoved > 0 {
		m.logger.Info("gc complete",
			"duration", elapsed,
			"programs_removed", result.ProgramsRemoved,
			"dispatchers_removed", result.DispatchersRemoved,
			"links_removed", result.LinksRemoved,
			"orphan_pins_removed", result.OrphanPinsRemoved)
	} else {
		m.logger.Debug("gc complete", "duration", elapsed)
	}

	return result, nil
}

// gcOrphanPins removes filesystem artefacts under bpffs that have no
// corresponding DB record and whose kernel object is also gone. It
// returns the number of orphan entries removed.
func (m *Manager) gcOrphanPins(ctx context.Context, kernelProgramIDs map[uint32]bool) int {
	removed := 0

	// Re-read DB state after store GC for the post-cleanup view.
	dbPrograms, err := m.store.List(ctx)
	if err != nil {
		m.logger.Warn("gcOrphanPins: failed to list programs", "error", err)
		return 0
	}

	dbProgPinSet := make(map[string]bool)
	dbProgIDSet := make(map[uint32]bool)
	for kernelID, prog := range dbPrograms {
		dbProgIDSet[kernelID] = true
		if prog.PinPath != "" {
			dbProgPinSet[prog.PinPath] = true
		}
	}

	dbDispatchers, err := m.store.ListDispatchers(ctx)
	if err != nil {
		m.logger.Warn("gcOrphanPins: failed to list dispatchers", "error", err)
		return removed
	}

	dbDispatcherSet := make(map[string]bool)
	for _, d := range dbDispatchers {
		key := fmt.Sprintf("%s/%d/%d", d.Type, d.Nsid, d.Ifindex)
		dbDispatcherSet[key] = true
	}

	// Orphan prog_* pins in bpffs root.
	bpffsRoot := m.dirs.FS
	if entries, err := os.ReadDir(bpffsRoot); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			if !strings.HasPrefix(name, "prog_") {
				continue
			}
			pinPath := filepath.Join(bpffsRoot, name)
			if dbProgPinSet[pinPath] {
				continue
			}
			// Parse kernel ID from prog_{id}.
			var kernelID uint32
			if n, _ := fmt.Sscanf(name, "prog_%d", &kernelID); n != 1 {
				continue
			}
			if kernelProgramIDs[kernelID] {
				continue // Kernel object still alive; leave it.
			}
			m.logger.Info("removing orphan program pin", "path", pinPath)
			if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
				m.logger.Warn("failed to remove orphan program pin", "path", pinPath, "error", err)
				continue
			}
			removed++
		}
	} else if !os.IsNotExist(err) {
		m.logger.Warn("gcOrphanPins: error reading bpffs root", "path", bpffsRoot, "error", err)
	}

	// Orphan link pin directories (named by program kernel ID).
	if entries, err := os.ReadDir(m.dirs.FS_LINKS); err == nil {
		for _, entry := range entries {
			name := entry.Name()
			var progID uint32
			if n, _ := fmt.Sscanf(name, "%d", &progID); n != 1 {
				continue
			}
			if dbProgIDSet[progID] {
				continue
			}
			if kernelProgramIDs[progID] {
				continue
			}
			dirPath := filepath.Join(m.dirs.FS_LINKS, name)
			m.logger.Info("removing orphan link pin directory", "path", dirPath)
			if err := os.RemoveAll(dirPath); err != nil && !os.IsNotExist(err) {
				m.logger.Warn("failed to remove orphan link pin directory", "path", dirPath, "error", err)
				continue
			}
			removed++
		}
	} else if !os.IsNotExist(err) {
		m.logger.Warn("gcOrphanPins: error reading links directory", "path", m.dirs.FS_LINKS, "error", err)
	}

	// Orphan map pin directories (named by program kernel ID).
	if entries, err := os.ReadDir(m.dirs.FS_MAPS); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			var progID uint32
			if n, _ := fmt.Sscanf(name, "%d", &progID); n != 1 {
				continue
			}
			if dbProgIDSet[progID] {
				continue
			}
			if kernelProgramIDs[progID] {
				continue
			}
			dirPath := filepath.Join(m.dirs.FS_MAPS, name)
			m.logger.Info("removing orphan map pin directory", "path", dirPath)
			if err := os.RemoveAll(dirPath); err != nil && !os.IsNotExist(err) {
				m.logger.Warn("failed to remove orphan map pin directory", "path", dirPath, "error", err)
				continue
			}
			removed++
		}
	} else if !os.IsNotExist(err) {
		m.logger.Warn("gcOrphanPins: error reading maps directory", "path", m.dirs.FS_MAPS, "error", err)
	}

	// Orphan dispatcher revision directories.
	dispTypes := []dispatcher.DispatcherType{
		dispatcher.DispatcherTypeXDP,
		dispatcher.DispatcherTypeTCIngress,
		dispatcher.DispatcherTypeTCEgress,
	}

	for _, dt := range dispTypes {
		typeDir := dispatcher.TypeDir(bpffsRoot, dt)
		entries, err := os.ReadDir(typeDir)
		if err != nil {
			if !os.IsNotExist(err) {
				m.logger.Warn("gcOrphanPins: error reading dispatcher directory", "path", typeDir, "error", err)
			}
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasPrefix(name, "dispatcher_") {
				continue
			}
			var nsid uint64
			var ifindex, revision uint32
			if n, _ := fmt.Sscanf(name, "dispatcher_%d_%d_%d", &nsid, &ifindex, &revision); n != 3 {
				continue
			}
			key := fmt.Sprintf("%s/%d/%d", dt, nsid, ifindex)
			if dbDispatcherSet[key] {
				continue
			}
			dirPath := filepath.Join(typeDir, name)
			m.logger.Info("removing orphan dispatcher directory", "path", dirPath)
			if err := os.RemoveAll(dirPath); err != nil && !os.IsNotExist(err) {
				m.logger.Warn("failed to remove orphan dispatcher directory", "path", dirPath, "error", err)
				continue
			}
			removed++
		}
		// Also check for orphan dispatcher link pins (non-directory files).
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasPrefix(name, "dispatcher_") || !strings.HasSuffix(name, "_link") {
				continue
			}
			// Parse dispatcher_{nsid}_{ifindex}_link
			var nsid uint64
			var ifindex uint32
			if n, _ := fmt.Sscanf(name, "dispatcher_%d_%d_link", &nsid, &ifindex); n != 2 {
				continue
			}
			key := fmt.Sprintf("%s/%d/%d", dt, nsid, ifindex)
			if dbDispatcherSet[key] {
				continue
			}
			pinPath := filepath.Join(typeDir, name)
			m.logger.Info("removing orphan dispatcher link pin", "path", pinPath)
			if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
				m.logger.Warn("failed to remove orphan dispatcher link pin", "path", pinPath, "error", err)
				continue
			}
			removed++
		}
	}

	return removed
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
