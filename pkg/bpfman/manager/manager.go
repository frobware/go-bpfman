// Package manager provides high-level orchestration using
// the fetch/compute/execute pattern.
//
// # Transactional Load
//
// The Manager provides transactional semantics for loading BPF programs.
// The goal is to ensure that either a program is fully loaded with its
// metadata persisted, or nothing is left behind (no partial state).
//
// The transaction boundary spans two state stores:
//   - bpffs pins (filesystem objects in /sys/fs/bpf)
//   - SQLite metadata (database row)
//
// True atomic commits across both stores are not possible without a
// distributed transaction system. Instead, we make failure states safe
// and recoverable:
//   - No partial pins visible at the final path
//   - Metadata only written once pins are committed
//   - If metadata write fails, pins are rolled back (strict rollback)
//
// # Two-Phase Commit for Pins
//
// Load uses a two-phase commit with a temporary directory:
//
//	temp:  /sys/fs/bpf/bpfman/.tmp/<uuid>-<nonce>
//	final: /sys/fs/bpf/bpfman/<uuid>
//
// The temp directory MUST be on the same filesystem as the final directory
// for rename() to be atomic. Both directories are on bpffs.
//
// Workflow:
//  1. Create temp directory
//  2. Load collection and pin program/maps to temp
//  3. Validate (get program info, map IDs)
//  4. Atomic commit: rename(temp, final)
//  5. Persist metadata to SQLite
//  6. If step 5 fails: rollback by removing final directory
//
// # CSI Integration
//
// The CSI driver is a consumer of loaded programs, not part of the
// transaction. It creates per-pod views of maps via re-pinning:
//
//	canonical: /sys/fs/bpf/bpfman/<uuid>/<map>     (managed by bpfman)
//	per-pod:   /run/bpfman/csi/fs/<vol>/<map>      (per-pod bpffs mount)
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/frobware/go-bpfman/pkg/bpfman/compute"
	"github.com/frobware/go-bpfman/pkg/bpfman/domain"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store"
)

// Manager orchestrates BPF program management using fetch/compute/execute.
type Manager struct {
	store    interpreter.ProgramStore
	kernel   interpreter.KernelOperations
	executor *interpreter.Executor
}

// New creates a new Manager.
func New(store interpreter.ProgramStore, kernel interpreter.KernelOperations) *Manager {
	return &Manager{
		store:    store,
		kernel:   kernel,
		executor: interpreter.NewExecutor(store, kernel),
	}
}

// LoadOpts contains optional metadata for a Load operation.
type LoadOpts struct {
	UUID         string
	UserMetadata map[string]string
	Owner        string
}

// Load loads a BPF program and stores its metadata transactionally.
//
// See package documentation for details on the two-phase commit design.
//
// IMPORTANT: spec.PinPath must be on bpffs (typically /sys/fs/bpf/...).
// The temp directory is created alongside PinPath and must be on the
// same filesystem for atomic rename. Do not use paths on tmpfs or other
// filesystems.
//
// On any failure, previously completed steps are rolled back. If metadata
// persistence fails after pins are committed, the pins are removed
// (strict rollback) to avoid unmanaged programs.
func (m *Manager) Load(ctx context.Context, spec domain.LoadSpec, opts LoadOpts) (domain.LoadedProgram, error) {
	finalDir := spec.PinPath

	// Phase 1: Create temp directory (same filesystem for atomic rename)
	tmpDir, err := mkTempPinDir(finalDir)
	if err != nil {
		return domain.LoadedProgram{}, err
	}

	// Track whether we've committed the temp dir to final location.
	// If not committed by the time we return, clean up temp pins.
	tmpCommitted := false
	defer func() {
		if tmpCommitted {
			return
		}
		// Best-effort cleanup of temp pins. Ignore error here:
		// the main error return already captures the failure cause.
		_ = m.kernel.Unload(ctx, tmpDir)
	}()

	// Phase 2: Load and pin to temp directory
	tmpSpec := spec
	tmpSpec.PinPath = tmpDir

	loaded, err := m.kernel.Load(ctx, tmpSpec)
	if err != nil {
		return domain.LoadedProgram{}, err
	}

	// Phase 3: Atomic commit - rename temp to final
	if err := os.MkdirAll(filepath.Dir(finalDir), 0755); err != nil {
		return domain.LoadedProgram{}, fmt.Errorf("create final pin parent: %w", err)
	}

	if err := os.Rename(tmpDir, finalDir); err != nil {
		// Pins remain in tmpDir; deferred cleanup will remove them
		return domain.LoadedProgram{}, fmt.Errorf("commit pins: %w", err)
	}
	tmpCommitted = true

	// Phase 4: Persist metadata (only after pins are committed)
	metadata := domain.ProgramMetadata{
		LoadSpec:     spec, // Use original spec with final pin path
		UUID:         opts.UUID,
		UserMetadata: opts.UserMetadata,
		Tags:         nil,
		Owner:        opts.Owner,
		CreatedAt:    time.Now(),
	}

	if err := m.store.Save(ctx, loaded.ID, metadata); err != nil {
		// Strict rollback: remove committed pins to avoid unmanaged programs
		rbErr := m.kernel.Unload(ctx, finalDir)
		if rbErr == nil {
			return domain.LoadedProgram{}, fmt.Errorf("persist metadata: %w", err)
		}
		// Rollback also failed - return compound error
		return domain.LoadedProgram{}, errors.Join(
			fmt.Errorf("persist metadata: %w", err),
			fmt.Errorf("rollback pins at %q failed: %w", finalDir, rbErr),
		)
	}

	// Update returned program with final pin path
	loaded.PinPath = filepath.Join(finalDir, spec.ProgramName)
	return loaded, nil
}

// Unload removes a BPF program and its metadata.
func (m *Manager) Unload(ctx context.Context, kernelID uint32) error {
	// FETCH - get metadata to find pin path
	metadata, err := m.store.Get(ctx, kernelID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}

	// If we have metadata, use it to unload from kernel
	if err == nil {
		if err := m.kernel.Unload(ctx, metadata.LoadSpec.PinPath); err != nil {
			return err
		}
	}

	// EXECUTE - remove from store
	return m.store.Delete(ctx, kernelID)
}

// List returns all managed programs with their kernel info.
func (m *Manager) List(ctx context.Context) ([]ManagedProgram, error) {
	// FETCH - get store and kernel data
	stored, err := m.store.List(ctx)
	if err != nil {
		return nil, err
	}

	var kernelPrograms []domain.KernelProgram
	for kp, err := range m.kernel.Programs(ctx) {
		if err != nil {
			continue // Skip programs we can't read
		}
		kernelPrograms = append(kernelPrograms, kp)
	}

	// COMPUTE - join data (pure)
	return joinManagedPrograms(stored, kernelPrograms), nil
}

// Reconcile cleans up orphaned store entries.
func (m *Manager) Reconcile(ctx context.Context) error {
	// FETCH
	stored, err := m.store.List(ctx)
	if err != nil {
		return err
	}

	var kernelPrograms []domain.KernelProgram
	for kp, err := range m.kernel.Programs(ctx) {
		if err != nil {
			continue
		}
		kernelPrograms = append(kernelPrograms, kp)
	}

	// COMPUTE - determine actions (pure)
	actions := compute.ReconcileActions(stored, kernelPrograms)

	// EXECUTE - apply actions
	return m.executor.ExecuteAll(ctx, actions)
}

// ManagedProgram combines kernel and metadata info.
type ManagedProgram struct {
	KernelProgram domain.KernelProgram
	Metadata      *domain.ProgramMetadata // nil if not managed by bpfman
}

// joinManagedPrograms is a pure function that joins kernel and store data.
func joinManagedPrograms(
	stored map[uint32]domain.ProgramMetadata,
	kernel []domain.KernelProgram,
) []ManagedProgram {
	result := make([]ManagedProgram, 0, len(kernel))

	for _, kp := range kernel {
		mp := ManagedProgram{
			KernelProgram: kp,
		}
		if metadata, ok := stored[kp.ID]; ok {
			mp.Metadata = &metadata
		}
		result = append(result, mp)
	}

	return result
}

// FilterManaged returns only managed programs.
func FilterManaged(programs []ManagedProgram) []ManagedProgram {
	var result []ManagedProgram
	for _, p := range programs {
		if p.Metadata != nil {
			result = append(result, p)
		}
	}
	return result
}

// FilterUnmanaged returns only unmanaged programs.
func FilterUnmanaged(programs []ManagedProgram) []ManagedProgram {
	var result []ManagedProgram
	for _, p := range programs {
		if p.Metadata == nil {
			result = append(result, p)
		}
	}
	return result
}

// mkTempPinDir creates a temporary directory alongside the final pin directory.
// This ensures the temp and final directories are on the same filesystem,
// allowing atomic rename during commit.
func mkTempPinDir(finalDir string) (string, error) {
	parent := filepath.Dir(finalDir)
	tmpRoot := filepath.Join(parent, ".tmp")

	if err := os.MkdirAll(tmpRoot, 0755); err != nil {
		return "", fmt.Errorf("create temp pin root: %w", err)
	}

	// Use final dir name as prefix for easier debugging
	prefix := filepath.Base(finalDir) + "-"

	tmpDir, err := os.MkdirTemp(tmpRoot, prefix)
	if err != nil {
		return "", fmt.Errorf("create temp pin dir: %w", err)
	}

	return tmpDir, nil
}
