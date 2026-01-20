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
// distributed transaction system. Instead, we use a DB-first reservation
// pattern that makes failure states safe and recoverable.
//
// # DB-First Reservation Pattern
//
// bpffs does not support mkdir - directories are only created implicitly
// when BPF objects are pinned. This means we cannot use a temp directory
// and rename approach. Instead, we use database reservations:
//
// Workflow:
//  1. Write reservation row (state=loading) with UUID
//  2. Load collection and pin to final path directly
//  3. Commit reservation (state=loaded) with kernel ID
//  4. If pinning fails: delete reservation
//  5. If commit fails: unpin + mark error (or delete reservation)
//
// The reservation pattern ensures:
//   - Normal List/Get only returns state=loaded programs
//   - Loading programs are invisible to normal operations
//   - Reconcile can clean up stale loading/error reservations
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
// See package documentation for details on the DB-first reservation pattern.
//
// IMPORTANT: spec.PinPath must be on bpffs (typically /sys/fs/bpf/...).
// bpffs does not support mkdir - directories are created implicitly when
// BPF objects are pinned.
//
// On any failure, previously completed steps are rolled back:
//   - If pinning fails: delete reservation
//   - If commit fails: unpin + mark error (or delete reservation)
func (m *Manager) Load(ctx context.Context, spec domain.LoadSpec, opts LoadOpts) (domain.LoadedProgram, error) {
	now := time.Now()

	// Phase 1: Write reservation (state=loading)
	metadata := domain.ProgramMetadata{
		LoadSpec:     spec,
		UUID:         opts.UUID,
		UserMetadata: opts.UserMetadata,
		Tags:         nil,
		Owner:        opts.Owner,
		CreatedAt:    now,
		State:        domain.StateLoading,
		UpdatedAt:    now,
	}

	if err := m.store.Reserve(ctx, opts.UUID, metadata); err != nil {
		return domain.LoadedProgram{}, fmt.Errorf("create reservation: %w", err)
	}

	// Track whether pinning succeeded for cleanup
	pinned := false
	defer func() {
		if pinned {
			return
		}
		// Pinning failed or we're returning early - delete reservation
		_ = m.store.DeleteReservation(ctx, opts.UUID)
	}()

	// Phase 2: Load and pin to final path directly
	loaded, err := m.kernel.Load(ctx, spec)
	if err != nil {
		return domain.LoadedProgram{}, fmt.Errorf("load program %s: %w", spec.ProgramName, err)
	}
	pinned = true

	// Phase 3: Commit reservation (state=loaded)
	if err := m.store.CommitReservation(ctx, opts.UUID, loaded.ID); err != nil {
		// Commit failed - unpin and mark error
		rbErr := m.kernel.Unload(ctx, spec.PinPath)
		if rbErr == nil {
			// Rollback succeeded - delete reservation
			_ = m.store.DeleteReservation(ctx, opts.UUID)
			return domain.LoadedProgram{}, fmt.Errorf("commit reservation: %w", err)
		}
		// Rollback also failed - mark as error for reconciliation
		_ = m.store.MarkError(ctx, opts.UUID, fmt.Sprintf("commit failed: %v; rollback failed: %v", err, rbErr))
		return domain.LoadedProgram{}, errors.Join(
			fmt.Errorf("commit reservation: %w", err),
			fmt.Errorf("rollback pins at %q failed: %w", spec.PinPath, rbErr),
		)
	}

	// Update returned program with complete info
	loaded.UUID = opts.UUID
	loaded.PinPath = filepath.Join(spec.PinPath, spec.ProgramName)
	loaded.PinDir = spec.PinPath
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

// Get retrieves a managed program by its kernel ID.
func (m *Manager) Get(ctx context.Context, kernelID uint32) (domain.ProgramMetadata, error) {
	return m.store.Get(ctx, kernelID)
}

// AttachTracepoint attaches a pinned program to a tracepoint.
func (m *Manager) AttachTracepoint(progPinPath, group, name, linkPinPath string) (*domain.AttachedLink, error) {
	return m.kernel.AttachTracepoint(progPinPath, group, name, linkPinPath)
}
