// Package manager provides high-level orchestration using
// the fetch/compute/execute pattern.
package manager

import (
	"context"
	"errors"
	"time"

	"github.com/frobware/bpffs-csi-driver/bpfman/compute"
	"github.com/frobware/bpffs-csi-driver/bpfman/domain"
	"github.com/frobware/bpffs-csi-driver/bpfman/interpreter"
	"github.com/frobware/bpffs-csi-driver/bpfman/interpreter/store"
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

// Load loads a BPF program and stores its metadata.
func (m *Manager) Load(ctx context.Context, spec domain.LoadSpec, owner string) (domain.LoadedProgram, error) {
	// EXECUTE - load program into kernel
	loaded, err := m.kernel.Load(ctx, spec)
	if err != nil {
		return domain.LoadedProgram{}, err
	}

	// COMPUTE - create metadata (pure)
	metadata := domain.ProgramMetadata{
		LoadSpec:  spec,
		Tags:      nil,
		Owner:     owner,
		CreatedAt: time.Now(),
	}

	// EXECUTE - save metadata to store
	if err := m.store.Save(ctx, loaded.ID, metadata); err != nil {
		// Best effort - program is loaded but metadata save failed
		return loaded, err
	}

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
