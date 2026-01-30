package manager

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/action"
	"github.com/frobware/go-bpfman/interpreter"
)

// LoadOpts contains optional metadata for a Load operation.
type LoadOpts struct {
	UserMetadata map[string]string
	Owner        string
}

// Load loads a BPF program and stores its metadata atomically.
//
// See package documentation for details on the atomic load model.
//
// spec.PinPath is the bpffs root (e.g., /run/bpfman/fs/). Actual pin paths
// are computed from the kernel ID following the upstream convention:
//   - Program: <root>/prog_<kernel_id>
//   - Maps: <root>/maps/<kernel_id>/<map_name>
//
// On failure, previously completed steps are rolled back:
//   - If kernel load fails: nothing to clean up
//   - If DB persist fails: unpin program and maps from kernel
func (m *Manager) Load(ctx context.Context, spec bpfman.LoadSpec, opts LoadOpts) (bpfman.ManagedProgram, error) {
	now := time.Now()

	// Phase 1: Load into kernel and pin to bpffs
	// Pin paths are computed from kernel ID by the kernel layer
	loaded, err := m.kernel.Load(ctx, spec)
	if err != nil {
		return bpfman.ManagedProgram{}, fmt.Errorf("load program %s: %w", spec.ProgramName(), err)
	}
	m.logger.InfoContext(ctx, "loaded program",
		"name", spec.ProgramName(),
		"kernel_id", loaded.Kernel.ID,
		"prog_pin", loaded.Managed.PinPath,
		"maps_dir", loaded.Managed.PinDir)

	// ROLLBACK: If the store write fails, unpin program and maps.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.UnloadProgram(ctx, loaded.Managed.PinPath, loaded.Managed.PinDir)
	})

	// Phase 2: Persist metadata to DB (single transaction)
	// Use the inferred type from the kernel layer (from ELF section name)
	// rather than the user-specified type.
	//
	// Convert MapOwnerID: 0 means self/no owner (nil), non-zero is a pointer.
	var mapOwnerID *uint32
	if ownerID := spec.MapOwnerID(); ownerID != 0 {
		mapOwnerID = &ownerID
	}

	metadata := bpfman.ProgramSpec{
		KernelID: loaded.Kernel.ID,
		Load: bpfman.ProgramLoadSpec{
			ProgramType:   loaded.Managed.Type,
			ObjectPath:    spec.ObjectPath(),
			ImageSource:   spec.ImageSource(),
			AttachFunc:    spec.AttachFunc(),
			GlobalData:    spec.GlobalData(),
			GPLCompatible: bpfman.ExtractGPLCompatible(loaded.Kernel),
		},
		Handles: bpfman.ProgramHandles{
			PinPath:    loaded.Managed.PinPath,
			MapPinPath: loaded.Managed.PinDir, // Maps directory for CSI/unload
			MapOwnerID: mapOwnerID,
		},
		Meta: bpfman.ProgramMeta{
			Name:     spec.ProgramName(),
			Owner:    opts.Owner,
			Metadata: opts.UserMetadata,
		},
		CreatedAt: now,
	}

	// Save atomically persists program metadata. RunInTransaction ensures
	// the upsert, tag updates, and metadata index updates all commit or
	// roll back together.
	err = m.store.RunInTransaction(ctx, func(txStore interpreter.Store) error {
		return txStore.Save(ctx, loaded.Kernel.ID, metadata)
	})
	if err != nil {
		m.logger.ErrorContext(ctx, "persist failed, rolling back", "kernel_id", loaded.Kernel.ID, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return bpfman.ManagedProgram{}, errors.Join(
				fmt.Errorf("persist metadata: %w", err),
				fmt.Errorf("rollback failed: %w", rbErr),
			)
		}
		return bpfman.ManagedProgram{}, fmt.Errorf("persist metadata: %w", err)
	}

	return loaded, nil
}

// Unload removes a BPF program, its links, and metadata.
//
// Pattern: FETCH -> COMPUTE -> EXECUTE
func (m *Manager) Unload(ctx context.Context, kernelID uint32) error {
	// FETCH: Get metadata and links (for link cleanup)
	_, err := m.store.Get(ctx, kernelID)
	if err != nil {
		return fmt.Errorf("program %d: %w", kernelID, err)
	}

	// FETCH: Check for dependent programs (map sharing)
	// Programs that share maps with this program must be unloaded first.
	depCount, err := m.store.CountDependentPrograms(ctx, kernelID)
	if err != nil {
		return fmt.Errorf("check dependent programs for %d: %w", kernelID, err)
	}
	if depCount > 0 {
		return fmt.Errorf("cannot unload program %d: %d dependent program(s) share its maps; unload dependents first", kernelID, depCount)
	}

	links, err := m.store.ListLinksByProgram(ctx, kernelID)
	if err != nil {
		return fmt.Errorf("list links for program %d: %w", kernelID, err)
	}

	// FETCH: Collect dispatcher keys for any TC/XDP links before
	// the unload actions delete them from the store. We need these
	// to check whether the dispatchers are now empty afterwards.
	dispatcherKeys := m.collectDispatcherKeys(ctx, links)

	// COMPUTE: Build paths from convention (kernel ID + bpffs root)
	progPinPath := m.dirs.ProgPinPath(kernelID)
	mapsDir := filepath.Join(m.dirs.FS, "maps", fmt.Sprintf("%d", kernelID))
	linksDir := m.dirs.LinkPinDir(kernelID)

	// COMPUTE: Build unload actions
	actions := computeUnloadActions(kernelID, progPinPath, mapsDir, linksDir, links)

	m.logger.InfoContext(ctx, "unloading program", "kernel_id", kernelID, "links", len(links))

	// EXECUTE: Run all actions
	if err := m.executor.ExecuteAll(ctx, actions); err != nil {
		return fmt.Errorf("execute unload actions: %w", err)
	}

	// Clean up any dispatchers left empty by the link removal.
	m.cleanupEmptyDispatchers(ctx, dispatcherKeys)

	m.logger.InfoContext(ctx, "unloaded program", "kernel_id", kernelID)
	return nil
}

// computeUnloadActions is a pure function that computes the actions needed
// to unload a program and its associated links.
//
// Action order:
// 1. DetachLink for each link
// 2. UnloadProgram (program pin)
// 3. UnloadProgram (maps directory)
// 4. DeleteProgram
func computeUnloadActions(kernelID uint32, progPinPath, mapsDir, linksDir string, links []bpfman.LinkRecord) []action.Action {
	var actions []action.Action

	// Detach links first, then remove the links directory.
	for _, link := range links {
		if link.PinPath != "" {
			actions = append(actions, action.DetachLink{PinPath: link.PinPath})
		}
	}
	actions = append(actions, action.RemovePin{Path: linksDir})

	// Unload program pin and maps directory, then delete metadata
	actions = append(actions,
		action.UnloadProgram{PinPath: progPinPath},
		action.UnloadProgram{PinPath: mapsDir},
		action.DeleteProgram{KernelID: kernelID},
	)

	return actions
}
