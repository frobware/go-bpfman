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
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/action"
	"github.com/frobware/go-bpfman/config"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/kernel"
	"github.com/frobware/go-bpfman/netns"
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
	m.logger.Info("loaded program",
		"name", spec.ProgramName(),
		"kernel_id", loaded.Kernel.ID(),
		"prog_pin", loaded.Managed.PinPath,
		"maps_dir", loaded.Managed.PinDir)

	// Phase 2: Persist metadata to DB (single transaction)
	// Use the inferred type from the kernel layer (from ELF section name)
	// rather than the user-specified type.
	metadata := bpfman.Program{
		ProgramName:  spec.ProgramName(),
		ProgramType:  loaded.Managed.Type,
		ObjectPath:   spec.ObjectPath(),
		PinPath:      loaded.Managed.PinPath,
		MapPinPath:   loaded.Managed.PinDir, // Maps directory for CSI/unload
		GlobalData:   spec.GlobalData(),
		ImageSource:  spec.ImageSource(),
		AttachFunc:   spec.AttachFunc(),
		MapOwnerID:   spec.MapOwnerID(),
		UserMetadata: opts.UserMetadata,
		Tags:         nil,
		Owner:        opts.Owner,
		CreatedAt:    now,
	}

	if err := m.store.Save(ctx, loaded.Kernel.ID(), metadata); err != nil {
		m.logger.Error("persist failed, rolling back", "kernel_id", loaded.Kernel.ID(), "error", err)
		// Cleanup kernel state using the upstream layout
		if rbErr := m.kernel.UnloadProgram(ctx, loaded.Managed.PinPath, loaded.Managed.PinDir); rbErr != nil {
			m.logger.Error("rollback failed", "kernel_id", loaded.Kernel.ID(), "error", rbErr)
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

	// COMPUTE: Build paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", kernelID))
	mapsDir := filepath.Join(m.dirs.FS, "maps", fmt.Sprintf("%d", kernelID))

	// COMPUTE: Build unload actions
	actions := computeUnloadActions(kernelID, progPinPath, mapsDir, links)

	m.logger.Info("unloading program", "kernel_id", kernelID, "links", len(links))

	// EXECUTE: Run all actions
	if err := m.executor.ExecuteAll(ctx, actions); err != nil {
		return fmt.Errorf("execute unload actions: %w", err)
	}

	m.logger.Info("unloaded program", "kernel_id", kernelID)
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
func computeUnloadActions(kernelID uint32, progPinPath, mapsDir string, links []bpfman.LinkSummary) []action.Action {
	var actions []action.Action

	// Detach links first
	for _, link := range links {
		if link.PinPath != "" {
			actions = append(actions, action.DetachLink{PinPath: link.PinPath})
		}
	}

	// Unload program pin and maps directory, then delete metadata
	actions = append(actions,
		action.UnloadProgram{PinPath: progPinPath},
		action.UnloadProgram{PinPath: mapsDir},
		action.DeleteProgram{KernelID: kernelID},
	)

	return actions
}

// List returns all managed programs with their kernel info.
func (m *Manager) List(ctx context.Context) ([]ManagedProgram, error) {
	// FETCH - get store and kernel data
	stored, err := m.store.List(ctx)
	if err != nil {
		return nil, err
	}

	var kernelPrograms []kernel.Program
	for kp, err := range m.kernel.Programs(ctx) {
		if err != nil {
			continue // Skip programs we can't read
		}
		kernelPrograms = append(kernelPrograms, kp)
	}

	// COMPUTE - join data (pure)
	return joinManagedPrograms(stored, kernelPrograms), nil
}

// ManagedProgram combines kernel and metadata info.
type ManagedProgram struct {
	KernelProgram kernel.Program  `json:"kernel"`
	Metadata      *bpfman.Program `json:"metadata,omitempty"`
}

// ProgramInfo is the complete view of a managed program.
type ProgramInfo struct {
	Kernel *KernelInfo `json:"kernel,omitempty"`
	Bpfman *BpfmanInfo `json:"bpfman,omitempty"`
}

// KernelInfo contains live kernel state.
type KernelInfo struct {
	Program *kernel.Program `json:"program,omitempty"`
	Links   []kernel.Link   `json:"links,omitempty"`
	Maps    []kernel.Map    `json:"maps,omitempty"`
}

// BpfmanInfo contains managed metadata.
type BpfmanInfo struct {
	Program *bpfman.Program   `json:"program,omitempty"`
	Links   []LinkWithDetails `json:"links,omitempty"`
}

// LinkWithDetails combines a link summary with its type-specific details.
type LinkWithDetails struct {
	Summary bpfman.LinkSummary `json:"summary"`
	Details bpfman.LinkDetails `json:"details"`
}

// joinManagedPrograms is a pure function that joins kernel and store data.
func joinManagedPrograms(
	stored map[uint32]bpfman.Program,
	kps []kernel.Program,
) []ManagedProgram {
	result := make([]ManagedProgram, 0, len(kps))

	for _, kp := range kps {
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
// Returns both the stored metadata and the live kernel state, including
// associated links and maps from both the kernel and the store.
// Returns an error if the program exists in the store but not in the kernel,
// as this indicates an inconsistent state that requires reconciliation.
func (m *Manager) Get(ctx context.Context, kernelID uint32) (ProgramInfo, error) {
	// Fetch program from store
	metadata, err := m.store.Get(ctx, kernelID)
	if err != nil {
		return ProgramInfo{}, err
	}

	// Fetch program from kernel
	kp, err := m.kernel.GetProgramByID(ctx, kernelID)
	if err != nil {
		return ProgramInfo{}, fmt.Errorf("program %d exists in store but not in kernel (requires reconciliation): %w", kernelID, err)
	}

	// Fetch links from store (summaries only)
	storedLinks, err := m.store.ListLinksByProgram(ctx, kernelID)
	if err != nil {
		return ProgramInfo{}, fmt.Errorf("list links: %w", err)
	}

	// Fetch each link's details and kernel info
	var kernelLinks []kernel.Link
	var linksWithDetails []LinkWithDetails
	for _, sl := range storedLinks {
		// Fetch details for this link
		_, details, err := m.store.GetLink(ctx, sl.KernelLinkID)
		if err != nil {
			m.logger.Warn("failed to get link details", "kernel_link_id", sl.KernelLinkID, "error", err)
			// Include summary only with nil details
			linksWithDetails = append(linksWithDetails, LinkWithDetails{
				Summary: sl,
				Details: nil,
			})
		} else {
			linksWithDetails = append(linksWithDetails, LinkWithDetails{
				Summary: sl,
				Details: details,
			})
		}

		// Fetch from kernel if we have a kernel link ID
		if sl.KernelLinkID == 0 {
			continue // Link not pinned or no kernel ID
		}
		kl, err := m.kernel.GetLinkByID(ctx, sl.KernelLinkID)
		if err != nil {
			// Link exists in store but not kernel - skip
			continue
		}
		kernelLinks = append(kernelLinks, kl)
	}

	// Fetch each map from kernel using the program's map IDs
	var kernelMaps []kernel.Map
	for _, mapID := range kp.MapIDs {
		km, err := m.kernel.GetMapByID(ctx, mapID)
		if err != nil {
			// Map exists in program but not accessible - skip
			continue
		}
		kernelMaps = append(kernelMaps, km)
	}

	return ProgramInfo{
		Kernel: &KernelInfo{
			Program: &kp,
			Links:   kernelLinks,
			Maps:    kernelMaps,
		},
		Bpfman: &BpfmanInfo{
			Program: &metadata,
			Links:   linksWithDetails,
		},
	}, nil
}

// AttachTracepoint attaches a pinned program to a tracepoint.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachTracepoint(ctx context.Context, spec bpfman.TracepointAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	group := spec.Group()
	name := spec.Name()
	linkPinPath := opts.LinkPinPath

	// FETCH: Verify program exists in store
	_, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := fmt.Sprintf("%s_%s", group, name)
		linksDir := filepath.Join(m.dirs.FS, "links", fmt.Sprintf("%d", programKernelID))
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel (returns ManagedLink with full info)
	link, err := m.kernel.AttachTracepoint(progPinPath, group, name, linkPinPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach tracepoint %s/%s: %w", group, name, err)
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachTracepointAction(programKernelID, link.Kernel.ID(), link.Managed.PinPath, group, name)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.Info("attached tracepoint",
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"tracepoint", group+"/"+name,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachTracepointAction is a pure function that builds the save action
// for a tracepoint attachment.
func computeAttachTracepointAction(programKernelID, kernelLinkID uint32, pinPath, group, name string) action.SaveTracepointLink {
	return action.SaveTracepointLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        bpfman.LinkTypeTracepoint,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.TracepointDetails{
			Group: group,
			Name:  name,
		},
	}
}

// AttachKprobe attaches a pinned program to a kernel function.
// retprobe is derived from the program type stored in the database.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachKprobe(ctx context.Context, spec bpfman.KprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	fnName := spec.FnName()
	offset := spec.Offset()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program to determine if it's a kretprobe
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// Derive retprobe from program type
	retprobe := prog.ProgramType == bpfman.ProgramTypeKretprobe

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := fnName
		if retprobe {
			linkName = "ret_" + linkName
		}
		linksDir := filepath.Join(m.dirs.FS, "links", fmt.Sprintf("%d", programKernelID))
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel (returns ManagedLink with full info)
	link, err := m.kernel.AttachKprobe(progPinPath, fnName, offset, retprobe, linkPinPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach kprobe %s: %w", fnName, err)
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachKprobeAction(programKernelID, link.Kernel.ID(), link.Managed.PinPath, fnName, offset, retprobe)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	probeType := "kprobe"
	if retprobe {
		probeType = "kretprobe"
	}
	m.logger.Info("attached "+probeType,
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"fn_name", fnName,
		"offset", offset,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachKprobeAction is a pure function that builds the save action
// for a kprobe/kretprobe attachment.
func computeAttachKprobeAction(programKernelID, kernelLinkID uint32, pinPath, fnName string, offset uint64, retprobe bool) action.SaveKprobeLink {
	linkType := bpfman.LinkTypeKprobe
	if retprobe {
		linkType = bpfman.LinkTypeKretprobe
	}
	return action.SaveKprobeLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        linkType,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.KprobeDetails{
			FnName:   fnName,
			Offset:   offset,
			Retprobe: retprobe,
		},
	}
}

// AttachUprobe attaches a pinned program to a user-space function.
// retprobe is derived from the program type stored in the database.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachUprobe(ctx context.Context, spec bpfman.UprobeAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	target := spec.Target()
	fnName := spec.FnName()
	offset := spec.Offset()
	containerPid := spec.ContainerPid()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program to determine if it's a uretprobe
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// Derive retprobe from program type
	retprobe := prog.ProgramType == bpfman.ProgramTypeUretprobe

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := fnName
		if retprobe {
			linkName = "ret_" + linkName
		}
		linksDir := filepath.Join(m.dirs.FS, "links", fmt.Sprintf("%d", programKernelID))
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel (returns ManagedLink with full info)
	link, err := m.kernel.AttachUprobe(progPinPath, target, fnName, offset, retprobe, linkPinPath, containerPid)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach uprobe %s to %s: %w", fnName, target, err)
	}

	// Get kernel link ID (0 for perf_event-based links which have no kernel link)
	var kernelLinkID uint32
	if link.Kernel != nil {
		kernelLinkID = link.Kernel.ID()
	} else {
		kernelLinkID = link.Managed.KernelLinkID
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachUprobeAction(programKernelID, kernelLinkID, link.Managed.PinPath, target, fnName, offset, retprobe, containerPid)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	probeType := "uprobe"
	if retprobe {
		probeType = "uretprobe"
	}
	m.logger.Info("attached "+probeType,
		"kernel_link_id", kernelLinkID,
		"program_id", programKernelID,
		"target", target,
		"fn_name", fnName,
		"offset", offset,
		"container_pid", containerPid,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachUprobeAction is a pure function that builds the save action
// for a uprobe/uretprobe attachment.
func computeAttachUprobeAction(programKernelID, kernelLinkID uint32, pinPath, target, fnName string, offset uint64, retprobe bool, containerPid int32) action.SaveUprobeLink {
	linkType := bpfman.LinkTypeUprobe
	if retprobe {
		linkType = bpfman.LinkTypeUretprobe
	}
	return action.SaveUprobeLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        linkType,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.UprobeDetails{
			Target:       target,
			FnName:       fnName,
			Offset:       offset,
			Retprobe:     retprobe,
			ContainerPid: containerPid,
		},
	}
}

// AttachFentry attaches a pinned fentry program to its target kernel function.
// The target function was specified at load time and stored in the program's AttachFunc.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachFentry(ctx context.Context, spec bpfman.FentryAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program metadata to access AttachFunc
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	fnName := prog.AttachFunc
	if fnName == "" {
		return bpfman.LinkSummary{}, fmt.Errorf("program %d has no attach function (fentry requires attach function at load time)", programKernelID)
	}

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := "fentry_" + fnName
		linksDir := filepath.Join(m.dirs.FS, "links", fmt.Sprintf("%d", programKernelID))
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel
	link, err := m.kernel.AttachFentry(progPinPath, fnName, linkPinPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach fentry %s: %w", fnName, err)
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachFentryAction(programKernelID, link.Kernel.ID(), link.Managed.PinPath, fnName)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.Info("attached fentry",
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"fn_name", fnName,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachFentryAction is a pure function that builds the save action
// for a fentry attachment.
func computeAttachFentryAction(programKernelID, kernelLinkID uint32, pinPath, fnName string) action.SaveFentryLink {
	return action.SaveFentryLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        bpfman.LinkTypeFentry,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.FentryDetails{
			FnName: fnName,
		},
	}
}

// AttachFexit attaches a pinned fexit program to its target kernel function.
// The target function was specified at load time and stored in the program's AttachFunc.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachFexit(ctx context.Context, spec bpfman.FexitAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program metadata to access AttachFunc
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	fnName := prog.AttachFunc
	if fnName == "" {
		return bpfman.LinkSummary{}, fmt.Errorf("program %d has no attach function (fexit requires attach function at load time)", programKernelID)
	}

	// COMPUTE: Construct paths from convention (kernel ID + bpffs root)
	progPinPath := filepath.Join(m.dirs.FS, fmt.Sprintf("prog_%d", programKernelID))

	// COMPUTE: Auto-generate link pin path if not provided
	if linkPinPath == "" {
		linkName := "fexit_" + fnName
		linksDir := filepath.Join(m.dirs.FS, "links", fmt.Sprintf("%d", programKernelID))
		linkPinPath = filepath.Join(linksDir, linkName)
	}

	// KERNEL I/O: Attach to the kernel
	link, err := m.kernel.AttachFexit(progPinPath, fnName, linkPinPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach fexit %s: %w", fnName, err)
	}

	// COMPUTE: Build save action from kernel result
	saveAction := computeAttachFexitAction(programKernelID, link.Kernel.ID(), link.Managed.PinPath, fnName)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.Info("attached fexit",
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"fn_name", fnName,
		"pin_path", link.Managed.PinPath)

	return saveAction.Summary, nil
}

// computeAttachFexitAction is a pure function that builds the save action
// for a fexit attachment.
func computeAttachFexitAction(programKernelID, kernelLinkID uint32, pinPath, fnName string) action.SaveFexitLink {
	return action.SaveFexitLink{
		Summary: bpfman.LinkSummary{
			KernelLinkID:    kernelLinkID,
			LinkType:        bpfman.LinkTypeFexit,
			KernelProgramID: programKernelID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: bpfman.FexitDetails{
			FnName: fnName,
		},
	}
}

// XDP proceed-on action bits (matches XDP return codes).
const (
	xdpProceedOnPass = 1 << 2 // Continue to next program on XDP_PASS
)

// AttachXDP attaches an XDP program to a network interface using the
// dispatcher model for multi-program chaining.
//
// The dispatcher is created automatically if it doesn't exist for the interface.
// Programs are attached as extensions (freplace) to dispatcher slots.
// The program is reloaded from its original ObjectPath as Extension type.
//
// Pin paths follow the Rust bpfman convention:
//   - Dispatcher link: /sys/fs/bpf/bpfman/xdp/dispatcher_{nsid}_{ifindex}_link
//   - Dispatcher prog: /sys/fs/bpf/bpfman/xdp/dispatcher_{nsid}_{ifindex}_{revision}/dispatcher
//   - Extension links: /sys/fs/bpf/bpfman/xdp/dispatcher_{nsid}_{ifindex}_{revision}/link_{position}
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachXDP(ctx context.Context, spec bpfman.XDPAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	ifindex := spec.Ifindex()
	ifname := spec.Ifname()
	netnsPath := spec.Netns()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program metadata to access ObjectPath and ProgramName
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// FETCH: Get network namespace ID (from target namespace if specified)
	nsid, err := netns.GetNsid(netnsPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get nsid: %w", err)
	}

	// FETCH: Look up existing dispatcher or create new one
	dispState, err := m.store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), nsid, uint32(ifindex))
	if errors.Is(err, store.ErrNotFound) {
		// KERNEL I/O + EXECUTE: Create new dispatcher
		dispState, err = m.createXDPDispatcher(ctx, nsid, uint32(ifindex), netnsPath)
		if err != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("create XDP dispatcher for %s: %w", ifname, err)
		}
	} else if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get dispatcher: %w", err)
	}

	m.logger.Debug("using dispatcher",
		"interface", ifname,
		"nsid", nsid,
		"ifindex", ifindex,
		"revision", dispState.Revision,
		"dispatcher_id", dispState.KernelID)

	// COMPUTE: Calculate extension link path
	revisionDir := dispatcher.DispatcherRevisionDir(m.dirs.FS, dispatcher.DispatcherTypeXDP, nsid, uint32(ifindex), dispState.Revision)
	position := int(dispState.NumExtensions)
	extensionLinkPath := dispatcher.ExtensionLinkPath(revisionDir, position)
	if linkPinPath == "" {
		linkPinPath = extensionLinkPath
	}

	// COMPUTE: Use the program's MapPinPath which points to the correct maps
	// directory (either the program's own or the map owner's if sharing).
	mapPinDir := prog.MapPinPath

	// KERNEL I/O: Attach user program as extension (returns ManagedLink)
	link, err := m.kernel.AttachXDPExtension(
		dispState.ProgPinPath,
		prog.ObjectPath,
		prog.ProgramName,
		position,
		linkPinPath,
		mapPinDir,
	)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach XDP extension to %s slot %d: %w", ifname, position, err)
	}

	// COMPUTE: Build save actions from kernel result
	saveActions := computeAttachXDPActions(
		programKernelID,
		link.Kernel.ID(),
		link.Managed.PinPath,
		ifname,
		uint32(ifindex),
		nsid,
		position,
		dispState,
	)

	// EXECUTE: Save dispatcher update and link metadata
	if err := m.executor.ExecuteAll(ctx, saveActions); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.Info("attached XDP via dispatcher",
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"interface", ifname,
		"ifindex", ifindex,
		"nsid", nsid,
		"position", position,
		"revision", dispState.Revision,
		"pin_path", link.Managed.PinPath)

	// Extract summary from computed action for return value
	for _, a := range saveActions {
		if saveXDP, ok := a.(action.SaveXDPLink); ok {
			return saveXDP.Summary, nil
		}
	}
	// Shouldn't happen, but return a constructed summary as fallback
	return bpfman.LinkSummary{
		KernelLinkID:    link.Kernel.ID(),
		LinkType:        bpfman.LinkTypeXDP,
		KernelProgramID: programKernelID,
		PinPath:         link.Managed.PinPath,
		CreatedAt:       time.Now(),
	}, nil
}

// computeAttachXDPActions is a pure function that builds the actions needed
// to save XDP attachment metadata (dispatcher update + link save).
func computeAttachXDPActions(
	programKernelID, kernelLinkID uint32,
	pinPath, ifname string,
	ifindex uint32,
	nsid uint64,
	position int,
	dispState dispatcher.State,
) []action.Action {
	// Update dispatcher extension count
	updatedDispState := dispState
	updatedDispState.NumExtensions++

	return []action.Action{
		action.SaveDispatcher{State: updatedDispState},
		action.SaveXDPLink{
			Summary: bpfman.LinkSummary{
				KernelLinkID:    kernelLinkID,
				LinkType:        bpfman.LinkTypeXDP,
				KernelProgramID: programKernelID,
				PinPath:         pinPath,
				CreatedAt:       time.Now(),
			},
			Details: bpfman.XDPDetails{
				Interface:    ifname,
				Ifindex:      ifindex,
				Priority:     50, // Default priority
				Position:     int32(position),
				ProceedOn:    []int32{2}, // XDP_PASS
				Nsid:         nsid,
				DispatcherID: dispState.KernelID,
				Revision:     dispState.Revision,
			},
		},
	}
}

// createXDPDispatcher creates a new XDP dispatcher for the given interface.
//
// Pattern: COMPUTE -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) createXDPDispatcher(ctx context.Context, nsid uint64, ifindex uint32, netnsPath string) (dispatcher.State, error) {
	// COMPUTE: Calculate paths according to Rust bpfman convention
	revision := uint32(1)
	linkPinPath := dispatcher.DispatcherLinkPath(m.dirs.FS, dispatcher.DispatcherTypeXDP, nsid, ifindex)
	revisionDir := dispatcher.DispatcherRevisionDir(m.dirs.FS, dispatcher.DispatcherTypeXDP, nsid, ifindex, revision)
	progPinPath := dispatcher.DispatcherProgPath(revisionDir)

	m.logger.Info("creating XDP dispatcher",
		"nsid", nsid,
		"ifindex", ifindex,
		"netns", netnsPath,
		"revision", revision,
		"prog_pin_path", progPinPath,
		"link_pin_path", linkPinPath)

	// KERNEL I/O: Create dispatcher (returns IDs)
	result, err := m.kernel.AttachXDPDispatcherWithPaths(
		int(ifindex),
		progPinPath,
		linkPinPath,
		dispatcher.MaxPrograms,
		xdpProceedOnPass,
		netnsPath,
	)
	if err != nil {
		return dispatcher.State{}, err
	}

	// COMPUTE: Build save action from kernel result
	state := computeDispatcherState(dispatcher.DispatcherTypeXDP, nsid, ifindex, revision, result, progPinPath, linkPinPath)
	saveAction := action.SaveDispatcher{State: state}

	// EXECUTE: Save through executor
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return dispatcher.State{}, fmt.Errorf("save dispatcher: %w", err)
	}

	m.logger.Info("created XDP dispatcher",
		"nsid", nsid,
		"ifindex", ifindex,
		"dispatcher_id", result.DispatcherID,
		"link_id", result.LinkID,
		"prog_pin_path", progPinPath,
		"link_pin_path", linkPinPath)

	return state, nil
}

// computeDispatcherState is a pure function that builds a DispatcherState
// from kernel attach results.
func computeDispatcherState(
	dispType dispatcher.DispatcherType,
	nsid uint64,
	ifindex, revision uint32,
	result *interpreter.XDPDispatcherResult,
	progPinPath, linkPinPath string,
) dispatcher.State {
	return dispatcher.State{
		Type:          dispType,
		Nsid:          nsid,
		Ifindex:       ifindex,
		Revision:      revision,
		KernelID:      result.DispatcherID,
		LinkID:        result.LinkID,
		LinkPinPath:   linkPinPath,
		ProgPinPath:   progPinPath,
		NumExtensions: 0,
	}
}

// TC proceed-on action bits (matches TC_ACT_* return codes).
const (
	tcProceedOnOK               = 1 << 0  // TC_ACT_OK
	tcProceedOnPipe             = 1 << 3  // TC_ACT_PIPE
	tcProceedOnDispatcherReturn = 1 << 30 // bpfman-specific sentinel
)

// DefaultTCProceedOn is the default bitmask for TC proceed-on actions.
var DefaultTCProceedOn = tcProceedOnOK | tcProceedOnPipe | tcProceedOnDispatcherReturn

// AttachTC attaches a TC program to a network interface using the
// dispatcher model for multi-program chaining.
//
// The dispatcher is created automatically if it doesn't exist for the interface
// and direction combination. Programs are attached as extensions (freplace) to
// dispatcher slots.
//
// Pin paths follow the Rust bpfman convention:
//   - Dispatcher link: /sys/fs/bpf/bpfman/tc-{direction}/dispatcher_{nsid}_{ifindex}_link
//   - Dispatcher prog: /sys/fs/bpf/bpfman/tc-{direction}/dispatcher_{nsid}_{ifindex}_{revision}/dispatcher
//   - Extension links: /sys/fs/bpf/bpfman/tc-{direction}/dispatcher_{nsid}_{ifindex}_{revision}/link_{position}
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachTC(ctx context.Context, spec bpfman.TCAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	ifindex := spec.Ifindex()
	ifname := spec.Ifname()
	direction := spec.Direction()
	priority := spec.Priority()
	proceedOn := spec.ProceedOn()
	netnsPath := spec.Netns()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program metadata to access ObjectPath and ProgramName
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// FETCH: Get network namespace ID (from target namespace if specified)
	nsid, err := netns.GetNsid(netnsPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get nsid: %w", err)
	}

	// Determine dispatcher type based on direction
	var dispType dispatcher.DispatcherType
	if direction == "ingress" {
		dispType = dispatcher.DispatcherTypeTCIngress
	} else {
		dispType = dispatcher.DispatcherTypeTCEgress
	}

	// FETCH: Look up existing dispatcher or create new one
	dispState, err := m.store.GetDispatcher(ctx, string(dispType), nsid, uint32(ifindex))
	if errors.Is(err, store.ErrNotFound) {
		// KERNEL I/O + EXECUTE: Create new dispatcher
		dispState, err = m.createTCDispatcher(ctx, nsid, uint32(ifindex), direction, dispType, netnsPath)
		if err != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("create TC dispatcher for %s %s: %w", ifname, direction, err)
		}
	} else if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get dispatcher: %w", err)
	}

	m.logger.Debug("using TC dispatcher",
		"interface", ifname,
		"direction", direction,
		"nsid", nsid,
		"ifindex", ifindex,
		"revision", dispState.Revision,
		"dispatcher_id", dispState.KernelID)

	// COMPUTE: Calculate extension link path
	revisionDir := dispatcher.DispatcherRevisionDir(m.dirs.FS, dispType, nsid, uint32(ifindex), dispState.Revision)
	position := int(dispState.NumExtensions)
	extensionLinkPath := dispatcher.ExtensionLinkPath(revisionDir, position)
	if linkPinPath == "" {
		linkPinPath = extensionLinkPath
	}

	// COMPUTE: Use the program's MapPinPath which points to the correct maps
	// directory (either the program's own or the map owner's if sharing).
	mapPinDir := prog.MapPinPath

	// KERNEL I/O: Attach user program as extension (returns ManagedLink)
	link, err := m.kernel.AttachTCExtension(
		dispState.ProgPinPath,
		prog.ObjectPath,
		prog.ProgramName,
		position,
		linkPinPath,
		mapPinDir,
	)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach TC extension to %s %s slot %d: %w", ifname, direction, position, err)
	}

	// COMPUTE: Build save actions from kernel result
	saveActions := computeAttachTCActions(
		programKernelID,
		link.Kernel.ID(),
		link.Managed.PinPath,
		ifname,
		uint32(ifindex),
		direction,
		int32(priority),
		proceedOn,
		nsid,
		position,
		dispState,
	)

	// EXECUTE: Save dispatcher update and link metadata
	if err := m.executor.ExecuteAll(ctx, saveActions); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.Info("attached TC via dispatcher",
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"interface", ifname,
		"direction", direction,
		"ifindex", ifindex,
		"nsid", nsid,
		"position", position,
		"revision", dispState.Revision,
		"pin_path", link.Managed.PinPath)

	// Extract summary from computed action for return value
	for _, a := range saveActions {
		if saveTC, ok := a.(action.SaveTCLink); ok {
			return saveTC.Summary, nil
		}
	}
	// Shouldn't happen, but return a constructed summary as fallback
	return bpfman.LinkSummary{
		KernelLinkID:    link.Kernel.ID(),
		LinkType:        bpfman.LinkTypeTC,
		KernelProgramID: programKernelID,
		PinPath:         link.Managed.PinPath,
		CreatedAt:       time.Now(),
	}, nil
}

// computeAttachTCActions is a pure function that builds the actions needed
// to save TC attachment metadata (dispatcher update + link save).
func computeAttachTCActions(
	programKernelID, kernelLinkID uint32,
	pinPath, ifname string,
	ifindex uint32,
	direction string,
	priority int32,
	proceedOn []int32,
	nsid uint64,
	position int,
	dispState dispatcher.State,
) []action.Action {
	// Update dispatcher extension count
	updatedDispState := dispState
	updatedDispState.NumExtensions++

	return []action.Action{
		action.SaveDispatcher{State: updatedDispState},
		action.SaveTCLink{
			Summary: bpfman.LinkSummary{
				KernelLinkID:    kernelLinkID,
				LinkType:        bpfman.LinkTypeTC,
				KernelProgramID: programKernelID,
				PinPath:         pinPath,
				CreatedAt:       time.Now(),
			},
			Details: bpfman.TCDetails{
				Interface:    ifname,
				Ifindex:      ifindex,
				Direction:    direction,
				Priority:     priority,
				Position:     int32(position),
				ProceedOn:    proceedOn,
				Nsid:         nsid,
				DispatcherID: dispState.KernelID,
				Revision:     dispState.Revision,
			},
		},
	}
}

// AttachTCX attaches a TCX program to a network interface using native
// kernel multi-program support. Unlike TC, TCX doesn't use dispatchers.
//
// Pin paths follow the convention:
//   - Link: /sys/fs/bpf/bpfman/tcx-{direction}/link_{nsid}_{ifindex}_{linkid}
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachTCX(ctx context.Context, spec bpfman.TCXAttachSpec, opts bpfman.AttachOpts) (bpfman.LinkSummary, error) {
	programKernelID := spec.ProgramID()
	ifindex := spec.Ifindex()
	ifname := spec.Ifname()
	direction := spec.Direction()
	priority := spec.Priority()
	netnsPath := spec.Netns()
	linkPinPath := opts.LinkPinPath

	// FETCH: Get program metadata to find pin path
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// Verify program type is TCX
	if prog.ProgramType != bpfman.ProgramTypeTCX {
		return bpfman.LinkSummary{}, fmt.Errorf("program %d is type %s, not tcx", programKernelID, prog.ProgramType)
	}

	// FETCH: Get network namespace ID (from target namespace if specified)
	nsid, err := netns.GetNsid(netnsPath)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get nsid: %w", err)
	}

	// COMPUTE: Calculate link pin path if not provided
	if linkPinPath == "" {
		// Use a path under tcx-{direction} directory
		dirName := fmt.Sprintf("tcx-%s", direction)
		linkPinPath = filepath.Join(m.dirs.FS, dirName, fmt.Sprintf("link_%d_%d", nsid, ifindex))
	}

	// COMPUTE: Use the stored program pin path directly
	progPinPath := prog.PinPath

	// FETCH: Get existing TCX links for this interface/direction to compute order
	existingLinks, err := m.store.ListTCXLinksByInterface(ctx, nsid, uint32(ifindex), direction)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("list existing TCX links: %w", err)
	}

	// COMPUTE: Determine attach order based on priority
	// Lower priority values should run first (earlier in chain).
	// We need to find where to insert this program in the priority-sorted chain.
	order := computeTCXAttachOrder(existingLinks, int32(priority))

	m.logger.Debug("computed TCX attach order",
		"program_id", programKernelID,
		"priority", priority,
		"existing_links", len(existingLinks),
		"order", order)

	// KERNEL I/O: Attach program using TCX link with computed order
	link, err := m.kernel.AttachTCX(ifindex, direction, progPinPath, linkPinPath, netnsPath, order)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("attach TCX to %s %s: %w", ifname, direction, err)
	}

	// COMPUTE: Build save action
	summary := bpfman.LinkSummary{
		KernelLinkID:    link.Kernel.ID(),
		LinkType:        bpfman.LinkTypeTCX,
		KernelProgramID: programKernelID,
		PinPath:         link.Managed.PinPath,
		CreatedAt:       time.Now(),
	}

	details := bpfman.TCXDetails{
		Interface: ifname,
		Ifindex:   uint32(ifindex),
		Direction: direction,
		Priority:  int32(priority),
		Nsid:      nsid,
	}

	saveAction := action.SaveTCXLink{
		Summary: summary,
		Details: details,
	}

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("save TCX link metadata: %w", err)
	}

	m.logger.Info("attached TCX program",
		"kernel_link_id", link.Kernel.ID(),
		"program_id", programKernelID,
		"interface", ifname,
		"direction", direction,
		"ifindex", ifindex,
		"nsid", nsid,
		"priority", priority,
		"pin_path", link.Managed.PinPath)

	return summary, nil
}

// computeTCXAttachOrder determines where to insert a new TCX program in the chain
// based on its priority relative to existing programs. Lower priority values run first.
//
// The algorithm:
// 1. If no existing links, attach at head (first)
// 2. Find the first existing link with priority > newPriority, attach before it
// 3. If all existing links have priority <= newPriority, attach after the last one
//
// This ensures programs are ordered by priority, with ties broken by insertion order.
func computeTCXAttachOrder(existingLinks []bpfman.TCXLinkInfo, newPriority int32) bpfman.TCXAttachOrder {
	if len(existingLinks) == 0 {
		// No existing links, attach at head
		return bpfman.TCXAttachFirst()
	}

	// Links are already sorted by priority ASC from the query
	// Find the first link with higher priority (should come after us)
	for _, link := range existingLinks {
		if link.Priority > newPriority {
			// This link has higher priority (runs later), we should attach before it
			return bpfman.TCXAttachBefore(link.KernelProgramID)
		}
	}

	// All existing links have priority <= ours, attach after the last one
	lastLink := existingLinks[len(existingLinks)-1]
	return bpfman.TCXAttachAfter(lastLink.KernelProgramID)
}

// createTCDispatcher creates a new TC dispatcher for the given interface and direction.
//
// Pattern: COMPUTE -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) createTCDispatcher(ctx context.Context, nsid uint64, ifindex uint32, direction string, dispType dispatcher.DispatcherType, netnsPath string) (dispatcher.State, error) {
	// COMPUTE: Calculate paths according to Rust bpfman convention
	revision := uint32(1)
	linkPinPath := dispatcher.DispatcherLinkPath(m.dirs.FS, dispType, nsid, ifindex)
	revisionDir := dispatcher.DispatcherRevisionDir(m.dirs.FS, dispType, nsid, ifindex, revision)
	progPinPath := dispatcher.DispatcherProgPath(revisionDir)

	m.logger.Info("creating TC dispatcher",
		"direction", direction,
		"nsid", nsid,
		"ifindex", ifindex,
		"netns", netnsPath,
		"revision", revision,
		"prog_pin_path", progPinPath,
		"link_pin_path", linkPinPath)

	// KERNEL I/O: Create TC dispatcher using TCX link
	result, err := m.kernel.AttachTCDispatcherWithPaths(
		int(ifindex),
		progPinPath,
		linkPinPath,
		direction,
		dispatcher.MaxPrograms,
		uint32(DefaultTCProceedOn),
		netnsPath,
	)
	if err != nil {
		return dispatcher.State{}, err
	}

	// COMPUTE: Build save action from kernel result
	state := computeTCDispatcherState(dispType, nsid, ifindex, revision, result, progPinPath, linkPinPath)
	saveAction := action.SaveDispatcher{State: state}

	// EXECUTE: Save through executor
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return dispatcher.State{}, fmt.Errorf("save TC dispatcher: %w", err)
	}

	m.logger.Info("created TC dispatcher",
		"direction", direction,
		"nsid", nsid,
		"ifindex", ifindex,
		"dispatcher_id", result.DispatcherID,
		"link_id", result.LinkID,
		"prog_pin_path", progPinPath,
		"link_pin_path", linkPinPath)

	return state, nil
}

// computeTCDispatcherState is a pure function that builds a DispatcherState
// from TC kernel attach results.
func computeTCDispatcherState(
	dispType dispatcher.DispatcherType,
	nsid uint64,
	ifindex, revision uint32,
	result *interpreter.TCDispatcherResult,
	progPinPath, linkPinPath string,
) dispatcher.State {
	return dispatcher.State{
		Type:          dispType,
		Nsid:          nsid,
		Ifindex:       ifindex,
		Revision:      revision,
		KernelID:      result.DispatcherID,
		LinkID:        result.LinkID,
		LinkPinPath:   linkPinPath,
		ProgPinPath:   progPinPath,
		NumExtensions: 0,
	}
}

// ListLinks returns all managed links (summaries only).
func (m *Manager) ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error) {
	return m.store.ListLinks(ctx)
}

// ListLinksByProgram returns all links for a given program.
func (m *Manager) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkSummary, error) {
	return m.store.ListLinksByProgram(ctx, programKernelID)
}

// GetLink retrieves a link by kernel link ID, returning both summary and type-specific details.
func (m *Manager) GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error) {
	return m.store.GetLink(ctx, kernelLinkID)
}

// Detach removes a link by kernel link ID.
//
// This detaches the link from the kernel (if pinned) and removes it from the
// store. The associated program remains loaded.
//
// For XDP and TC links attached via dispatchers, this also decrements the
// dispatcher's extension count. If the dispatcher has no remaining extensions,
// it is cleaned up automatically (pins removed and deleted from store).
//
// Pattern: FETCH -> COMPUTE -> EXECUTE
func (m *Manager) Detach(ctx context.Context, kernelLinkID uint32) error {
	// FETCH: Get link summary and details
	summary, details, err := m.store.GetLink(ctx, kernelLinkID)
	if err != nil {
		return fmt.Errorf("get link %d: %w", kernelLinkID, err)
	}

	// FETCH: Get dispatcher state if this is a dispatcher-based link
	var dispState *dispatcher.State
	if summary.LinkType == bpfman.LinkTypeXDP || summary.LinkType == bpfman.LinkTypeTC {
		dispType, nsid, ifindex, err := extractDispatcherKey(details)
		if err != nil {
			return fmt.Errorf("extract dispatcher key: %w", err)
		}
		if dispType != "" {
			state, err := m.store.GetDispatcher(ctx, string(dispType), nsid, ifindex)
			if err != nil {
				m.logger.Warn("failed to get dispatcher for cleanup", "error", err)
			} else {
				dispState = &state
			}
		}
	}

	// COMPUTE: Build actions for detach
	actions := computeDetachActions(summary, dispState)

	// Log before executing
	m.logger.Info("detaching link",
		"kernel_link_id", kernelLinkID,
		"type", summary.LinkType,
		"program_id", summary.KernelProgramID,
		"pin_path", summary.PinPath)

	// EXECUTE: Run all actions
	if err := m.executor.ExecuteAll(ctx, actions); err != nil {
		return fmt.Errorf("execute detach actions: %w", err)
	}

	m.logger.Info("removed link", "kernel_link_id", kernelLinkID, "type", summary.LinkType, "program_id", summary.KernelProgramID)
	return nil
}

// computeDetachActions is a pure function that computes the actions needed
// to detach a link and optionally clean up its dispatcher.
func computeDetachActions(summary bpfman.LinkSummary, dispState *dispatcher.State) []action.Action {
	var actions []action.Action

	// Detach link from kernel if pinned
	if summary.PinPath != "" {
		actions = append(actions, action.DetachLink{PinPath: summary.PinPath})
	}

	// Delete link from store
	actions = append(actions, action.DeleteLink{KernelLinkID: summary.KernelLinkID})

	// Handle dispatcher cleanup if applicable
	if dispState != nil {
		dispatcherActions := computeDispatcherCleanupActions(*dispState)
		actions = append(actions, dispatcherActions...)
	}

	return actions
}

// extractDispatcherKey extracts dispatcher identification from link details.
// Returns empty dispType if the link type doesn't use dispatchers.
func extractDispatcherKey(details bpfman.LinkDetails) (dispType dispatcher.DispatcherType, nsid uint64, ifindex uint32, err error) {
	switch d := details.(type) {
	case bpfman.XDPDetails:
		return dispatcher.DispatcherTypeXDP, d.Nsid, d.Ifindex, nil
	case bpfman.TCDetails:
		switch d.Direction {
		case "ingress":
			return dispatcher.DispatcherTypeTCIngress, d.Nsid, d.Ifindex, nil
		case "egress":
			return dispatcher.DispatcherTypeTCEgress, d.Nsid, d.Ifindex, nil
		default:
			return "", 0, 0, fmt.Errorf("unknown TC direction: %s", d.Direction)
		}
	default:
		return "", 0, 0, nil
	}
}

// computeDispatcherCleanupActions is a pure function that computes the actions
// needed to update or remove a dispatcher after an extension is detached.
func computeDispatcherCleanupActions(state dispatcher.State) []action.Action {
	// Decrement extension count
	newCount := state.NumExtensions
	if newCount > 0 {
		newCount--
	}

	// If still has extensions, just save updated count
	if newCount > 0 {
		updatedState := state
		updatedState.NumExtensions = newCount
		return []action.Action{
			action.SaveDispatcher{State: updatedState},
		}
	}

	// No extensions left - remove dispatcher completely
	revisionDir := filepath.Dir(state.ProgPinPath)
	return []action.Action{
		action.RemovePin{Path: state.LinkPinPath},
		action.RemovePin{Path: state.ProgPinPath},
		action.RemovePin{Path: revisionDir},
		action.DeleteDispatcher{
			Type:    string(state.Type),
			Nsid:    state.Nsid,
			Ifindex: state.Ifindex,
		},
	}
}

// LoadedProgram pairs a program's database metadata with its kernel info.
type LoadedProgram struct {
	KernelID   uint32
	Program    bpfman.Program
	KernelInfo kernel.Program
}

// ListLoadedPrograms returns all programs that exist in both the database
// and the kernel. This reconciles DB state with kernel state, filtering out
// stale entries where a program exists in DB but not in the kernel (e.g.,
// after a daemon restart or failed unload).
func (m *Manager) ListLoadedPrograms(ctx context.Context) ([]LoadedProgram, error) {
	// Get all programs from DB
	dbPrograms, err := m.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list programs from store: %w", err)
	}

	// Filter to only those that exist in kernel
	var loaded []LoadedProgram
	for kernelID, prog := range dbPrograms {
		kp, err := m.kernel.GetProgramByID(ctx, kernelID)
		if err != nil {
			// Program not in kernel - skip (stale DB entry)
			m.logger.Debug("skipping stale program",
				"kernel_id", kernelID,
				"name", prog.ProgramName,
				"reason", "not in kernel",
			)
			continue
		}
		loaded = append(loaded, LoadedProgram{
			KernelID:   kernelID,
			Program:    prog,
			KernelInfo: kp,
		})
	}

	return loaded, nil
}

// ErrMultipleProgramsFound is returned when multiple programs match the
// search criteria and none is the map owner.
var ErrMultipleProgramsFound = errors.New("multiple programs found")

// ErrMultipleMapOwners is returned when multiple programs claim to be
// the map owner (MapOwnerID == 0). This indicates a data inconsistency.
var ErrMultipleMapOwners = errors.New("multiple map owners found")

// FindLoadedProgramByMetadata finds a program by metadata key/value from
// the reconciled list of loaded programs (those in both DB and kernel).
//
// When multiple programs match (e.g., multi-program applications), this
// returns the map owner (the program with MapOwnerID == 0). All maps are
// pinned at the owner's MapPinPath, so the CSI can find them there.
//
// Returns an error if no programs match, or if multiple map owners exist
// (data inconsistency).
func (m *Manager) FindLoadedProgramByMetadata(ctx context.Context, key, value string) (bpfman.Program, uint32, error) {
	programs, err := m.ListLoadedPrograms(ctx)
	if err != nil {
		return bpfman.Program{}, 0, fmt.Errorf("list loaded programs: %w", err)
	}

	var matches []LoadedProgram
	for _, lp := range programs {
		if lp.Program.UserMetadata[key] == value {
			matches = append(matches, lp)
		}
	}

	switch len(matches) {
	case 0:
		return bpfman.Program{}, 0, fmt.Errorf("program with %s=%s: %w", key, value, store.ErrNotFound)
	case 1:
		return matches[0].Program, matches[0].KernelID, nil
	default:
		// Multiple programs match - find the map owner (MapOwnerID == 0).
		// In multi-program loads, one program owns all maps and the others
		// reference it via MapOwnerID.
		var owners []LoadedProgram
		for _, lp := range matches {
			if lp.Program.MapOwnerID == 0 {
				owners = append(owners, lp)
			}
		}

		switch len(owners) {
		case 0:
			// No map owner found - all programs reference another owner
			// that doesn't match our metadata query. This shouldn't happen.
			ids := make([]uint32, len(matches))
			for i, m := range matches {
				ids[i] = m.KernelID
			}
			return bpfman.Program{}, 0, fmt.Errorf("%w: %d programs with %s=%s but no map owner (kernel IDs: %v)",
				ErrMultipleProgramsFound, len(matches), key, value, ids)
		case 1:
			m.logger.Debug("found map owner among multiple matching programs",
				"key", key,
				"value", value,
				"total_matches", len(matches),
				"owner_kernel_id", owners[0].KernelID,
				"owner_name", owners[0].Program.ProgramName,
			)
			return owners[0].Program, owners[0].KernelID, nil
		default:
			// Multiple map owners - data inconsistency
			ids := make([]uint32, len(owners))
			for i, o := range owners {
				ids[i] = o.KernelID
			}
			return bpfman.Program{}, 0, fmt.Errorf("%w: %d map owners with %s=%s (kernel IDs: %v)",
				ErrMultipleMapOwners, len(owners), key, value, ids)
		}
	}
}
