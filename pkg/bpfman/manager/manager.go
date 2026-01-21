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
	"log/slog"
	"path/filepath"
	"time"

	googleuuid "github.com/google/uuid"

	"github.com/frobware/go-bpfman/pkg/bpfman/action"
	"github.com/frobware/go-bpfman/pkg/bpfman/compute"
	"github.com/frobware/go-bpfman/pkg/bpfman/dispatcher"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/pkg/bpfman/kernel"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
	"github.com/frobware/go-bpfman/pkg/bpfman/netns"
)

// Manager orchestrates BPF program management using fetch/compute/execute.
type Manager struct {
	store    interpreter.Store
	kernel   interpreter.KernelOperations
	executor *interpreter.Executor
	logger   *slog.Logger
}

// New creates a new Manager.
func New(store interpreter.Store, kernel interpreter.KernelOperations, logger *slog.Logger) *Manager {
	if logger == nil {
		logger = slog.Default()
	}
	return &Manager{
		store:    store,
		kernel:   kernel,
		executor: interpreter.NewExecutor(store, kernel),
		logger:   logger.With("component", "manager"),
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
func (m *Manager) Load(ctx context.Context, spec managed.LoadSpec, opts LoadOpts) (managed.Loaded, error) {
	now := time.Now()

	// Phase 1: Write reservation (state=loading)
	metadata := managed.Program{
		LoadSpec:     spec,
		UUID:         opts.UUID,
		UserMetadata: opts.UserMetadata,
		Tags:         nil,
		Owner:        opts.Owner,
		CreatedAt:    now,
		State:        managed.StateLoading,
		UpdatedAt:    now,
	}

	if err := m.store.Reserve(ctx, opts.UUID, metadata); err != nil {
		return managed.Loaded{}, fmt.Errorf("create reservation: %w", err)
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
		return managed.Loaded{}, fmt.Errorf("load program %s: %w", spec.ProgramName, err)
	}
	pinned = true
	m.logger.Info("loaded program", "name", spec.ProgramName, "kernel_id", loaded.ID, "pin_path", spec.PinPath)

	// Phase 3: Commit reservation (state=loaded)
	if err := m.store.CommitReservation(ctx, opts.UUID, loaded.ID); err != nil {
		m.logger.Error("commit failed", "kernel_id", loaded.ID, "error", err)
		// Commit failed - unpin and mark error
		rbErr := m.kernel.Unload(ctx, spec.PinPath)
		if rbErr == nil {
			m.logger.Info("rollback succeeded", "kernel_id", loaded.ID)
			// Rollback succeeded - delete reservation
			_ = m.store.DeleteReservation(ctx, opts.UUID)
			return managed.Loaded{}, fmt.Errorf("commit reservation: %w", err)
		}
		// Rollback also failed - mark as error for reconciliation
		_ = m.store.MarkError(ctx, opts.UUID, fmt.Sprintf("commit failed: %v; rollback failed: %v", err, rbErr))
		return managed.Loaded{}, errors.Join(
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

// Unload removes a BPF program, its links, and metadata.
//
// Uses 2PC to ensure consistent state:
//   - Phase 1: Mark state=unloading in DB
//   - Phase 2: Unpin links, unpin program, delete from DB
//
// If phase 2 fails, the program remains in state=unloading which GC
// can detect and clean up (no kernel program but DB entry exists).
//
// Pattern: FETCH -> COMPUTE -> EXECUTE
func (m *Manager) Unload(ctx context.Context, kernelID uint32) error {
	// FETCH: Get metadata and links
	metadata, err := m.store.Get(ctx, kernelID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}
	if errors.Is(err, store.ErrNotFound) {
		// No metadata - nothing to unload from our perspective
		return nil
	}

	links, _ := m.store.ListLinksByProgram(ctx, kernelID)

	// COMPUTE: Build unload actions
	actions := computeUnloadActions(kernelID, metadata.LoadSpec.PinPath, links)

	m.logger.Info("unloading program", "kernel_id", kernelID, "links", len(links))

	// EXECUTE: Run all actions (2PC semantics preserved by action order)
	if err := m.executor.ExecuteAll(ctx, actions); err != nil {
		return fmt.Errorf("execute unload actions: %w", err)
	}

	m.logger.Info("unloaded program", "kernel_id", kernelID)
	return nil
}

// computeUnloadActions is a pure function that computes the actions needed
// to unload a program and its associated links.
//
// Action order preserves 2PC semantics:
// 1. MarkProgramUnloading (Phase 1)
// 2. DetachLink for each link (Phase 2 start)
// 3. UnloadProgram (Phase 2 continue)
// 4. DeleteProgram (Phase 2 complete)
func computeUnloadActions(kernelID uint32, pinPath string, links []managed.LinkSummary) []action.Action {
	actions := []action.Action{
		// Phase 1: Mark intent
		action.MarkProgramUnloading{KernelID: kernelID},
	}

	// Phase 2: Detach links
	for _, link := range links {
		if link.PinPath != "" {
			actions = append(actions, action.DetachLink{PinPath: link.PinPath})
		}
	}

	// Phase 2: Unload program and delete metadata
	actions = append(actions,
		action.UnloadProgram{PinPath: pinPath},
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

// Reconcile cleans up orphaned store entries.
func (m *Manager) Reconcile(ctx context.Context) error {
	// FETCH
	stored, err := m.store.List(ctx)
	if err != nil {
		return err
	}

	var kernelPrograms []kernel.Program
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
	KernelProgram kernel.Program   `json:"kernel"`
	Metadata      *managed.Program `json:"metadata,omitempty"`
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
	Program *managed.Program  `json:"program,omitempty"`
	Links   []LinkWithDetails `json:"links,omitempty"`
}

// LinkWithDetails combines a link summary with its type-specific details.
type LinkWithDetails struct {
	Summary managed.LinkSummary `json:"summary"`
	Details managed.LinkDetails `json:"details"`
}

// joinManagedPrograms is a pure function that joins kernel and store data.
func joinManagedPrograms(
	stored map[uint32]managed.Program,
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
		_, details, err := m.store.GetLink(ctx, sl.UUID)
		if err != nil {
			m.logger.Warn("failed to get link details", "uuid", sl.UUID, "error", err)
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
// programKernelID is required to associate the link with the program in the store.
//
// Pattern: FETCH -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) AttachTracepoint(ctx context.Context, programKernelID uint32, progPinPath, group, name, linkPinPath string) (managed.LinkSummary, error) {
	// FETCH: Verify program exists
	_, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return managed.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// KERNEL I/O: Attach to the kernel (returns IDs needed for store action)
	kernelLink, err := m.kernel.AttachTracepoint(progPinPath, group, name, linkPinPath)
	if err != nil {
		return managed.LinkSummary{}, fmt.Errorf("attach tracepoint %s/%s: %w", group, name, err)
	}

	// COMPUTE: Build save action from kernel result
	linkUUID := googleuuid.New().String()
	saveAction := computeAttachTracepointAction(linkUUID, programKernelID, kernelLink.ID, kernelLink.PinPath, group, name)

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		m.logger.Error("failed to save link metadata", "uuid", linkUUID, "error", err)
		// Don't fail the attachment - the link is already created in the kernel
		// This is a metadata-only failure
	} else {
		m.logger.Info("attached tracepoint",
			"link_uuid", linkUUID,
			"program_id", programKernelID,
			"tracepoint", group+"/"+name,
			"pin_path", kernelLink.PinPath)
	}

	return saveAction.Summary, nil
}

// computeAttachTracepointAction is a pure function that builds the save action
// for a tracepoint attachment.
func computeAttachTracepointAction(linkUUID string, programKernelID, kernelLinkID uint32, pinPath, group, name string) action.SaveTracepointLink {
	return action.SaveTracepointLink{
		Summary: managed.LinkSummary{
			UUID:            linkUUID,
			LinkType:        managed.LinkTypeTracepoint,
			KernelProgramID: programKernelID,
			KernelLinkID:    kernelLinkID,
			PinPath:         pinPath,
			CreatedAt:       time.Now(),
		},
		Details: managed.TracepointDetails{
			Group: group,
			Name:  name,
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
func (m *Manager) AttachXDP(ctx context.Context, programKernelID uint32, ifindex int, ifname string, linkPinPath string) (managed.LinkSummary, error) {
	// FETCH: Get program metadata to access ObjectPath and ProgramName
	prog, err := m.store.Get(ctx, programKernelID)
	if err != nil {
		return managed.LinkSummary{}, fmt.Errorf("get program %d: %w", programKernelID, err)
	}

	// FETCH: Get network namespace ID
	nsid, err := netns.GetCurrentNsid()
	if err != nil {
		return managed.LinkSummary{}, fmt.Errorf("get current nsid: %w", err)
	}

	// FETCH: Look up existing dispatcher or create new one
	dispState, err := m.store.GetDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), nsid, uint32(ifindex))
	if errors.Is(err, store.ErrNotFound) {
		// KERNEL I/O + EXECUTE: Create new dispatcher
		dispState, err = m.createXDPDispatcher(ctx, nsid, uint32(ifindex))
		if err != nil {
			return managed.LinkSummary{}, fmt.Errorf("create XDP dispatcher for %s: %w", ifname, err)
		}
	} else if err != nil {
		return managed.LinkSummary{}, fmt.Errorf("get dispatcher: %w", err)
	}

	m.logger.Debug("using dispatcher",
		"interface", ifname,
		"nsid", nsid,
		"ifindex", ifindex,
		"revision", dispState.Revision,
		"dispatcher_id", dispState.KernelID)

	// COMPUTE: Calculate extension link path
	revisionDir := dispatcher.DispatcherRevisionDir(dispatcher.DispatcherTypeXDP, nsid, uint32(ifindex), dispState.Revision)
	position := int(dispState.NumExtensions)
	extensionLinkPath := dispatcher.ExtensionLinkPath(revisionDir, position)
	if linkPinPath == "" {
		linkPinPath = extensionLinkPath
	}

	// KERNEL I/O: Attach user program as extension (returns IDs)
	extensionLink, err := m.kernel.AttachXDPExtension(
		dispState.ProgPinPath,
		prog.LoadSpec.ObjectPath,
		prog.LoadSpec.ProgramName,
		position,
		linkPinPath,
	)
	if err != nil {
		return managed.LinkSummary{}, fmt.Errorf("attach XDP extension to %s slot %d: %w", ifname, position, err)
	}

	// COMPUTE: Build save actions from kernel result
	linkUUID := googleuuid.New().String()
	saveActions := computeAttachXDPActions(
		linkUUID,
		programKernelID,
		extensionLink.ID,
		extensionLink.PinPath,
		ifname,
		uint32(ifindex),
		nsid,
		position,
		dispState,
	)

	// EXECUTE: Save dispatcher update and link metadata
	if err := m.executor.ExecuteAll(ctx, saveActions); err != nil {
		m.logger.Error("failed to save link metadata", "uuid", linkUUID, "error", err)
		// Don't fail the attachment - the link is already created in the kernel
		// This is a metadata-only failure
	} else {
		m.logger.Info("attached XDP via dispatcher",
			"link_uuid", linkUUID,
			"program_id", programKernelID,
			"interface", ifname,
			"ifindex", ifindex,
			"nsid", nsid,
			"position", position,
			"revision", dispState.Revision,
			"pin_path", extensionLink.PinPath)
	}

	// Extract summary from computed action for return value
	for _, a := range saveActions {
		if saveXDP, ok := a.(action.SaveXDPLink); ok {
			return saveXDP.Summary, nil
		}
	}
	// Shouldn't happen, but return a constructed summary as fallback
	return managed.LinkSummary{
		UUID:            linkUUID,
		LinkType:        managed.LinkTypeXDP,
		KernelProgramID: programKernelID,
		KernelLinkID:    extensionLink.ID,
		PinPath:         extensionLink.PinPath,
		CreatedAt:       time.Now(),
	}, nil
}

// computeAttachXDPActions is a pure function that builds the actions needed
// to save XDP attachment metadata (dispatcher update + link save).
func computeAttachXDPActions(
	linkUUID string,
	programKernelID, kernelLinkID uint32,
	pinPath, ifname string,
	ifindex uint32,
	nsid uint64,
	position int,
	dispState managed.DispatcherState,
) []action.Action {
	// Update dispatcher extension count
	updatedDispState := dispState
	updatedDispState.NumExtensions++

	return []action.Action{
		action.SaveDispatcher{State: updatedDispState},
		action.SaveXDPLink{
			Summary: managed.LinkSummary{
				UUID:            linkUUID,
				LinkType:        managed.LinkTypeXDP,
				KernelProgramID: programKernelID,
				KernelLinkID:    kernelLinkID,
				PinPath:         pinPath,
				CreatedAt:       time.Now(),
			},
			Details: managed.XDPDetails{
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
func (m *Manager) createXDPDispatcher(ctx context.Context, nsid uint64, ifindex uint32) (managed.DispatcherState, error) {
	// COMPUTE: Calculate paths according to Rust bpfman convention
	revision := uint32(1)
	linkPinPath := dispatcher.DispatcherLinkPath(dispatcher.DispatcherTypeXDP, nsid, ifindex)
	revisionDir := dispatcher.DispatcherRevisionDir(dispatcher.DispatcherTypeXDP, nsid, ifindex, revision)
	progPinPath := dispatcher.DispatcherProgPath(revisionDir)

	m.logger.Info("creating XDP dispatcher",
		"nsid", nsid,
		"ifindex", ifindex,
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
	)
	if err != nil {
		return managed.DispatcherState{}, err
	}

	// COMPUTE: Build save action from kernel result
	state := computeDispatcherState(dispatcher.DispatcherTypeXDP, nsid, ifindex, revision, result, progPinPath, linkPinPath)
	saveAction := action.SaveDispatcher{State: state}

	// EXECUTE: Save through executor
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		return managed.DispatcherState{}, fmt.Errorf("save dispatcher: %w", err)
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
) managed.DispatcherState {
	return managed.DispatcherState{
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
func (m *Manager) ListLinks(ctx context.Context) ([]managed.LinkSummary, error) {
	return m.store.ListLinks(ctx)
}

// ListLinksByProgram returns all links for a given program.
func (m *Manager) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	return m.store.ListLinksByProgram(ctx, programKernelID)
}

// GetLink retrieves a link by UUID, returning both summary and type-specific details.
func (m *Manager) GetLink(ctx context.Context, uuid string) (managed.LinkSummary, managed.LinkDetails, error) {
	return m.store.GetLink(ctx, uuid)
}

// Detach removes a link by UUID.
//
// This detaches the link from the kernel (if pinned) and removes it from the
// store. The associated program remains loaded.
//
// For XDP and TC links attached via dispatchers, this also decrements the
// dispatcher's extension count. If the dispatcher has no remaining extensions,
// it is cleaned up automatically (pins removed and deleted from store).
//
// Pattern: FETCH -> COMPUTE -> EXECUTE
func (m *Manager) Detach(ctx context.Context, linkUUID string) error {
	// FETCH: Get link summary and details
	summary, details, err := m.store.GetLink(ctx, linkUUID)
	if err != nil {
		return fmt.Errorf("get link %s: %w", linkUUID, err)
	}

	// FETCH: Get dispatcher state if this is a dispatcher-based link
	var dispState *managed.DispatcherState
	if summary.LinkType == managed.LinkTypeXDP || summary.LinkType == managed.LinkTypeTC {
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
		"uuid", linkUUID,
		"type", summary.LinkType,
		"program_id", summary.KernelProgramID,
		"pin_path", summary.PinPath)

	// EXECUTE: Run all actions
	if err := m.executor.ExecuteAll(ctx, actions); err != nil {
		return fmt.Errorf("execute detach actions: %w", err)
	}

	m.logger.Info("removed link", "uuid", linkUUID, "type", summary.LinkType, "program_id", summary.KernelProgramID)
	return nil
}

// computeDetachActions is a pure function that computes the actions needed
// to detach a link and optionally clean up its dispatcher.
func computeDetachActions(summary managed.LinkSummary, dispState *managed.DispatcherState) []action.Action {
	var actions []action.Action

	// Detach link from kernel if pinned
	if summary.PinPath != "" {
		actions = append(actions, action.DetachLink{PinPath: summary.PinPath})
	}

	// Delete link from store
	actions = append(actions, action.DeleteLink{UUID: summary.UUID})

	// Handle dispatcher cleanup if applicable
	if dispState != nil {
		dispatcherActions := computeDispatcherCleanupActions(*dispState)
		actions = append(actions, dispatcherActions...)
	}

	return actions
}

// extractDispatcherKey extracts dispatcher identification from link details.
// Returns empty dispType if the link type doesn't use dispatchers.
func extractDispatcherKey(details managed.LinkDetails) (dispType dispatcher.DispatcherType, nsid uint64, ifindex uint32, err error) {
	switch d := details.(type) {
	case managed.XDPDetails:
		return dispatcher.DispatcherTypeXDP, d.Nsid, d.Ifindex, nil
	case managed.TCDetails:
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
func computeDispatcherCleanupActions(state managed.DispatcherState) []action.Action {
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
