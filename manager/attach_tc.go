package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/action"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/netns"
)

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

	// FETCH: Look up existing dispatcher or create new one.
	dispState, err := m.store.GetDispatcher(ctx, string(dispType), nsid, uint32(ifindex))
	if errors.Is(err, store.ErrNotFound) {
		// KERNEL I/O + EXECUTE: Create new dispatcher
		dispState, err = m.createTCDispatcher(ctx, nsid, uint32(ifindex), ifname, direction, dispType, netnsPath)
		if err != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("create TC dispatcher for %s %s: %w", ifname, direction, err)
		}
	} else if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("get dispatcher: %w", err)
	}

	m.logger.DebugContext(ctx, "using TC dispatcher",
		"interface", ifname,
		"direction", direction,
		"nsid", nsid,
		"ifindex", ifindex,
		"revision", dispState.Revision,
		"dispatcher_id", dispState.KernelID)

	// COMPUTE: Calculate extension link path
	revisionDir := dispatcher.DispatcherRevisionDir(m.dirs.FS, dispType, nsid, uint32(ifindex), dispState.Revision)
	position, err := m.store.CountDispatcherLinks(ctx, dispState.KernelID)
	if err != nil {
		return bpfman.LinkSummary{}, fmt.Errorf("count dispatcher links: %w", err)
	}
	extensionLinkPath := dispatcher.ExtensionLinkPath(revisionDir, position)
	if linkPinPath == "" {
		linkPinPath = extensionLinkPath
	}

	// COMPUTE: Use the program's MapPinPath which points to the correct maps
	// directory (either the program's own or the map owner's if sharing).
	mapPinDir := prog.MapPinPath

	// KERNEL I/O: Attach user program as extension (returns ManagedLink)
	progPinPath := dispatcher.DispatcherProgPath(revisionDir)
	link, err := m.kernel.AttachTCExtension(
		ctx,
		progPinPath,
		prog.ObjectPath,
		prog.Name,
		position,
		linkPinPath,
		mapPinDir,
	)
	if err != nil {
		// The dispatcher DB record may be stale: the kernel program
		// survives (held by a tc filter) but its bpffs pin is gone
		// after a fresh mount. GC keeps the record because the kernel
		// program exists, but the pin path is invalid. Delete the
		// stale record and retry once with a fresh dispatcher.
		if !errors.Is(err, os.ErrNotExist) {
			return bpfman.LinkSummary{}, fmt.Errorf("attach TC extension to %s %s slot %d: %w", ifname, direction, position, err)
		}
		m.logger.WarnContext(ctx, "dispatcher pin missing, recreating",
			"prog_pin_path", progPinPath,
			"dispatcher_id", dispState.KernelID,
			"error", err)
		if delErr := m.store.DeleteDispatcher(ctx, string(dispType), nsid, uint32(ifindex)); delErr != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("delete stale TC dispatcher: %w", delErr)
		}
		dispState, err = m.createTCDispatcher(ctx, nsid, uint32(ifindex), ifname, direction, dispType, netnsPath)
		if err != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("recreate TC dispatcher for %s %s: %w", ifname, direction, err)
		}
		// Recalculate paths for the fresh dispatcher
		revisionDir = dispatcher.DispatcherRevisionDir(m.dirs.FS, dispType, nsid, uint32(ifindex), dispState.Revision)
		position, err = m.store.CountDispatcherLinks(ctx, dispState.KernelID)
		if err != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("count dispatcher links after recreate: %w", err)
		}
		extensionLinkPath = dispatcher.ExtensionLinkPath(revisionDir, position)
		if linkPinPath == "" || strings.Contains(linkPinPath, "dispatcher_") {
			linkPinPath = extensionLinkPath
		}
		progPinPath = dispatcher.DispatcherProgPath(revisionDir)
		link, err = m.kernel.AttachTCExtension(
			ctx,
			progPinPath,
			prog.ObjectPath,
			prog.Name,
			position,
			linkPinPath,
			mapPinDir,
		)
		if err != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("attach TC extension to %s %s slot %d (after recreate): %w", ifname, direction, position, err)
		}
	}

	// ROLLBACK: If the store write fails, detach the link we just created.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.DetachLink(ctx, link.Managed.PinPath)
	})

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
		m.logger.ErrorContext(ctx, "persist failed, rolling back", "program_id", programKernelID, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return bpfman.LinkSummary{}, errors.Join(fmt.Errorf("save link metadata: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.InfoContext(ctx, "attached TC via dispatcher",
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
	return []action.Action{
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

	// COMPUTE: Calculate link pin path if not provided.
	// The path must be unique per program to support multiple TCX programs
	// on the same interface — each needs its own pinned link to keep the
	// kernel attachment alive.
	if linkPinPath == "" {
		dirName := fmt.Sprintf("tcx-%s", direction)
		linkPinPath = filepath.Join(m.dirs.FS, dirName, fmt.Sprintf("link_%d_%d_%d", nsid, ifindex, programKernelID))
	}

	// KERNEL I/O: Remove stale pin if it exists from a previous daemon run.
	if _, statErr := os.Stat(linkPinPath); statErr == nil {
		m.logger.WarnContext(ctx, "removing stale TCX link pin", "path", linkPinPath)
		if removeErr := os.Remove(linkPinPath); removeErr != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("remove stale TCX link pin %s: %w", linkPinPath, removeErr)
		}
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

	m.logger.DebugContext(ctx, "computed TCX attach order",
		"program_id", programKernelID,
		"priority", priority,
		"existing_links", len(existingLinks),
		"order", order)

	// KERNEL I/O: Attach program using TCX link with computed order
	link, err := m.kernel.AttachTCX(ctx, ifindex, direction, progPinPath, linkPinPath, netnsPath, order)
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

	// ROLLBACK: If the store write fails, detach the link we just created.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.DetachLink(ctx, link.Managed.PinPath)
	})

	saveAction := action.SaveTCXLink{
		Summary: summary,
		Details: details,
	}

	// EXECUTE: Save link metadata
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		m.logger.ErrorContext(ctx, "persist failed, rolling back", "program_id", programKernelID, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return bpfman.LinkSummary{}, errors.Join(fmt.Errorf("save TCX link metadata: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return bpfman.LinkSummary{}, fmt.Errorf("save TCX link metadata: %w", err)
	}

	m.logger.InfoContext(ctx, "attached TCX program",
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
// The dispatcher is attached via legacy netlink TC (clsact qdisc + BPF filter),
// matching the upstream Rust bpfman approach.
//
// Pattern: COMPUTE -> KERNEL I/O -> COMPUTE -> EXECUTE
func (m *Manager) createTCDispatcher(ctx context.Context, nsid uint64, ifindex uint32, ifname, direction string, dispType dispatcher.DispatcherType, netnsPath string) (dispatcher.State, error) {
	// COMPUTE: Calculate paths according to Rust bpfman convention.
	// TC dispatchers do not use a link pin — legacy netlink TC has no
	// BPF link to pin. The filter is identified by handle + priority.
	revision := uint32(1)
	revisionDir := dispatcher.DispatcherRevisionDir(m.dirs.FS, dispType, nsid, ifindex, revision)
	progPinPath := dispatcher.DispatcherProgPath(revisionDir)

	m.logger.InfoContext(ctx, "creating TC dispatcher",
		"direction", direction,
		"nsid", nsid,
		"ifindex", ifindex,
		"ifname", ifname,
		"netns", netnsPath,
		"revision", revision,
		"prog_pin_path", progPinPath)

	// KERNEL I/O: Create TC dispatcher using legacy netlink TC
	result, err := m.kernel.AttachTCDispatcherWithPaths(
		ctx,
		int(ifindex),
		ifname,
		progPinPath,
		direction,
		dispatcher.MaxPrograms,
		uint32(DefaultTCProceedOn),
		netnsPath,
	)
	if err != nil {
		return dispatcher.State{}, err
	}

	// ROLLBACK: If the store write fails, undo kernel state.
	// Order: remove prog pin first, then detach the TC filter.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.RemovePin(ctx, progPinPath)
	})
	undo.push(func() error {
		return m.kernel.DetachTCFilter(ctx, int(ifindex), ifname, tcParentHandle(dispType), result.Priority, result.Handle)
	})

	// COMPUTE: Build save action from kernel result
	state := computeTCDispatcherState(dispType, nsid, ifindex, revision, result)
	saveAction := action.SaveDispatcher{State: state}

	// EXECUTE: Save through executor
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		m.logger.ErrorContext(ctx, "persist failed, rolling back TC dispatcher", "ifname", ifname, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return dispatcher.State{}, errors.Join(fmt.Errorf("save TC dispatcher: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return dispatcher.State{}, fmt.Errorf("save TC dispatcher: %w", err)
	}

	m.logger.InfoContext(ctx, "created TC dispatcher",
		"direction", direction,
		"nsid", nsid,
		"ifindex", ifindex,
		"ifname", ifname,
		"dispatcher_id", result.DispatcherID,
		"handle", fmt.Sprintf("%x", result.Handle),
		"priority", result.Priority,
		"prog_pin_path", progPinPath)

	return state, nil
}

// computeTCDispatcherState is a pure function that builds a DispatcherState
// from TC kernel attach results.
func computeTCDispatcherState(
	dispType dispatcher.DispatcherType,
	nsid uint64,
	ifindex, revision uint32,
	result *interpreter.TCDispatcherResult,
) dispatcher.State {
	return dispatcher.State{
		Type:     dispType,
		Nsid:     nsid,
		Ifindex:  ifindex,
		Revision: revision,
		KernelID: result.DispatcherID,
		Priority: result.Priority,
	}
}
