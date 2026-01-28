package manager

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/action"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/netns"
)

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

	// FETCH: Look up existing dispatcher or create new one.
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

	m.logger.DebugContext(ctx, "using dispatcher",
		"interface", ifname,
		"nsid", nsid,
		"ifindex", ifindex,
		"revision", dispState.Revision,
		"dispatcher_id", dispState.KernelID)

	// COMPUTE: Calculate extension link path
	revisionDir := dispatcher.DispatcherRevisionDir(m.dirs.FS, dispatcher.DispatcherTypeXDP, nsid, uint32(ifindex), dispState.Revision)
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
	link, err := m.kernel.AttachXDPExtension(
		ctx,
		progPinPath,
		prog.ObjectPath,
		prog.ProgramName,
		position,
		linkPinPath,
		mapPinDir,
	)
	if err != nil {
		// Stale dispatcher recovery: the DB record exists but the
		// bpffs pin is gone (e.g., fresh mount after pod restart while
		// the kernel program survives via XDP link). Delete the stale
		// record and retry with a fresh dispatcher.
		if !errors.Is(err, os.ErrNotExist) {
			return bpfman.LinkSummary{}, fmt.Errorf("attach XDP extension to %s slot %d: %w", ifname, position, err)
		}
		m.logger.WarnContext(ctx, "dispatcher pin missing, recreating",
			"prog_pin_path", progPinPath,
			"dispatcher_id", dispState.KernelID,
			"error", err)
		if delErr := m.store.DeleteDispatcher(ctx, string(dispatcher.DispatcherTypeXDP), nsid, uint32(ifindex)); delErr != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("delete stale XDP dispatcher: %w", delErr)
		}
		dispState, err = m.createXDPDispatcher(ctx, nsid, uint32(ifindex), netnsPath)
		if err != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("recreate XDP dispatcher for %s: %w", ifname, err)
		}
		revisionDir = dispatcher.DispatcherRevisionDir(m.dirs.FS, dispatcher.DispatcherTypeXDP, nsid, uint32(ifindex), dispState.Revision)
		position, err = m.store.CountDispatcherLinks(ctx, dispState.KernelID)
		if err != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("count dispatcher links after recreate: %w", err)
		}
		extensionLinkPath = dispatcher.ExtensionLinkPath(revisionDir, position)
		if linkPinPath == "" || strings.Contains(linkPinPath, "dispatcher_") {
			linkPinPath = extensionLinkPath
		}
		progPinPath = dispatcher.DispatcherProgPath(revisionDir)
		link, err = m.kernel.AttachXDPExtension(
			ctx,
			progPinPath,
			prog.ObjectPath,
			prog.ProgramName,
			position,
			linkPinPath,
			mapPinDir,
		)
		if err != nil {
			return bpfman.LinkSummary{}, fmt.Errorf("attach XDP extension to %s slot %d (after recreate): %w", ifname, position, err)
		}
	}

	// ROLLBACK: If the store write fails, detach the link we just created.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.DetachLink(ctx, link.Managed.PinPath)
	})

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
		m.logger.ErrorContext(ctx, "persist failed, rolling back", "program_id", programKernelID, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return bpfman.LinkSummary{}, errors.Join(fmt.Errorf("save link metadata: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return bpfman.LinkSummary{}, fmt.Errorf("save link metadata: %w", err)
	}

	m.logger.InfoContext(ctx, "attached XDP via dispatcher",
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
	return []action.Action{
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

	m.logger.InfoContext(ctx, "creating XDP dispatcher",
		"nsid", nsid,
		"ifindex", ifindex,
		"netns", netnsPath,
		"revision", revision,
		"prog_pin_path", progPinPath,
		"link_pin_path", linkPinPath)

	// KERNEL I/O: Create dispatcher (returns IDs)
	result, err := m.kernel.AttachXDPDispatcherWithPaths(
		ctx,
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

	// ROLLBACK: If the store write fails, undo kernel state.
	// Order: remove prog pin first, then detach the dispatcher link.
	var undo undoStack
	undo.push(func() error {
		return m.kernel.RemovePin(ctx, progPinPath)
	})
	undo.push(func() error {
		return m.kernel.DetachLink(ctx, linkPinPath)
	})

	// COMPUTE: Build save action from kernel result
	state := computeXDPDispatcherState(dispatcher.DispatcherTypeXDP, nsid, ifindex, revision, result)
	saveAction := action.SaveDispatcher{State: state}

	// EXECUTE: Save through executor
	if err := m.executor.Execute(ctx, saveAction); err != nil {
		m.logger.ErrorContext(ctx, "persist failed, rolling back XDP dispatcher", "ifindex", ifindex, "error", err)
		if rbErr := undo.rollback(ctx, m.logger); rbErr != nil {
			return dispatcher.State{}, errors.Join(fmt.Errorf("save dispatcher: %w", err), fmt.Errorf("rollback failed: %w", rbErr))
		}
		return dispatcher.State{}, fmt.Errorf("save dispatcher: %w", err)
	}

	m.logger.InfoContext(ctx, "created XDP dispatcher",
		"nsid", nsid,
		"ifindex", ifindex,
		"dispatcher_id", result.DispatcherID,
		"link_id", result.LinkID,
		"prog_pin_path", progPinPath,
		"link_pin_path", linkPinPath)

	return state, nil
}

// computeXDPDispatcherState is a pure function that builds a DispatcherState
// from kernel attach results.
func computeXDPDispatcherState(
	dispType dispatcher.DispatcherType,
	nsid uint64,
	ifindex, revision uint32,
	result *interpreter.XDPDispatcherResult,
) dispatcher.State {
	return dispatcher.State{
		Type:     dispType,
		Nsid:     nsid,
		Ifindex:  ifindex,
		Revision: revision,
		KernelID: result.DispatcherID,
		LinkID:   result.LinkID,
	}
}
