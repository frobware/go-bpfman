package manager

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/vishvananda/netlink"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/action"
	"github.com/frobware/go-bpfman/dispatcher"
)

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

	// No extensions left - remove dispatcher completely.
	revisionDir := filepath.Dir(state.ProgPinPath)
	var actions []action.Action

	// TC dispatchers use legacy netlink (Handle != 0) and must be
	// detached via RTM_DELTFILTER rather than removing a link pin.
	// XDP dispatchers use BPF links and are detached by removing
	// the link pin.
	if state.Handle != 0 {
		var parent uint32
		switch state.Type {
		case dispatcher.DispatcherTypeTCIngress:
			parent = netlink.HANDLE_MIN_INGRESS
		case dispatcher.DispatcherTypeTCEgress:
			parent = netlink.HANDLE_MIN_EGRESS
		}
		actions = append(actions, action.DetachTCFilter{
			Ifindex:  int(state.Ifindex),
			Parent:   parent,
			Priority: state.Priority,
			Handle:   state.Handle,
		})
	} else if state.LinkPinPath != "" {
		actions = append(actions, action.RemovePin{Path: state.LinkPinPath})
	}

	actions = append(actions,
		action.RemovePin{Path: state.ProgPinPath},
		action.RemovePin{Path: revisionDir},
		action.DeleteDispatcher{
			Type:    string(state.Type),
			Nsid:    state.Nsid,
			Ifindex: state.Ifindex,
		},
	)

	return actions
}
