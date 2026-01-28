package ebpf

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/netns"
)

// tcDispatcherPriority is the default TC priority for the dispatcher
// filter, matching the upstream Rust bpfman value.
const tcDispatcherPriority = 50

// AttachTCDispatcherWithPaths loads and attaches a TC dispatcher to an
// interface using legacy netlink TC (clsact qdisc + BPF tc filter).
// This matches the upstream Rust bpfman approach: the dispatcher
// program is attached as a cls_bpf filter on the clsact qdisc,
// visible to tc(8) tooling, and works on kernels older than 6.6.
//
// Parameters:
//   - ifindex: Network interface index
//   - ifname: Network interface name (needed for netlink)
//   - progPinPath: Path to pin the dispatcher program
//   - direction: "ingress" or "egress"
//   - numProgs: Number of extension slots to enable
//   - proceedOn: Bitmask of TC return codes that trigger continuation
//   - netnsPath: if non-empty, attachment is performed in that network namespace
func (k *kernelAdapter) AttachTCDispatcherWithPaths(ctx context.Context, ifindex int, ifname, progPinPath, direction string, numProgs int, proceedOn uint32, netnsPath string) (*interpreter.TCDispatcherResult, error) {
	// Configure the TC dispatcher
	// TC_DISPATCHER_RETVAL (30) is returned by empty slots - we must include
	// this bit so the dispatcher continues past empty slots to the final TC_ACT_OK.
	const tcDispatcherRetval = 30
	cfg := dispatcher.NewTCConfig(numProgs)
	for i := 0; i < dispatcher.MaxPrograms; i++ {
		cfg.ChainCallActions[i] = proceedOn | (1 << tcDispatcherRetval)
	}

	// Load the TC dispatcher spec with config injected
	spec, err := dispatcher.LoadTCDispatcher(cfg)
	if err != nil {
		return nil, fmt.Errorf("load TC dispatcher spec: %w", err)
	}

	// Create collection from spec
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create TC dispatcher collection: %w", err)
	}
	defer coll.Close()

	// Get the dispatcher program
	dispatcherProg := coll.Programs["tc_dispatcher"]
	if dispatcherProg == nil {
		return nil, fmt.Errorf("tc_dispatcher program not found in collection")
	}

	// Determine the parent handle based on direction
	var parent uint32
	switch direction {
	case "ingress":
		parent = netlink.HANDLE_MIN_INGRESS
	case "egress":
		parent = netlink.HANDLE_MIN_EGRESS
	default:
		return nil, fmt.Errorf("invalid TC direction %q: must be ingress or egress", direction)
	}

	// Attach and pin in target namespace (if specified)
	if netnsPath != "" {
		k.logger.Debug("entering network namespace for TC dispatcher attachment", "netns", netnsPath, "ifindex", ifindex, "direction", direction)
	}

	var result *interpreter.TCDispatcherResult
	err = netns.Run(netnsPath, func() error {
		// Step 1: Ensure clsact qdisc exists (matching Rust bpfman behaviour).
		// Aya checks has_qdisc("clsact"), errors on "ingress", else adds clsact.
		// We mirror this: attempt to add clsact, ignore EEXIST.
		qdisc := &netlink.Clsact{
			QdiscAttrs: netlink.QdiscAttrs{
				LinkIndex: ifindex,
				Handle:    netlink.MakeHandle(0xffff, 0),
				Parent:    netlink.HANDLE_INGRESS,
			},
		}
		if err := netlink.QdiscAdd(qdisc); err != nil {
			// EEXIST is fine — clsact already present.
			if !errors.Is(err, unix.EEXIST) {
				return fmt.Errorf("add clsact qdisc to ifindex %d: %w", ifindex, err)
			}
		}

		// Step 2: Add a BPF tc filter with the dispatcher program.
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{
				LinkIndex: ifindex,
				Parent:    parent,
				Priority:  tcDispatcherPriority,
				Protocol:  unix.ETH_P_ALL,
			},
			Fd:           dispatcherProg.FD(),
			Name:         "tc_dispatcher",
			DirectAction: true,
		}
		if err := netlink.FilterAdd(filter); err != nil {
			return fmt.Errorf("add TC BPF filter to ifindex %d direction %s: %w", ifindex, direction, err)
		}

		// Step 3: Read back the kernel-assigned handle.
		// vishvananda/netlink FilterAdd does not use NLM_F_ECHO, so
		// we must list filters to find our newly-added one.
		handle, err := readBackTCFilterHandle(ifindex, parent, tcDispatcherPriority)
		if err != nil {
			return fmt.Errorf("read back TC filter handle: %w", err)
		}

		result = &interpreter.TCDispatcherResult{
			Handle:   handle,
			Priority: tcDispatcherPriority,
		}

		// Get dispatcher program info
		progInfo, err := dispatcherProg.Info()
		if err != nil {
			return fmt.Errorf("get TC dispatcher program info: %w", err)
		}
		progID, ok := progInfo.ID()
		if !ok {
			return fmt.Errorf("failed to get TC dispatcher program ID from kernel")
		}
		result.DispatcherID = uint32(progID)

		// Pin dispatcher program to the revision-specific path
		if progPinPath != "" {
			progDir := filepath.Dir(progPinPath)
			if err := os.MkdirAll(progDir, 0755); err != nil {
				return fmt.Errorf("create TC dispatcher program directory: %w", err)
			}

			if err := dispatcherProg.Pin(progPinPath); err != nil {
				return fmt.Errorf("pin TC dispatcher program to %s: %w", progPinPath, err)
			}
			result.DispatcherPin = progPinPath
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// FindTCFilterHandle looks up the kernel-assigned handle for a TC BPF
// filter by listing filters on the given parent and matching priority.
func (k *kernelAdapter) FindTCFilterHandle(ctx context.Context, ifindex int, parent uint32, priority uint16) (uint32, error) {
	return readBackTCFilterHandle(ifindex, parent, priority)
}

// readBackTCFilterHandle lists tc filters on the given parent/priority
// and returns the handle of the first BPF filter found. This is
// needed because vishvananda/netlink FilterAdd does not echo back the
// kernel-assigned handle the way aya does with NLM_F_ECHO.
func readBackTCFilterHandle(ifindex int, parent uint32, priority uint16) (uint32, error) {
	lo := &netlink.Dummy{}
	lo.Index = ifindex
	filters, err := netlink.FilterList(lo, parent)
	if err != nil {
		return 0, fmt.Errorf("list filters on ifindex %d parent %x: %w", ifindex, parent, err)
	}
	for _, f := range filters {
		bpf, ok := f.(*netlink.BpfFilter)
		if !ok {
			continue
		}
		if bpf.Priority == priority {
			return bpf.Handle, nil
		}
	}
	return 0, fmt.Errorf("no BPF filter found at priority %d on ifindex %d parent %x", priority, ifindex, parent)
}

// DetachTCFilter removes a legacy TC BPF filter via netlink.
func (k *kernelAdapter) DetachTCFilter(ctx context.Context, ifindex int, ifname string, parent uint32, priority uint16, handle uint32) error {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: ifindex,
			Parent:    parent,
			Handle:    handle,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
	}
	if err := netlink.FilterDel(filter); err != nil {
		return fmt.Errorf("delete TC filter (ifindex=%d parent=%x prio=%d handle=%x): %w",
			ifindex, parent, priority, handle, err)
	}
	k.logger.Debug("detached TC filter",
		"ifindex", ifindex,
		"ifname", ifname,
		"parent", fmt.Sprintf("%x", parent),
		"priority", priority,
		"handle", fmt.Sprintf("%x", handle))
	return nil
}

// AttachTCExtension loads a program from ELF as Extension type and attaches
// it to a TC dispatcher slot. This follows the same pattern as XDP extension.
//
// The mapPinDir parameter specifies the directory containing the program's
// pinned maps. These maps are loaded and passed as MapReplacements so the
// extension program shares the same maps as the original loaded program.
func (k *kernelAdapter) AttachTCExtension(ctx context.Context, dispatcherPinPath, objectPath, programName string, position int, linkPinPath, mapPinDir string) (bpfman.ManagedLink, error) {
	// Load the pinned dispatcher to use as attach target
	dispatcherProg, err := ebpf.LoadPinnedProgram(dispatcherPinPath, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load pinned TC dispatcher %s: %w", dispatcherPinPath, err)
	}
	defer dispatcherProg.Close()

	// Load the collection spec from the ELF file
	collSpec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load collection spec from %s: %w", objectPath, err)
	}

	// Verify the program exists in the collection
	progSpec, ok := collSpec.Programs[programName]
	if !ok {
		return bpfman.ManagedLink{}, fmt.Errorf("program %q not found in %s", programName, objectPath)
	}

	// Modify the program spec to be Extension type targeting the dispatcher
	progSpec.Type = ebpf.Extension
	progSpec.AttachTarget = dispatcherProg
	progSpec.AttachTo = dispatcher.SlotName(position)

	// Load pinned maps from the original program's map directory.
	// This ensures the extension program uses the same maps that were
	// created during the initial Load and are exposed via CSI.
	// We iterate over collSpec.Maps to get the exact ELF map names,
	// which must match the MapReplacements keys.
	mapReplacements := make(map[string]*ebpf.Map)
	if mapPinDir != "" {
		for name := range collSpec.Maps {
			// Skip internal maps (same filtering as Load)
			if strings.HasPrefix(name, ".") {
				continue
			}
			mapPath := filepath.Join(mapPinDir, name)
			m, err := ebpf.LoadPinnedMap(mapPath, nil)
			if err != nil {
				return bpfman.ManagedLink{}, fmt.Errorf("load pinned map %s: %w", mapPath, err)
			}
			mapReplacements[name] = m
			k.logger.Debug("loaded pinned map for TC extension", "name", name, "path", mapPath)
		}
	}

	// Ensure we close loaded maps on error
	closeMapReplacements := func() {
		for _, m := range mapReplacements {
			m.Close()
		}
	}

	// Clear map pinning flags - maps will come from MapReplacements
	for _, mapSpec := range collSpec.Maps {
		mapSpec.Pinning = ebpf.PinNone
	}

	// Load the collection with map replacements from the original program
	coll, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	})
	if err != nil {
		closeMapReplacements()
		return bpfman.ManagedLink{}, fmt.Errorf("load TC extension collection: %w", err)
	}
	defer coll.Close()

	// Get the loaded extension program
	extensionProg := coll.Programs[programName]
	if extensionProg == nil {
		return bpfman.ManagedLink{}, fmt.Errorf("TC extension program %q not in loaded collection", programName)
	}

	// Get program info for the extension
	progInfo, err := extensionProg.Info()
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("get TC extension program info: %w", err)
	}
	progID, _ := progInfo.ID()

	// Attach the extension using freplace link
	lnk, err := link.AttachFreplace(dispatcherProg, progSpec.AttachTo, extensionProg)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach TC freplace to %s: %w", progSpec.AttachTo, err)
	}

	// Pin the link if path provided
	if linkPinPath != "" {
		if err := pinWithRetry(lnk, linkPinPath); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("pin TC extension link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.ManagedLink{}, fmt.Errorf("get TC link info: %w", err)
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            bpfman.LinkTypeTC,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.TCDetails{Position: int32(position)},
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}

// AttachTCX attaches a loaded program directly to an interface using TCX link.
// Unlike TC which uses dispatchers, TCX uses native kernel multi-program support.
// The order parameter specifies where to insert the program in the TCX chain.
func (k *kernelAdapter) AttachTCX(ctx context.Context, ifindex int, direction, programPinPath, linkPinPath, netnsPath string, order bpfman.TCXAttachOrder) (bpfman.ManagedLink, error) {
	// Load the pinned program
	prog, err := ebpf.LoadPinnedProgram(programPinPath, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load pinned program %s: %w", programPinPath, err)
	}
	defer prog.Close()

	// Get program info for the ID
	progInfo, err := prog.Info()
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("get program info: %w", err)
	}
	progID, _ := progInfo.ID()

	// Determine attach type based on direction
	var attachType ebpf.AttachType
	switch direction {
	case "ingress":
		attachType = ebpf.AttachTCXIngress
	case "egress":
		attachType = ebpf.AttachTCXEgress
	default:
		return bpfman.ManagedLink{}, fmt.Errorf("invalid TCX direction %q: must be ingress or egress", direction)
	}

	// Convert TCXAttachOrder to cilium/ebpf link.Anchor
	var anchor link.Anchor
	switch {
	case order.First:
		anchor = link.Head()
	case order.Last:
		anchor = link.Tail()
	case order.BeforeProgID != 0:
		anchor = link.BeforeProgramByID(ebpf.ProgramID(order.BeforeProgID))
	case order.AfterProgID != 0:
		anchor = link.AfterProgramByID(ebpf.ProgramID(order.AfterProgID))
	default:
		// Default to head for safety - ensures new programs run before existing ones
		anchor = link.Head()
	}

	// Attach and pin in target namespace (if specified)
	if netnsPath != "" {
		k.logger.Debug("entering network namespace for TCX attachment", "netns", netnsPath, "ifindex", ifindex, "direction", direction)
	}

	var result bpfman.ManagedLink
	err = netns.Run(netnsPath, func() error {
		// Attach using TCX link with ordering anchor
		lnk, err := link.AttachTCX(link.TCXOptions{
			Interface: ifindex,
			Program:   prog,
			Attach:    attachType,
			Anchor:    anchor,
		})
		if err != nil {
			return fmt.Errorf("attach TCX to ifindex %d %s: %w", ifindex, direction, err)
		}

		// Pin the link if path provided
		if linkPinPath != "" {
			if err := pinWithRetry(lnk, linkPinPath); err != nil {
				lnk.Close()
				return fmt.Errorf("pin TCX link to %s: %w", linkPinPath, err)
			}
		}

		// Get link info
		linkInfo, err := lnk.Info()
		if err != nil {
			lnk.Close()
			return fmt.Errorf("get TCX link info: %w", err)
		}

		result = bpfman.ManagedLink{
			Managed: &bpfman.LinkInfo{
				KernelLinkID:    uint32(linkInfo.ID),
				KernelProgramID: uint32(progID),
				Type:            bpfman.LinkTypeTCX,
				PinPath:         linkPinPath,
				CreatedAt:       time.Now(),
			},
			Kernel: NewLinkInfo(linkInfo),
		}
		return nil
	})
	if err != nil {
		return bpfman.ManagedLink{}, err
	}

	return result, nil
}
