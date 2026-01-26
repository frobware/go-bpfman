package ebpf

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/netns"
)

// AttachTCDispatcherWithPaths loads and attaches a TC dispatcher to an interface
// using the TCX link API. This follows the same pattern as XDP dispatcher attachment.
//
// Parameters:
//   - ifindex: Network interface index
//   - progPinPath: Path to pin the dispatcher program
//   - linkPinPath: Stable path to pin the TCX link
//   - direction: "ingress" or "egress"
//   - numProgs: Number of extension slots to enable
//   - proceedOn: Bitmask of TC return codes that trigger continuation
//   - netnsPath: if non-empty, attachment is performed in that network namespace
func (k *kernelAdapter) AttachTCDispatcherWithPaths(ifindex int, progPinPath, linkPinPath, direction string, numProgs int, proceedOn uint32, netnsPath string) (*interpreter.TCDispatcherResult, error) {
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

	// Get the dispatcher program - TC dispatcher uses "tc_dispatcher" as the program name
	dispatcherProg := coll.Programs["tc_dispatcher"]
	if dispatcherProg == nil {
		return nil, fmt.Errorf("tc_dispatcher program not found in collection")
	}

	// Determine attach type based on direction
	var attachType ebpf.AttachType
	switch direction {
	case "ingress":
		attachType = ebpf.AttachTCXIngress
	case "egress":
		attachType = ebpf.AttachTCXEgress
	default:
		return nil, fmt.Errorf("invalid TC direction %q: must be ingress or egress", direction)
	}

	// Attach and pin in target namespace (if specified)
	if netnsPath != "" {
		k.logger.Debug("entering network namespace for TC dispatcher attachment", "netns", netnsPath, "ifindex", ifindex, "direction", direction)
	}

	var result *interpreter.TCDispatcherResult
	err = netns.Run(netnsPath, func() error {
		// Attach to interface using TCX link
		lnk, err := link.AttachTCX(link.TCXOptions{
			Program:   dispatcherProg,
			Interface: ifindex,
			Attach:    attachType,
		})
		if err != nil {
			return fmt.Errorf("attach TC dispatcher to ifindex %d direction %s: %w", ifindex, direction, err)
		}

		result = &interpreter.TCDispatcherResult{}

		// Get dispatcher program info
		progInfo, err := dispatcherProg.Info()
		if err != nil {
			lnk.Close()
			return fmt.Errorf("get TC dispatcher program info: %w", err)
		}
		progID, ok := progInfo.ID()
		if !ok {
			lnk.Close()
			return fmt.Errorf("failed to get TC dispatcher program ID from kernel")
		}
		result.DispatcherID = uint32(progID)

		// Get link info
		linkInfo, err := lnk.Info()
		if err != nil {
			lnk.Close()
			return fmt.Errorf("get TC dispatcher link info: %w", err)
		}
		result.LinkID = uint32(linkInfo.ID)

		// Pin dispatcher program to the revision-specific path
		if progPinPath != "" {
			progDir := filepath.Dir(progPinPath)
			if err := os.MkdirAll(progDir, 0755); err != nil {
				lnk.Close()
				return fmt.Errorf("create TC dispatcher program directory: %w", err)
			}

			if err := dispatcherProg.Pin(progPinPath); err != nil {
				lnk.Close()
				return fmt.Errorf("pin TC dispatcher program to %s: %w", progPinPath, err)
			}
			result.DispatcherPin = progPinPath
		}

		// Pin link to the stable path
		if linkPinPath != "" {
			linkDir := filepath.Dir(linkPinPath)
			if err := os.MkdirAll(linkDir, 0755); err != nil {
				if progPinPath != "" {
					if rmErr := os.Remove(progPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
						k.logger.Warn("failed to remove program pin during cleanup", "path", progPinPath, "error", rmErr)
					}
				}
				lnk.Close()
				return fmt.Errorf("create TC link pin directory: %w", err)
			}

			if err := lnk.Pin(linkPinPath); err != nil {
				if progPinPath != "" {
					if rmErr := os.Remove(progPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
						k.logger.Warn("failed to remove program pin during cleanup", "path", progPinPath, "error", rmErr)
					}
				}
				lnk.Close()
				return fmt.Errorf("pin TC dispatcher link to %s: %w", linkPinPath, err)
			}
			result.LinkPin = linkPinPath
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	return result, nil
}

// AttachTCExtension loads a program from ELF as Extension type and attaches
// it to a TC dispatcher slot. This follows the same pattern as XDP extension.
//
// The mapPinDir parameter specifies the directory containing the program's
// pinned maps. These maps are loaded and passed as MapReplacements so the
// extension program shares the same maps as the original loaded program.
func (k *kernelAdapter) AttachTCExtension(dispatcherPinPath, objectPath, programName string, position int, linkPinPath, mapPinDir string) (bpfman.ManagedLink, error) {
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
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("create TC extension link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
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
func (k *kernelAdapter) AttachTCX(ifindex int, direction, programPinPath, linkPinPath, netnsPath string, order bpfman.TCXAttachOrder) (bpfman.ManagedLink, error) {
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
			if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
				lnk.Close()
				return fmt.Errorf("create TCX link pin directory: %w", err)
			}

			if err := lnk.Pin(linkPinPath); err != nil {
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
