package ebpf

import (
	"context"
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

// AttachXDP attaches a pinned XDP program to a network interface.
func (k *kernelAdapter) AttachXDP(ctx context.Context, progPinPath string, ifindex int, linkPinPath string) (bpfman.Link, error) {
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
	})
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, err)
	}

	// Pin the link if a path is provided
	if linkPinPath != "" {
		if err := pinWithRetry(lnk, linkPinPath); err != nil {
			lnk.Close()
			return bpfman.Link{}, fmt.Errorf("pin link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.Link{}, fmt.Errorf("get link info: %w", err)
	}

	kernelLinkID := uint32(linkInfo.ID)
	return bpfman.Link{
		Managed: bpfman.LinkRecord{
			Kind:         bpfman.LinkKindXDP,
			KernelLinkID: &kernelLinkID,
			PinPath:      linkPinPath,
			CreatedAt:    time.Now(),
			Details:      bpfman.XDPDetails{Ifindex: uint32(ifindex)},
		},
		Kernel: *ToKernelLink(linkInfo),
	}, nil
}

// AttachXDPDispatcher loads and attaches an XDP dispatcher to an interface.
// The dispatcher allows multiple XDP programs to be chained together.
func (k *kernelAdapter) AttachXDPDispatcher(ctx context.Context, ifindex int, pinDir string, numProgs int, proceedOn uint32) (*interpreter.XDPDispatcherResult, error) {
	// Configure the dispatcher
	// XDP_DISPATCHER_RETVAL (31) is returned by empty slots - we must include
	// this bit so the dispatcher continues past empty slots to the final XDP_PASS.
	const xdpDispatcherRetval = 31
	cfg := dispatcher.NewXDPConfig(numProgs)
	for i := 0; i < dispatcher.MaxPrograms; i++ {
		cfg.ChainCallActions[i] = proceedOn | (1 << xdpDispatcherRetval)
	}

	// Load the dispatcher spec with config injected
	spec, err := dispatcher.LoadXDPDispatcher(cfg)
	if err != nil {
		return nil, fmt.Errorf("load XDP dispatcher spec: %w", err)
	}

	// Create collection from spec
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create XDP dispatcher collection: %w", err)
	}
	defer coll.Close()

	// Get the dispatcher program
	dispatcherProg := coll.Programs["xdp_dispatcher"]
	if dispatcherProg == nil {
		return nil, fmt.Errorf("xdp_dispatcher program not found in collection")
	}

	// Attach to interface
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   dispatcherProg,
		Interface: ifindex,
	})
	if err != nil {
		return nil, fmt.Errorf("attach XDP dispatcher to ifindex %d: %w", ifindex, err)
	}

	result := &interpreter.XDPDispatcherResult{}

	// Get dispatcher program info
	progInfo, err := dispatcherProg.Info()
	if err != nil {
		lnk.Close()
		return nil, fmt.Errorf("get dispatcher program info: %w", err)
	}
	progID, ok := progInfo.ID()
	if !ok {
		lnk.Close()
		return nil, fmt.Errorf("failed to get dispatcher program ID from kernel")
	}
	result.DispatcherID = uint32(progID)

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return nil, fmt.Errorf("get dispatcher link info: %w", err)
	}
	result.LinkID = uint32(linkInfo.ID)

	// Pin dispatcher and link if pinDir provided
	if pinDir != "" {
		if err := os.MkdirAll(pinDir, 0755); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("create dispatcher pin directory: %w", err)
		}

		// Pin dispatcher program
		dispatcherPinPath := filepath.Join(pinDir, "xdp_dispatcher")
		if err := dispatcherProg.Pin(dispatcherPinPath); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("pin dispatcher program: %w", err)
		}
		result.DispatcherPin = dispatcherPinPath

		// Pin link
		linkPinPath := filepath.Join(pinDir, "link")
		if err := lnk.Pin(linkPinPath); err != nil {
			if rmErr := os.Remove(dispatcherPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
				k.logger.Warn("failed to remove dispatcher pin during cleanup", "path", dispatcherPinPath, "error", rmErr)
			}
			lnk.Close()
			return nil, fmt.Errorf("pin dispatcher link: %w", err)
		}
		result.LinkPin = linkPinPath
	}

	return result, nil
}

// AttachXDPDispatcherWithPaths loads and attaches an XDP dispatcher to an interface
// with explicit paths for the dispatcher program and link.
// This follows the Rust bpfman convention where:
//   - progPinPath: revision-specific path for the dispatcher program
//   - linkPinPath: stable path for the XDP link (outside revision directory)
//   - netnsPath: if non-empty, attachment is performed in that network namespace
func (k *kernelAdapter) AttachXDPDispatcherWithPaths(ctx context.Context, ifindex int, progPinPath, linkPinPath string, numProgs int, proceedOn uint32, netnsPath string) (*interpreter.XDPDispatcherResult, error) {
	// Configure the dispatcher
	// XDP_DISPATCHER_RETVAL (31) is returned by empty slots - we must include
	// this bit so the dispatcher continues past empty slots to the final XDP_PASS.
	const xdpDispatcherRetval = 31
	cfg := dispatcher.NewXDPConfig(numProgs)
	for i := 0; i < dispatcher.MaxPrograms; i++ {
		cfg.ChainCallActions[i] = proceedOn | (1 << xdpDispatcherRetval)
	}

	// Load the dispatcher spec with config injected
	spec, err := dispatcher.LoadXDPDispatcher(cfg)
	if err != nil {
		return nil, fmt.Errorf("load XDP dispatcher spec: %w", err)
	}

	// Create collection from spec
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("create XDP dispatcher collection: %w", err)
	}
	defer coll.Close()

	// Get the dispatcher program
	dispatcherProg := coll.Programs["xdp_dispatcher"]
	if dispatcherProg == nil {
		return nil, fmt.Errorf("xdp_dispatcher program not found in collection")
	}

	// Attach and pin in target namespace (if specified)
	if netnsPath != "" {
		k.logger.Debug("entering network namespace for XDP dispatcher attachment", "netns", netnsPath, "ifindex", ifindex)
	}

	var result *interpreter.XDPDispatcherResult
	err = netns.Run(netnsPath, func() error {
		// Attach to interface
		lnk, err := link.AttachXDP(link.XDPOptions{
			Program:   dispatcherProg,
			Interface: ifindex,
		})
		if err != nil {
			return fmt.Errorf("attach XDP dispatcher to ifindex %d: %w", ifindex, err)
		}

		result = &interpreter.XDPDispatcherResult{}

		// Get dispatcher program info
		progInfo, err := dispatcherProg.Info()
		if err != nil {
			lnk.Close()
			return fmt.Errorf("get dispatcher program info: %w", err)
		}
		progID, ok := progInfo.ID()
		if !ok {
			lnk.Close()
			return fmt.Errorf("failed to get dispatcher program ID from kernel")
		}
		result.DispatcherID = uint32(progID)

		// Get link info
		linkInfo, err := lnk.Info()
		if err != nil {
			lnk.Close()
			return fmt.Errorf("get dispatcher link info: %w", err)
		}
		result.LinkID = uint32(linkInfo.ID)

		// Pin dispatcher program to the revision-specific path
		if progPinPath != "" {
			progDir := filepath.Dir(progPinPath)
			if err := os.MkdirAll(progDir, 0755); err != nil {
				lnk.Close()
				return fmt.Errorf("create dispatcher program directory: %w", err)
			}

			if err := dispatcherProg.Pin(progPinPath); err != nil {
				lnk.Close()
				return fmt.Errorf("pin dispatcher program to %s: %w", progPinPath, err)
			}
			result.DispatcherPin = progPinPath
		}

		// Pin link to the stable path (outside revision directory)
		if linkPinPath != "" {
			linkDir := filepath.Dir(linkPinPath)
			if err := os.MkdirAll(linkDir, 0755); err != nil {
				if progPinPath != "" {
					if rmErr := os.Remove(progPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
						k.logger.Warn("failed to remove program pin during cleanup", "path", progPinPath, "error", rmErr)
					}
				}
				lnk.Close()
				return fmt.Errorf("create link pin directory: %w", err)
			}

			if err := lnk.Pin(linkPinPath); err != nil {
				if progPinPath != "" {
					if rmErr := os.Remove(progPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
						k.logger.Warn("failed to remove program pin during cleanup", "path", progPinPath, "error", rmErr)
					}
				}
				lnk.Close()
				return fmt.Errorf("pin dispatcher link to %s: %w", linkPinPath, err)
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

// AttachXDPExtension loads a program from ELF as Extension type and attaches
// it to a dispatcher slot.
//
// This is different from simple XDP attachment - the program must be loaded
// specifically as BPF_PROG_TYPE_EXT with the dispatcher as the attach target.
// The same ELF bytecode used for direct XDP attachment is reloaded with
// different type settings.
//
// The mapPinDir parameter specifies the directory containing the program's
// pinned maps. These maps are loaded and passed as MapReplacements so the
// extension program shares the same maps as the original loaded program.
func (k *kernelAdapter) AttachXDPExtension(ctx context.Context, dispatcherPinPath, objectPath, programName string, position int, linkPinPath, mapPinDir string) (bpfman.Link, error) {
	// Load the pinned dispatcher to use as attach target
	dispatcherProg, err := ebpf.LoadPinnedProgram(dispatcherPinPath, nil)
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("load pinned dispatcher %s: %w", dispatcherPinPath, err)
	}
	defer dispatcherProg.Close()

	// Load the collection spec from the ELF file
	collSpec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("load collection spec from %s: %w", objectPath, err)
	}

	// Verify the program exists in the collection
	progSpec, ok := collSpec.Programs[programName]
	if !ok {
		return bpfman.Link{}, fmt.Errorf("program %q not found in %s", programName, objectPath)
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
				return bpfman.Link{}, fmt.Errorf("load pinned map %s: %w", mapPath, err)
			}
			mapReplacements[name] = m
			k.logger.Debug("loaded pinned map for extension", "name", name, "path", mapPath)
		}
	}

	// Ensure we close loaded maps on error or when done
	closeMapReplacements := func() {
		for _, m := range mapReplacements {
			m.Close()
		}
	}

	// Clear map pinning flags - maps will come from MapReplacements
	for _, mapSpec := range collSpec.Maps {
		mapSpec.Pinning = ebpf.PinNone
	}

	// Load the collection with map replacements from the original program.
	// This ensures the extension uses the same maps that were pinned during Load.
	coll, err := ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	})
	if err != nil {
		closeMapReplacements()
		return bpfman.Link{}, fmt.Errorf("load extension collection: %w", err)
	}
	defer coll.Close()
	// Note: maps in mapReplacements are now owned by the collection or
	// were used as replacements. We don't close them here as the collection
	// manages their lifecycle.

	// Get the loaded extension program
	extensionProg := coll.Programs[programName]
	if extensionProg == nil {
		return bpfman.Link{}, fmt.Errorf("extension program %q not in loaded collection", programName)
	}

	// Attach the extension using freplace link
	lnk, err := link.AttachFreplace(dispatcherProg, progSpec.AttachTo, extensionProg)
	if err != nil {
		return bpfman.Link{}, fmt.Errorf("attach freplace to %s: %w", progSpec.AttachTo, err)
	}

	// Pin the link if path provided
	if linkPinPath != "" {
		if err := pinWithRetry(lnk, linkPinPath); err != nil {
			lnk.Close()
			return bpfman.Link{}, fmt.Errorf("pin extension link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.Link{}, fmt.Errorf("get link info: %w", err)
	}

	kernelLinkID := uint32(linkInfo.ID)
	return bpfman.Link{
		Managed: bpfman.LinkRecord{
			Kind:         bpfman.LinkKindXDP, // XDP extension
			KernelLinkID: &kernelLinkID,
			PinPath:      linkPinPath,
			CreatedAt:    time.Now(),
			Details:      bpfman.XDPDetails{Position: int32(position)},
		},
		Kernel: *ToKernelLink(linkInfo),
	}, nil
}
