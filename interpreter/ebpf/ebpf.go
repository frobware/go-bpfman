// Package ebpf provides kernel operations using cilium/ebpf.
package ebpf

import (
	"context"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/kernel"
)

// kernelAdapter implements interpreter.KernelOperations using cilium/ebpf.
type kernelAdapter struct{}

// New creates a new kernel adapter.
func New() interpreter.KernelOperations {
	return &kernelAdapter{}
}

// GetProgramByID retrieves a kernel program by its ID.
func (k *kernelAdapter) GetProgramByID(ctx context.Context, id uint32) (kernel.Program, error) {
	prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
	if err != nil {
		return kernel.Program{}, fmt.Errorf("program %d: %w", id, err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return kernel.Program{}, fmt.Errorf("get info for program %d: %w", id, err)
	}

	return infoToProgram(info, id), nil
}

// GetLinkByID retrieves a kernel link by its ID.
func (k *kernelAdapter) GetLinkByID(ctx context.Context, id uint32) (kernel.Link, error) {
	lnk, err := link.NewFromID(link.ID(id))
	if err != nil {
		return kernel.Link{}, fmt.Errorf("link %d: %w", id, err)
	}
	defer lnk.Close()

	info, err := lnk.Info()
	if err != nil {
		return kernel.Link{}, fmt.Errorf("get info for link %d: %w", id, err)
	}

	return infoToLink(info), nil
}

// GetMapByID retrieves a kernel map by its ID.
func (k *kernelAdapter) GetMapByID(ctx context.Context, id uint32) (kernel.Map, error) {
	m, err := ebpf.NewMapFromID(ebpf.MapID(id))
	if err != nil {
		return kernel.Map{}, fmt.Errorf("map %d: %w", id, err)
	}
	defer m.Close()

	info, err := m.Info()
	if err != nil {
		return kernel.Map{}, fmt.Errorf("get info for map %d: %w", id, err)
	}

	return infoToMap(info, id), nil
}

// Programs returns an iterator over kernel BPF programs.
func (k *kernelAdapter) Programs(ctx context.Context) iter.Seq2[kernel.Program, error] {
	return func(yield func(kernel.Program, error) bool) {
		var id ebpf.ProgramID
		for {
			nextID, err := ebpf.ProgramGetNextID(id)
			if err != nil {
				return // No more programs
			}
			id = nextID

			prog, err := ebpf.NewProgramFromID(id)
			if err != nil {
				if !yield(kernel.Program{}, err) {
					return
				}
				continue
			}

			info, err := prog.Info()
			prog.Close()
			if err != nil {
				if !yield(kernel.Program{}, err) {
					return
				}
				continue
			}

			kp := infoToProgram(info, uint32(id))
			if !yield(kp, nil) {
				return
			}
		}
	}
}

// Maps returns an iterator over kernel BPF maps.
func (k *kernelAdapter) Maps(ctx context.Context) iter.Seq2[kernel.Map, error] {
	return func(yield func(kernel.Map, error) bool) {
		var id ebpf.MapID
		for {
			nextID, err := ebpf.MapGetNextID(id)
			if err != nil {
				return
			}
			id = nextID

			m, err := ebpf.NewMapFromID(id)
			if err != nil {
				if !yield(kernel.Map{}, err) {
					return
				}
				continue
			}

			info, err := m.Info()
			m.Close()
			if err != nil {
				if !yield(kernel.Map{}, err) {
					return
				}
				continue
			}

			km := infoToMap(info, uint32(id))
			if !yield(km, nil) {
				return
			}
		}
	}
}

// Links returns an iterator over kernel BPF links.
func (k *kernelAdapter) Links(ctx context.Context) iter.Seq2[kernel.Link, error] {
	return func(yield func(kernel.Link, error) bool) {
		it := new(link.Iterator)
		defer it.Close()

		for it.Next() {
			info, err := it.Link.Info()
			if err != nil {
				if !yield(kernel.Link{}, err) {
					return
				}
				continue
			}

			kl := infoToLink(info)
			if !yield(kl, nil) {
				return
			}
		}

		if err := it.Err(); err != nil {
			yield(kernel.Link{}, err)
		}
	}
}

// Load loads a BPF program into the kernel.
//
// Load loads a BPF program and pins it using kernel ID-based paths.
//
// Pin paths follow the upstream bpfman convention:
//   - Program: <root>/prog_<kernel_id>
//   - Maps: <root>/maps/<kernel_id>/<map_name>
//
// spec.PinPath is the bpffs root (e.g., /run/bpfman/fs/).
// On failure, all successfully pinned objects are cleaned up.
func (k *kernelAdapter) Load(ctx context.Context, spec bpfman.LoadSpec) (bpfman.ManagedProgram, error) {
	// Load the collection from the object file
	collSpec, err := ebpf.LoadCollectionSpec(spec.ObjectPath)
	if err != nil {
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to load collection spec: %w", err)
	}

	// Set global data if provided
	for name, data := range spec.GlobalData {
		if err := collSpec.RewriteConstants(map[string]interface{}{name: data}); err != nil {
			// Ignore errors for constants that don't exist
		}
	}

	// Load collection WITHOUT pinning - we'll pin after getting kernel ID
	coll, err := ebpf.NewCollection(collSpec)
	if err != nil {
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to load collection: %w", err)
	}
	defer coll.Close()

	// Find the requested program
	prog, ok := coll.Programs[spec.ProgramName]
	if !ok {
		return bpfman.ManagedProgram{}, fmt.Errorf("program %q not found in collection", spec.ProgramName)
	}

	// Get program info to obtain kernel ID
	info, err := prog.Info()
	if err != nil {
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to get program info: %w", err)
	}
	progID, ok := info.ID()
	if !ok {
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to get program ID from kernel")
	}
	kernelID := uint32(progID)

	// Track pinned paths for rollback on failure
	var pinnedPaths []string
	cleanup := func() {
		for i := len(pinnedPaths) - 1; i >= 0; i-- {
			os.Remove(pinnedPaths[i])
		}
	}

	// Pin program to <root>/prog_<kernel_id>
	progPinPath := filepath.Join(spec.PinPath, fmt.Sprintf("prog_%d", kernelID))
	if err := prog.Pin(progPinPath); err != nil {
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to pin program: %w", err)
	}
	pinnedPaths = append(pinnedPaths, progPinPath)

	// Create maps directory: <root>/maps/<kernel_id>/
	mapsDir := filepath.Join(spec.PinPath, "maps", fmt.Sprintf("%d", kernelID))
	if err := os.MkdirAll(mapsDir, 0755); err != nil {
		cleanup()
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to create maps directory: %w", err)
	}

	// Pin all maps (skip internal maps like .rodata, .bss, .data)
	for name, m := range coll.Maps {
		if strings.HasPrefix(name, ".") {
			continue
		}
		mapPinPath := filepath.Join(mapsDir, sanitiseFilename(name))
		if err := m.Pin(mapPinPath); err != nil {
			cleanup()
			// Also remove the maps directory
			os.Remove(mapsDir)
			return bpfman.ManagedProgram{}, fmt.Errorf("failed to pin map %q: %w", name, err)
		}
		pinnedPaths = append(pinnedPaths, mapPinPath)
	}

	ebpfMapIDs, ok := info.MapIDs()
	if !ok {
		cleanup()
		os.Remove(mapsDir)
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to get map IDs from kernel")
	}
	_ = ebpfMapIDs // MapIDs now accessed via KernelProgramInfo

	return bpfman.ManagedProgram{
		Managed: &bpfman.ProgramInfo{
			Name:       spec.ProgramName,
			Type:       spec.ProgramType,
			ObjectPath: spec.ObjectPath,
			PinPath:    progPinPath,
			PinDir:     mapsDir,
		},
		Kernel: NewProgramInfo(info),
	}, nil
}

// Unload removes a BPF program from the kernel by unpinning.
// Handles both old-style (directory containing everything) and new-style
// (separate program pin and maps directory) layouts.
func (k *kernelAdapter) Unload(ctx context.Context, pinPath string) error {
	info, err := os.Stat(pinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat pin path: %w", err)
	}

	// If it's a file (program pin), just remove it
	if !info.IsDir() {
		if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to unpin %s: %w", pinPath, err)
		}
		return nil
	}

	// It's a directory - remove contents then directory
	entries, err := os.ReadDir(pinPath)
	if err != nil {
		return fmt.Errorf("failed to read pin directory: %w", err)
	}

	for _, e := range entries {
		path := filepath.Join(pinPath, e.Name())
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to unpin %s: %w", path, err)
		}
	}

	if err := os.Remove(pinPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove pin directory: %w", err)
	}

	return nil
}

// UnloadProgram removes a program and its maps using the upstream pin layout.
// progPinPath is the program pin (e.g., /run/bpfman/fs/prog_123)
// mapsDir is the maps directory (e.g., /run/bpfman/fs/maps/123)
func (k *kernelAdapter) UnloadProgram(ctx context.Context, progPinPath, mapsDir string) error {
	// Remove program pin
	if err := os.Remove(progPinPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to unpin program %s: %w", progPinPath, err)
	}

	// Remove maps directory and contents
	if mapsDir != "" {
		if err := k.Unload(ctx, mapsDir); err != nil {
			return fmt.Errorf("failed to unload maps: %w", err)
		}
	}

	return nil
}

// bootTime returns the system boot time by reading /proc/stat.
// Falls back to time.Now() if /proc/stat cannot be read.
func bootTime() time.Time {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return time.Now()
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "btime ") {
			var btime int64
			if _, err := fmt.Sscanf(line, "btime %d", &btime); err == nil {
				return time.Unix(btime, 0)
			}
		}
	}
	return time.Now()
}

func infoToProgram(info *ebpf.ProgramInfo, id uint32) kernel.Program {
	ebpfMapIDs, _ := info.MapIDs()
	mapIDs := make([]uint32, len(ebpfMapIDs))
	for i, mid := range ebpfMapIDs {
		mapIDs[i] = uint32(mid)
	}

	kp := kernel.Program{
		ID:          id,
		Name:        info.Name,
		ProgramType: info.Type.String(),
		Tag:         info.Tag,
		MapIDs:      mapIDs,
	}

	if uid, ok := info.CreatedByUID(); ok {
		kp.UID = uid
	}
	if loadTime, ok := info.LoadTime(); ok {
		// LoadTime is nanoseconds since boot, convert to wall clock time
		kp.LoadedAt = bootTime().Add(loadTime)
	}
	if btfID, ok := info.BTFID(); ok {
		kp.BTFId = uint32(btfID)
	}
	if jitedSize, err := info.JitedSize(); err == nil {
		kp.JitedSize = jitedSize
	}
	if xlatedSize, err := info.TranslatedSize(); err == nil {
		kp.XlatedSize = uint32(xlatedSize)
	}

	return kp
}

func infoToMap(info *ebpf.MapInfo, id uint32) kernel.Map {
	return kernel.Map{
		ID:         id,
		Name:       info.Name,
		MapType:    info.Type.String(),
		KeySize:    info.KeySize,
		ValueSize:  info.ValueSize,
		MaxEntries: info.MaxEntries,
		Flags:      uint32(info.Flags),
	}
}

func infoToLink(info *link.Info) kernel.Link {
	kl := kernel.Link{
		ID:        uint32(info.ID),
		ProgramID: uint32(info.Program),
		LinkType:  linkTypeString(info.Type),
	}

	// Extract type-specific info where available.
	if tracing := info.Tracing(); tracing != nil {
		kl.AttachType = fmt.Sprintf("%d", tracing.AttachType)
		kl.TargetObjID = tracing.TargetObjId
		kl.TargetBTFId = uint32(tracing.TargetBtfId)
	} else if xdp := info.XDP(); xdp != nil {
		kl.TargetObjID = xdp.Ifindex
	} else if tcx := info.TCX(); tcx != nil {
		kl.AttachType = fmt.Sprintf("%d", tcx.AttachType)
		kl.TargetObjID = tcx.Ifindex
	} else if cgroup := info.Cgroup(); cgroup != nil {
		kl.AttachType = fmt.Sprintf("%d", cgroup.AttachType)
	} else if netns := info.NetNs(); netns != nil {
		kl.AttachType = fmt.Sprintf("%d", netns.AttachType)
		kl.TargetObjID = netns.NetnsIno
	} else if netkit := info.Netkit(); netkit != nil {
		kl.AttachType = fmt.Sprintf("%d", netkit.AttachType)
		kl.TargetObjID = netkit.Ifindex
	}

	return kl
}

// linkTypeString converts a link.Type to a human-readable string.
func linkTypeString(t link.Type) string {
	// These values come from include/uapi/linux/bpf.h (BPF_LINK_TYPE_*)
	names := map[link.Type]string{
		0:  "unspec",
		1:  "raw_tracepoint",
		2:  "tracing",
		3:  "cgroup",
		4:  "iter",
		5:  "netns",
		6:  "xdp",
		7:  "perf_event",
		8:  "kprobe_multi",
		9:  "struct_ops",
		10: "netfilter",
		11: "tcx",
		12: "uprobe_multi",
		13: "netkit",
	}
	if name, ok := names[t]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", t)
}

// ============================================================================
// CLI helpers - filesystem-based operations for scanning bpffs
// ============================================================================

// ListPinDir scans a bpffs directory and returns its contents.
func (k *kernelAdapter) ListPinDir(pinDir string, includeMaps bool) (*kernel.PinDirContents, error) {
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read pin directory: %w", err)
	}

	result := &kernel.PinDirContents{}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(pinDir, entry.Name())

		// Try to load as program first
		prog, err := ebpf.LoadPinnedProgram(path, nil)
		if err == nil {
			info, _ := prog.Info()
			if info != nil {
				id, _ := info.ID()
				ebpfMapIDs, _ := info.MapIDs()
				mapIDs := make([]uint32, len(ebpfMapIDs))
				for i, mid := range ebpfMapIDs {
					mapIDs[i] = uint32(mid)
				}
				result.Programs = append(result.Programs, kernel.PinnedProgram{
					ID:         uint32(id),
					Name:       info.Name,
					Type:       prog.Type().String(),
					Tag:        info.Tag,
					PinnedPath: path,
					MapIDs:     mapIDs,
				})
			}
			prog.Close()
			continue
		}

		// Try as map if includeMaps
		if includeMaps {
			mp, err := ebpf.LoadPinnedMap(path, nil)
			if err == nil {
				info, _ := mp.Info()
				if info != nil {
					id, _ := info.ID()
					result.Maps = append(result.Maps, kernel.PinnedMap{
						ID:         uint32(id),
						Name:       info.Name,
						Type:       info.Type.String(),
						KeySize:    info.KeySize,
						ValueSize:  info.ValueSize,
						MaxEntries: info.MaxEntries,
						PinnedPath: path,
					})
				}
				mp.Close()
			}
		}
	}

	return result, nil
}

// GetPinned loads and returns info about a pinned program.
func (k *kernelAdapter) GetPinned(pinPath string) (*kernel.PinnedProgram, error) {
	prog, err := ebpf.LoadPinnedProgram(pinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load pinned program: %w", err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get program info: %w", err)
	}

	id, ok := info.ID()
	if !ok {
		return nil, fmt.Errorf("failed to get program ID from kernel")
	}
	ebpfMapIDs, _ := info.MapIDs() // MapIDs may not be available on older kernels
	mapIDs := make([]uint32, len(ebpfMapIDs))
	for i, mid := range ebpfMapIDs {
		mapIDs[i] = uint32(mid)
	}

	return &kernel.PinnedProgram{
		ID:         uint32(id),
		Name:       info.Name,
		Type:       prog.Type().String(),
		Tag:        info.Tag,
		PinnedPath: pinPath,
		MapIDs:     mapIDs,
	}, nil
}

// LoadSingle loads a single program and returns CLI-friendly output.
// This is a convenience method for CLI usage that creates the pin directory
// if it doesn't exist. For transactional loads, use Manager.Load instead.
func (k *kernelAdapter) LoadSingle(ctx context.Context, objectPath, programName, pinDir string) (*kernel.LoadResult, error) {
	// Create pin directory for CLI convenience
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create pin directory: %w", err)
	}

	spec := bpfman.LoadSpec{
		ObjectPath:  objectPath,
		ProgramName: programName,
		PinPath:     pinDir,
	}

	loaded, err := k.Load(ctx, spec)
	if err != nil {
		return nil, err
	}

	// Get map info from the pin directory
	var maps []kernel.PinnedMap
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read pin directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == programName {
			continue
		}
		path := filepath.Join(pinDir, entry.Name())
		mp, err := ebpf.LoadPinnedMap(path, nil)
		if err == nil {
			info, _ := mp.Info()
			if info != nil {
				id, _ := info.ID()
				maps = append(maps, kernel.PinnedMap{
					ID:         uint32(id),
					Name:       info.Name,
					Type:       info.Type.String(),
					KeySize:    info.KeySize,
					ValueSize:  info.ValueSize,
					MaxEntries: info.MaxEntries,
					PinnedPath: path,
				})
			}
			mp.Close()
		}
	}

	return &kernel.LoadResult{
		Program: kernel.PinnedProgram{
			ID:         loaded.Kernel.ID(),
			Name:       loaded.Managed.Name,
			Type:       loaded.Kernel.Type().String(),
			PinnedPath: loaded.Managed.PinPath,
			MapIDs:     loaded.Kernel.MapIDs(),
		},
		Maps:   maps,
		PinDir: pinDir,
	}, nil
}

// RepinMap loads a pinned map and re-pins it to a new path.
// This is used by CSI to expose maps to per-pod bpffs.
func (k *kernelAdapter) RepinMap(srcPath, dstPath string) error {
	m, err := ebpf.LoadPinnedMap(srcPath, nil)
	if err != nil {
		return fmt.Errorf("load pinned map %s: %w", srcPath, err)
	}
	defer m.Close()

	// Clone the map FD to get a map without pin path tracking.
	// This avoids the "invalid cross-device link" error when pinning
	// to a different bpffs instance, since cilium/ebpf tries to
	// rename/move the old pin when Pin() is called on an already-pinned map.
	cloned, err := m.Clone()
	if err != nil {
		return fmt.Errorf("clone map: %w", err)
	}
	defer cloned.Close()

	if err := cloned.Pin(dstPath); err != nil {
		return fmt.Errorf("re-pin map to %s: %w", dstPath, err)
	}
	return nil
}

// Unpin removes all pins from a directory.
func (k *kernelAdapter) Unpin(pinDir string) (int, error) {
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("failed to read pin directory: %w", err)
	}

	count := 0
	for _, entry := range entries {
		path := filepath.Join(pinDir, entry.Name())
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return count, fmt.Errorf("failed to unpin %s: %w", path, err)
		}
		count++
	}

	if err := os.Remove(pinDir); err != nil && !os.IsNotExist(err) {
		return count, fmt.Errorf("failed to remove pin directory: %w", err)
	}

	return count, nil
}

// DetachLink removes a pinned link by deleting its pin from bpffs.
// This releases the kernel link if it was the last reference.
func (k *kernelAdapter) DetachLink(linkPinPath string) error {
	if err := os.Remove(linkPinPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already gone
		}
		return fmt.Errorf("remove link pin %s: %w", linkPinPath, err)
	}
	return nil
}

// RemovePin removes a pin or empty directory from bpffs.
// Returns nil if the path does not exist.
func (k *kernelAdapter) RemovePin(path string) error {
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil // Already gone
		}
		return fmt.Errorf("remove pin %s: %w", path, err)
	}
	return nil
}

// AttachTracepoint attaches a pinned program to a tracepoint.
func (k *kernelAdapter) AttachTracepoint(progPinPath, group, name, linkPinPath string) (bpfman.ManagedLink, error) {
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	// Get program info to find kernel program ID
	progInfo, err := prog.Info()
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("get program info: %w", err)
	}
	progID, _ := progInfo.ID()

	lnk, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach to tracepoint %s:%s: %w", group, name, err)
	}

	// Pin the link if a path is provided
	if linkPinPath != "" {
		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("create link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("pin link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.ManagedLink{}, fmt.Errorf("get link info: %w", err)
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            bpfman.LinkTypeTracepoint,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.TracepointDetails{Group: group, Name: name},
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}

// AttachXDP attaches a pinned XDP program to a network interface.
func (k *kernelAdapter) AttachXDP(progPinPath string, ifindex int, linkPinPath string) (bpfman.ManagedLink, error) {
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	// Get program info to find kernel program ID
	progInfo, err := prog.Info()
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("get program info: %w", err)
	}
	progID, _ := progInfo.ID()

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
	})
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, err)
	}

	// Pin the link if a path is provided
	if linkPinPath != "" {
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("create link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("pin link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.ManagedLink{}, fmt.Errorf("get link info: %w", err)
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            bpfman.LinkTypeXDP,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.XDPDetails{Ifindex: uint32(ifindex)},
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}

// AttachXDPDispatcher loads and attaches an XDP dispatcher to an interface.
// The dispatcher allows multiple XDP programs to be chained together.
func (k *kernelAdapter) AttachXDPDispatcher(ifindex int, pinDir string, numProgs int, proceedOn uint32) (*interpreter.XDPDispatcherResult, error) {
	// Configure the dispatcher
	cfg := dispatcher.NewXDPConfig(numProgs)
	for i := 0; i < dispatcher.MaxPrograms; i++ {
		cfg.ChainCallActions[i] = proceedOn
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
			os.Remove(dispatcherPinPath)
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
func (k *kernelAdapter) AttachXDPDispatcherWithPaths(ifindex int, progPinPath, linkPinPath string, numProgs int, proceedOn uint32) (*interpreter.XDPDispatcherResult, error) {
	// Configure the dispatcher
	cfg := dispatcher.NewXDPConfig(numProgs)
	for i := 0; i < dispatcher.MaxPrograms; i++ {
		cfg.ChainCallActions[i] = proceedOn
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

	// Pin dispatcher program to the revision-specific path
	if progPinPath != "" {
		progDir := filepath.Dir(progPinPath)
		if err := os.MkdirAll(progDir, 0755); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("create dispatcher program directory: %w", err)
		}

		if err := dispatcherProg.Pin(progPinPath); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("pin dispatcher program to %s: %w", progPinPath, err)
		}
		result.DispatcherPin = progPinPath
	}

	// Pin link to the stable path (outside revision directory)
	if linkPinPath != "" {
		linkDir := filepath.Dir(linkPinPath)
		if err := os.MkdirAll(linkDir, 0755); err != nil {
			if progPinPath != "" {
				os.Remove(progPinPath)
			}
			lnk.Close()
			return nil, fmt.Errorf("create link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			if progPinPath != "" {
				os.Remove(progPinPath)
			}
			lnk.Close()
			return nil, fmt.Errorf("pin dispatcher link to %s: %w", linkPinPath, err)
		}
		result.LinkPin = linkPinPath
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
func (k *kernelAdapter) AttachXDPExtension(dispatcherPinPath, objectPath, programName string, position int, linkPinPath string) (bpfman.ManagedLink, error) {
	// Load the pinned dispatcher to use as attach target
	dispatcherProg, err := ebpf.LoadPinnedProgram(dispatcherPinPath, nil)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load pinned dispatcher %s: %w", dispatcherPinPath, err)
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

	// Load the collection with the modified program spec.
	// This ensures any maps the program depends on are also loaded.
	coll, err := ebpf.NewCollection(collSpec)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("load extension collection: %w", err)
	}
	defer coll.Close()

	// Get the loaded extension program
	extensionProg := coll.Programs[programName]
	if extensionProg == nil {
		return bpfman.ManagedLink{}, fmt.Errorf("extension program %q not in loaded collection", programName)
	}

	// Get program info for the extension
	progInfo, err := extensionProg.Info()
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("get extension program info: %w", err)
	}
	progID, _ := progInfo.ID()

	// Attach the extension using freplace link
	lnk, err := link.AttachFreplace(dispatcherProg, progSpec.AttachTo, extensionProg)
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach freplace to %s: %w", progSpec.AttachTo, err)
	}

	// Pin the link if path provided
	if linkPinPath != "" {
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("create extension link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("pin extension link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.ManagedLink{}, fmt.Errorf("get link info: %w", err)
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            bpfman.LinkTypeXDP, // XDP extension
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.XDPDetails{Position: int32(position)},
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}

// sanitiseFilename replaces characters that are invalid in filenames.
func sanitiseFilename(s string) string {
	var result []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}
