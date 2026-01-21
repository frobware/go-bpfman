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

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/kernel"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

// Kernel implements interpreter.KernelOperations using cilium/ebpf.
type Kernel struct{}

// New creates a new kernel adapter.
func New() *Kernel {
	return &Kernel{}
}

// GetProgramByID retrieves a kernel program by its ID.
func (k *Kernel) GetProgramByID(ctx context.Context, id uint32) (kernel.Program, error) {
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
func (k *Kernel) GetLinkByID(ctx context.Context, id uint32) (kernel.Link, error) {
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
func (k *Kernel) GetMapByID(ctx context.Context, id uint32) (kernel.Map, error) {
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
func (k *Kernel) Programs(ctx context.Context) iter.Seq2[kernel.Program, error] {
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
func (k *Kernel) Maps(ctx context.Context) iter.Seq2[kernel.Map, error] {
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
func (k *Kernel) Links(ctx context.Context) iter.Seq2[kernel.Link, error] {
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
// Creates the pin directory if it doesn't exist. On bpffs, directory
// creation typically works with appropriate privileges (CAP_SYS_ADMIN
// or mount with allow_other).
func (k *Kernel) Load(ctx context.Context, spec managed.LoadSpec) (managed.Loaded, error) {
	// Create pin directory if it doesn't exist
	if err := os.MkdirAll(spec.PinPath, 0755); err != nil {
		return managed.Loaded{}, fmt.Errorf("create pin directory %q: %w", spec.PinPath, err)
	}

	// Load the collection from the object file
	collSpec, err := ebpf.LoadCollectionSpec(spec.ObjectPath)
	if err != nil {
		return managed.Loaded{}, fmt.Errorf("failed to load collection spec: %w", err)
	}

	// Set global data if provided
	for name, data := range spec.GlobalData {
		if err := collSpec.RewriteConstants(map[string]interface{}{name: data}); err != nil {
			// Ignore errors for constants that don't exist
		}
	}

	// Load with pinning
	opts := &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: spec.PinPath,
		},
		Programs: ebpf.ProgramOptions{},
	}

	coll, err := ebpf.NewCollectionWithOptions(collSpec, *opts)
	if err != nil {
		return managed.Loaded{}, fmt.Errorf("failed to load collection: %w", err)
	}
	// Always close the collection - pinning creates kernel references
	// that persist independently of the file descriptors we hold here.
	defer coll.Close()

	// Find the requested program
	prog, ok := coll.Programs[spec.ProgramName]
	if !ok {
		return managed.Loaded{}, fmt.Errorf("program %q not found in collection", spec.ProgramName)
	}

	// Pin the program
	progPinPath := filepath.Join(spec.PinPath, spec.ProgramName)
	if err := prog.Pin(progPinPath); err != nil {
		return managed.Loaded{}, fmt.Errorf("failed to pin program: %w", err)
	}

	// Explicitly pin all maps (skip internal maps like .rodata, .bss, .data)
	for name, m := range coll.Maps {
		// Skip internal maps - these are compiler-generated sections that
		// become maps, and they don't need to be pinned separately.
		// Also, bpffs paths starting with '.' can be problematic.
		if strings.HasPrefix(name, ".") {
			continue
		}
		mapPinPath := filepath.Join(spec.PinPath, name)
		if err := m.Pin(mapPinPath); err != nil {
			// Ignore if already pinned
			if !os.IsExist(err) {
				return managed.Loaded{}, fmt.Errorf("failed to pin map %q: %w", name, err)
			}
		}
	}

	info, err := prog.Info()
	if err != nil {
		return managed.Loaded{}, fmt.Errorf("failed to get program info: %w", err)
	}

	progID, _ := info.ID()
	ebpfMapIDs, _ := info.MapIDs()
	mapIDs := make([]uint32, len(ebpfMapIDs))
	for i, mid := range ebpfMapIDs {
		mapIDs[i] = uint32(mid)
	}

	return managed.Loaded{
		ID:          uint32(progID),
		Name:        spec.ProgramName,
		ProgramType: spec.ProgramType,
		PinPath:     progPinPath,
		MapIDs:      mapIDs,
	}, nil
}

// Unload removes a BPF program from the kernel by unpinning.
func (k *Kernel) Unload(ctx context.Context, pinPath string) error {
	entries, err := os.ReadDir(pinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
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
func (k *Kernel) ListPinDir(pinDir string, includeMaps bool) (*kernel.PinDirContents, error) {
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
func (k *Kernel) GetPinned(pinPath string) (*kernel.PinnedProgram, error) {
	prog, err := ebpf.LoadPinnedProgram(pinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to load pinned program: %w", err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get program info: %w", err)
	}

	id, _ := info.ID()
	ebpfMapIDs, _ := info.MapIDs()
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
func (k *Kernel) LoadSingle(ctx context.Context, objectPath, programName, pinDir string) (*kernel.LoadResult, error) {
	// Create pin directory for CLI convenience
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create pin directory: %w", err)
	}

	spec := managed.LoadSpec{
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
	entries, _ := os.ReadDir(pinDir)
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
			ID:         loaded.ID,
			Name:       loaded.Name,
			Type:       loaded.ProgramType.String(),
			PinnedPath: loaded.PinPath,
			MapIDs:     loaded.MapIDs,
		},
		Maps:   maps,
		PinDir: pinDir,
	}, nil
}

// RepinMap loads a pinned map and re-pins it to a new path.
// This is used by CSI to expose maps to per-pod bpffs.
func (k *Kernel) RepinMap(srcPath, dstPath string) error {
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
func (k *Kernel) Unpin(pinDir string) (int, error) {
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
func (k *Kernel) DetachLink(linkPinPath string) error {
	if err := os.Remove(linkPinPath); err != nil {
		if os.IsNotExist(err) {
			return nil // Already gone
		}
		return fmt.Errorf("remove link pin %s: %w", linkPinPath, err)
	}
	return nil
}

// AttachTracepoint attaches a pinned program to a tracepoint.
func (k *Kernel) AttachTracepoint(progPinPath, group, name, linkPinPath string) (*bpfman.AttachedLink, error) {
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	lnk, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		return nil, fmt.Errorf("attach to tracepoint %s:%s: %w", group, name, err)
	}

	result := &bpfman.AttachedLink{
		Type: bpfman.AttachTracepoint,
	}

	// Pin the link if a path is provided
	if linkPinPath != "" {
		// Ensure parent directory exists
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("create link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("pin link to %s: %w", linkPinPath, err)
		}
		result.PinPath = linkPinPath
	}

	// Get link info if available
	info, err := lnk.Info()
	if err == nil {
		result.ID = uint32(info.ID)
	}

	return result, nil
}

// AttachXDP attaches a pinned XDP program to a network interface.
func (k *Kernel) AttachXDP(progPinPath string, ifindex int, linkPinPath string) (*bpfman.AttachedLink, error) {
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		return nil, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   prog,
		Interface: ifindex,
	})
	if err != nil {
		return nil, fmt.Errorf("attach XDP to ifindex %d: %w", ifindex, err)
	}

	result := &bpfman.AttachedLink{
		Type: bpfman.AttachXDP,
	}

	// Pin the link if a path is provided
	if linkPinPath != "" {
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("create link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("pin link to %s: %w", linkPinPath, err)
		}
		result.PinPath = linkPinPath
	}

	// Get link info if available
	info, err := lnk.Info()
	if err == nil {
		result.ID = uint32(info.ID)
	}

	return result, nil
}
