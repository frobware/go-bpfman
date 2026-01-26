// Package ebpf provides kernel operations using cilium/ebpf.
package ebpf

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/kernel"
	"github.com/frobware/go-bpfman/netns"
	"github.com/frobware/go-bpfman/nsenter"
)

// generateSyntheticLinkID creates a unique ID for perf_event-based links that
// lack kernel link IDs (e.g., container uprobes on kernels < 5.15). IDs are
// generated in the range 0x80000000-0xFFFFFFFF to avoid collision with real
// kernel link IDs which are small sequential numbers.
func generateSyntheticLinkID() uint32 {
	// Generate random ID in high range (SyntheticLinkIDBase+)
	return bpfman.SyntheticLinkIDBase | rand.Uint32()
}

// inferProgramType returns the program type based on the ELF section name.
// This follows the Rust bpfman approach of deriving the type from bytecode
// metadata rather than relying on user-specified types.
//
// Section name patterns (from cilium/ebpf elf_sections.go):
//   - kprobe/*, kprobe.multi/* -> kprobe
//   - kretprobe/*, kretprobe.multi/* -> kretprobe
//   - uprobe/*, uprobe.multi/* -> uprobe
//   - uretprobe/*, uretprobe.multi/* -> uretprobe
//   - tracepoint/* -> tracepoint
//   - xdp*, xdp.frags* -> xdp
//   - tc, classifier/* -> tc
//   - tcx/* -> tcx
//   - fentry/* -> fentry
//   - fexit/* -> fexit
func inferProgramType(sectionName string) bpfman.ProgramType {
	// Remove optional program marking prefix
	sectionName = strings.TrimPrefix(sectionName, "?")

	switch {
	case strings.HasPrefix(sectionName, "kretprobe"):
		return bpfman.ProgramTypeKretprobe
	case strings.HasPrefix(sectionName, "kprobe"):
		return bpfman.ProgramTypeKprobe
	case strings.HasPrefix(sectionName, "uretprobe"):
		return bpfman.ProgramTypeUretprobe
	case strings.HasPrefix(sectionName, "uprobe"):
		return bpfman.ProgramTypeUprobe
	case strings.HasPrefix(sectionName, "tracepoint"):
		return bpfman.ProgramTypeTracepoint
	case strings.HasPrefix(sectionName, "fentry"):
		return bpfman.ProgramTypeFentry
	case strings.HasPrefix(sectionName, "fexit"):
		return bpfman.ProgramTypeFexit
	case strings.HasPrefix(sectionName, "xdp"):
		return bpfman.ProgramTypeXDP
	case strings.HasPrefix(sectionName, "tcx"):
		return bpfman.ProgramTypeTCX
	case strings.HasPrefix(sectionName, "tc") || strings.HasPrefix(sectionName, "classifier"):
		return bpfman.ProgramTypeTC
	default:
		return bpfman.ProgramTypeUnspecified
	}
}

// kernelAdapter implements interpreter.KernelOperations using cilium/ebpf.
type kernelAdapter struct {
	logger *slog.Logger

	// linkFds stores file descriptors for perf_event-based links that cannot
	// be pinned to bpffs. The uprobe attachment remains active as long as the
	// fd is open. Key is a unique identifier (e.g., "containerPid:target:fnName").
	linkFds sync.Map
}

// Option configures a kernelAdapter.
type Option func(*kernelAdapter)

// WithLogger sets the logger for kernel operations.
func WithLogger(logger *slog.Logger) Option {
	return func(k *kernelAdapter) {
		k.logger = logger
	}
}

// New creates a new kernel adapter.
func New(opts ...Option) interpreter.KernelOperations {
	k := &kernelAdapter{
		logger: slog.Default(),
	}
	for _, opt := range opts {
		opt(k)
	}
	return k
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
//
// Map sharing: If spec.MapOwnerID() is non-zero, this program will share maps
// with the owner program instead of creating its own. The owner's maps directory
// (<root>/maps/<owner_id>/) must exist and contain the required pinned maps.
// This is used when loading multiple programs from the same image (e.g., via
// the bpfman-operator) where all programs should share the same map instances.
func (k *kernelAdapter) Load(ctx context.Context, spec bpfman.LoadSpec) (bpfman.ManagedProgram, error) {
	// Load the collection from the object file
	collSpec, err := ebpf.LoadCollectionSpec(spec.ObjectPath())
	if err != nil {
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to load collection spec: %w", err)
	}

	// Set global data if provided
	for name, data := range spec.GlobalData() {
		if err := collSpec.RewriteConstants(map[string]interface{}{name: data}); err != nil {
			// Ignore errors for constants that don't exist
		}
	}

	// Clear map pinning flags - we'll pin manually after getting the kernel ID.
	// Some BPF programs have maps annotated with PIN_BY_NAME which requires
	// a pin path at load time, but we need the kernel ID first.
	for _, mapSpec := range collSpec.Maps {
		mapSpec.Pinning = ebpf.PinNone
	}

	// Find the requested program and get its license (needed before loading)
	progSpec, ok := collSpec.Programs[spec.ProgramName()]
	if !ok {
		return bpfman.ManagedProgram{}, fmt.Errorf("program %q not found in collection spec", spec.ProgramName())
	}
	license := progSpec.License

	// Determine program type: prefer user-specified type, fall back to ELF inference.
	// The user's CLI specification (e.g., --programs kretprobe:func) takes precedence
	// because a kprobe program CAN be attached as either entry or return probe.
	programType := spec.ProgramType()
	if programType == bpfman.ProgramTypeUnspecified {
		// Fall back to inferring from ELF section name
		programType = inferProgramType(progSpec.SectionName)
	}

	// Check if we should share maps with another program (map_owner_id).
	// When set, we load the owner's pinned maps and pass them as replacements
	// so this program uses the same map instances.
	var mapReplacements map[string]*ebpf.Map
	var ownerMapsDir string
	mapOwnerID := spec.MapOwnerID()

	if mapOwnerID != 0 {
		ownerMapsDir = filepath.Join(spec.PinPath(), "maps", fmt.Sprintf("%d", mapOwnerID))
		mapReplacements = make(map[string]*ebpf.Map)

		k.logger.Debug("loading shared maps from owner program",
			"map_owner_id", mapOwnerID,
			"owner_maps_dir", ownerMapsDir)

		// Load pinned maps from owner's directory.
		// We iterate over collSpec.Maps to get the exact ELF map names.
		for name := range collSpec.Maps {
			// Skip internal maps (same filtering as pinning below)
			if strings.HasPrefix(name, ".") {
				continue
			}
			mapPath := filepath.Join(ownerMapsDir, name)
			m, err := ebpf.LoadPinnedMap(mapPath, nil)
			if err != nil {
				// Clean up any maps we've already loaded
				for _, loaded := range mapReplacements {
					loaded.Close()
				}
				return bpfman.ManagedProgram{}, fmt.Errorf("load shared map %q from owner %d: %w", name, mapOwnerID, err)
			}
			mapReplacements[name] = m
			k.logger.Debug("loaded shared map from owner", "name", name, "path", mapPath)
		}
	}

	// Load collection - use map replacements if sharing with owner
	var coll *ebpf.Collection
	if len(mapReplacements) > 0 {
		coll, err = ebpf.NewCollectionWithOptions(collSpec, ebpf.CollectionOptions{
			MapReplacements: mapReplacements,
		})
	} else {
		coll, err = ebpf.NewCollection(collSpec)
	}
	if err != nil {
		// Clean up map replacements on error
		for _, m := range mapReplacements {
			m.Close()
		}
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to load collection: %w", err)
	}
	defer coll.Close()

	prog, ok := coll.Programs[spec.ProgramName()]
	if !ok {
		return bpfman.ManagedProgram{}, fmt.Errorf("program %q not found in collection", spec.ProgramName())
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
			if err := os.Remove(pinnedPaths[i]); err != nil && !os.IsNotExist(err) {
				k.logger.Warn("failed to remove pin during cleanup", "path", pinnedPaths[i], "error", err)
			}
		}
	}

	// Pin program to <root>/prog_<kernel_id>
	progPinPath := filepath.Join(spec.PinPath(), fmt.Sprintf("prog_%d", kernelID))
	if err := prog.Pin(progPinPath); err != nil {
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to pin program: %w", err)
	}
	pinnedPaths = append(pinnedPaths, progPinPath)

	// Determine the maps directory to use:
	// - If sharing maps (map_owner_id set): use owner's mapsDir, don't create/pin maps
	// - Otherwise: create our own mapsDir and pin maps
	var mapsDir string
	if mapOwnerID != 0 {
		// Use owner's maps directory - maps are already pinned there
		mapsDir = ownerMapsDir
		k.logger.Debug("using shared maps from owner",
			"program_id", kernelID,
			"map_owner_id", mapOwnerID,
			"maps_dir", mapsDir)
	} else {
		// Create our own maps directory: <root>/maps/<kernel_id>/
		mapsDir = filepath.Join(spec.PinPath(), "maps", fmt.Sprintf("%d", kernelID))
		if err := os.MkdirAll(mapsDir, 0755); err != nil {
			cleanup()
			return bpfman.ManagedProgram{}, fmt.Errorf("failed to create maps directory: %w", err)
		}

		// Pin all maps (skip internal maps like .rodata, .bss, .data)
		for name, m := range coll.Maps {
			if strings.HasPrefix(name, ".") {
				continue
			}
			mapPinPath := filepath.Join(mapsDir, name)
			if err := m.Pin(mapPinPath); err != nil {
				cleanup()
				if rmErr := os.Remove(mapsDir); rmErr != nil && !os.IsNotExist(rmErr) {
					k.logger.Warn("failed to remove maps directory during cleanup", "path", mapsDir, "error", rmErr)
				}
				return bpfman.ManagedProgram{}, fmt.Errorf("failed to pin map %q: %w", name, err)
			}
			pinnedPaths = append(pinnedPaths, mapPinPath)
		}
	}

	ebpfMapIDs, ok := info.MapIDs()
	if !ok {
		cleanup()
		if mapOwnerID == 0 {
			if rmErr := os.Remove(mapsDir); rmErr != nil && !os.IsNotExist(rmErr) {
				k.logger.Warn("failed to remove maps directory during cleanup", "path", mapsDir, "error", rmErr)
			}
		}
		return bpfman.ManagedProgram{}, fmt.Errorf("failed to get map IDs from kernel")
	}
	_ = ebpfMapIDs // MapIDs now accessed via KernelProgramInfo

	return bpfman.ManagedProgram{
		Managed: &bpfman.ProgramInfo{
			Name:       spec.ProgramName(),
			Type:       programType,
			ObjectPath: spec.ObjectPath(),
			PinPath:    progPinPath,
			PinDir:     mapsDir,
		},
		Kernel: NewProgramInfo(info, license),
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
func (k *kernelAdapter) AttachXDPDispatcherWithPaths(ifindex int, progPinPath, linkPinPath string, numProgs int, proceedOn uint32, netnsPath string) (*interpreter.XDPDispatcherResult, error) {
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

	// Enter target network namespace if specified
	var nsGuard *netns.Guard
	if netnsPath != "" {
		k.logger.Debug("entering network namespace for XDP dispatcher attachment", "netns", netnsPath, "ifindex", ifindex)
		guard, err := netns.Enter(netnsPath)
		if err != nil {
			return nil, fmt.Errorf("enter network namespace %s: %w", netnsPath, err)
		}
		nsGuard = guard
		defer func() {
			if err := nsGuard.Close(); err != nil {
				k.logger.Warn("failed to restore network namespace", "error", err)
			}
		}()
	}

	// Attach to interface (now in target namespace if netnsPath was provided)
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
				if rmErr := os.Remove(progPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
					k.logger.Warn("failed to remove program pin during cleanup", "path", progPinPath, "error", rmErr)
				}
			}
			lnk.Close()
			return nil, fmt.Errorf("create link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			if progPinPath != "" {
				if rmErr := os.Remove(progPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
					k.logger.Warn("failed to remove program pin during cleanup", "path", progPinPath, "error", rmErr)
				}
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
//
// The mapPinDir parameter specifies the directory containing the program's
// pinned maps. These maps are loaded and passed as MapReplacements so the
// extension program shares the same maps as the original loaded program.
func (k *kernelAdapter) AttachXDPExtension(dispatcherPinPath, objectPath, programName string, position int, linkPinPath, mapPinDir string) (bpfman.ManagedLink, error) {
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
		return bpfman.ManagedLink{}, fmt.Errorf("load extension collection: %w", err)
	}
	defer coll.Close()
	// Note: maps in mapReplacements are now owned by the collection or
	// were used as replacements. We don't close them here as the collection
	// manages their lifecycle.

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

	// Enter target network namespace if specified
	var nsGuard *netns.Guard
	if netnsPath != "" {
		k.logger.Debug("entering network namespace for TC dispatcher attachment", "netns", netnsPath, "ifindex", ifindex, "direction", direction)
		guard, err := netns.Enter(netnsPath)
		if err != nil {
			return nil, fmt.Errorf("enter network namespace %s: %w", netnsPath, err)
		}
		nsGuard = guard
		defer func() {
			if err := nsGuard.Close(); err != nil {
				k.logger.Warn("failed to restore network namespace", "error", err)
			}
		}()
	}

	// Attach to interface using TCX link (now in target namespace if netnsPath was provided)
	lnk, err := link.AttachTCX(link.TCXOptions{
		Program:   dispatcherProg,
		Interface: ifindex,
		Attach:    attachType,
	})
	if err != nil {
		return nil, fmt.Errorf("attach TC dispatcher to ifindex %d direction %s: %w", ifindex, direction, err)
	}

	result := &interpreter.TCDispatcherResult{}

	// Get dispatcher program info
	progInfo, err := dispatcherProg.Info()
	if err != nil {
		lnk.Close()
		return nil, fmt.Errorf("get TC dispatcher program info: %w", err)
	}
	progID, ok := progInfo.ID()
	if !ok {
		lnk.Close()
		return nil, fmt.Errorf("failed to get TC dispatcher program ID from kernel")
	}
	result.DispatcherID = uint32(progID)

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return nil, fmt.Errorf("get TC dispatcher link info: %w", err)
	}
	result.LinkID = uint32(linkInfo.ID)

	// Pin dispatcher program to the revision-specific path
	if progPinPath != "" {
		progDir := filepath.Dir(progPinPath)
		if err := os.MkdirAll(progDir, 0755); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("create TC dispatcher program directory: %w", err)
		}

		if err := dispatcherProg.Pin(progPinPath); err != nil {
			lnk.Close()
			return nil, fmt.Errorf("pin TC dispatcher program to %s: %w", progPinPath, err)
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
			return nil, fmt.Errorf("create TC link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			if progPinPath != "" {
				if rmErr := os.Remove(progPinPath); rmErr != nil && !os.IsNotExist(rmErr) {
					k.logger.Warn("failed to remove program pin during cleanup", "path", progPinPath, "error", rmErr)
				}
			}
			lnk.Close()
			return nil, fmt.Errorf("pin TC dispatcher link to %s: %w", linkPinPath, err)
		}
		result.LinkPin = linkPinPath
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

	// Enter target network namespace if specified
	if netnsPath != "" {
		k.logger.Debug("entering network namespace for TCX attachment", "netns", netnsPath, "ifindex", ifindex, "direction", direction)
		guard, err := netns.Enter(netnsPath)
		if err != nil {
			return bpfman.ManagedLink{}, fmt.Errorf("enter network namespace %s: %w", netnsPath, err)
		}
		defer func() {
			if err := guard.Close(); err != nil {
				k.logger.Warn("failed to restore network namespace", "error", err)
			}
		}()
	}

	// Attach using TCX link with ordering anchor
	lnk, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   prog,
		Attach:    attachType,
		Anchor:    anchor,
	})
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach TCX to ifindex %d %s: %w", ifindex, direction, err)
	}

	// Pin the link if path provided
	if linkPinPath != "" {
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("create TCX link pin directory: %w", err)
		}

		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return bpfman.ManagedLink{}, fmt.Errorf("pin TCX link to %s: %w", linkPinPath, err)
		}
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return bpfman.ManagedLink{}, fmt.Errorf("get TCX link info: %w", err)
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            bpfman.LinkTypeTCX,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}

// AttachKprobe attaches a pinned program to a kernel function.
// If retprobe is true, attaches as a kretprobe instead of kprobe.
func (k *kernelAdapter) AttachKprobe(progPinPath, fnName string, offset uint64, retprobe bool, linkPinPath string) (bpfman.ManagedLink, error) {
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

	// Build kprobe options
	opts := &link.KprobeOptions{
		Offset: offset,
	}

	// Attach as kprobe or kretprobe
	var lnk link.Link
	if retprobe {
		lnk, err = link.Kretprobe(fnName, prog, opts)
	} else {
		lnk, err = link.Kprobe(fnName, prog, opts)
	}
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach kprobe to %s: %w", fnName, err)
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

	// Determine link type based on retprobe flag
	linkType := bpfman.LinkTypeKprobe
	if retprobe {
		linkType = bpfman.LinkTypeKretprobe
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            linkType,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.KprobeDetails{FnName: fnName, Offset: offset, Retprobe: retprobe},
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}

// AttachUprobe attaches a pinned program to a user-space function.
// target is the path to the binary or library (e.g., /usr/lib/libc.so.6).
// If retprobe is true, attaches as a uretprobe instead of uprobe.
// If containerPid > 0, uses the bpfman-ns helper subprocess to attach
// in the target container's mount namespace.
func (k *kernelAdapter) AttachUprobe(progPinPath, target, fnName string, offset uint64, retprobe bool, linkPinPath string, containerPid int32) (bpfman.ManagedLink, error) {
	k.logger.Debug("AttachUprobe called",
		"target", target,
		"fn_name", fnName,
		"offset", offset,
		"retprobe", retprobe,
		"container_pid", containerPid,
		"prog_pin_path", progPinPath,
		"link_pin_path", linkPinPath)

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

	var linkID uint32

	if containerPid > 0 {
		// Use bpfman-ns helper for container uprobes
		// This runs in a subprocess with GOMAXPROCS=1 to allow setns to work
		linkID, err = k.attachUprobeViaHelper(progPinPath, target, fnName, offset, retprobe, linkPinPath, containerPid)
		if err != nil {
			return bpfman.ManagedLink{}, fmt.Errorf("attach uprobe via helper: %w", err)
		}
	} else {
		// Regular uprobe - attach directly
		linkID, err = k.attachUprobeLocal(progPinPath, target, fnName, offset, retprobe, linkPinPath)
		if err != nil {
			return bpfman.ManagedLink{}, err
		}
	}

	// Determine link type based on retprobe flag
	linkType := bpfman.LinkTypeUprobe
	if retprobe {
		linkType = bpfman.LinkTypeUretprobe
	}

	// Load pinned link to get full info
	var kernelLink bpfman.KernelLinkInfo
	if linkPinPath != "" {
		pinnedLink, err := link.LoadPinnedLink(linkPinPath, nil)
		if err == nil {
			if info, err := pinnedLink.Info(); err == nil {
				kernelLink = NewLinkInfo(info)
			}
			pinnedLink.Close()
		}
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    linkID,
			KernelProgramID: uint32(progID),
			Type:            linkType,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         bpfman.UprobeDetails{Target: target, FnName: fnName, Offset: offset, Retprobe: retprobe, ContainerPid: containerPid},
		},
		Kernel: kernelLink,
	}, nil
}

// attachUprobeLocal attaches a uprobe directly (no namespace switching).
func (k *kernelAdapter) attachUprobeLocal(progPinPath, target, fnName string, offset uint64, retprobe bool, linkPinPath string) (uint32, error) {
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		return 0, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	ex, err := link.OpenExecutable(target)
	if err != nil {
		return 0, fmt.Errorf("open executable %s: %w", target, err)
	}

	opts := &link.UprobeOptions{Offset: offset}
	var lnk link.Link
	if retprobe {
		lnk, err = ex.Uretprobe(fnName, prog, opts)
	} else {
		lnk, err = ex.Uprobe(fnName, prog, opts)
	}
	if err != nil {
		return 0, fmt.Errorf("attach uprobe to %s in %s: %w", fnName, target, err)
	}

	// Get link info
	linkInfo, err := lnk.Info()
	if err != nil {
		lnk.Close()
		return 0, fmt.Errorf("get link info: %w", err)
	}
	linkID := uint32(linkInfo.ID)

	k.logger.Debug("uprobe link created", "link_id", linkID, "link_type", linkInfo.Type)

	// Pin the link if path provided
	if linkPinPath != "" {
		if err := os.MkdirAll(filepath.Dir(linkPinPath), 0755); err != nil {
			lnk.Close()
			return 0, fmt.Errorf("create link pin directory: %w", err)
		}
		if err := lnk.Pin(linkPinPath); err != nil {
			lnk.Close()
			return 0, fmt.Errorf("pin link to %s: %w", linkPinPath, err)
		}
		k.logger.Debug("link pinned successfully", "path", linkPinPath)
	}

	return linkID, nil
}

// attachUprobeViaHelper re-execs the current binary with CGO-based namespace
// switching to attach a uprobe in a container's mount namespace.
//
// Go's runtime is multi-threaded and setns(CLONE_NEWNS) requires a
// single-threaded process. We solve this using a CGO constructor (in the
// nsenter package) that runs before Go's runtime starts:
//
// 1. Parent creates socketpair for fd passing
// 2. Parent loads pinned program, passes fd via ExtraFiles (fd 3)
// 3. Parent passes socket via ExtraFiles (fd 4) for receiving link fd
// 4. Parent sets _BPFMAN_MNT_NS env var and re-execs itself as "bpfman-ns"
// 5. Child's C constructor calls setns() before Go runtime starts
// 6. Child's Go code runs in target mount namespace (target binary visible)
// 7. Child uses inherited program fd to attach uprobe
// 8. Child sends link fd back to parent via socket (SCM_RIGHTS)
// 9. Parent receives link fd, keeps it open to maintain the uprobe
func (k *kernelAdapter) attachUprobeViaHelper(progPinPath, target, fnName string, offset uint64, retprobe bool, linkPinPath string, containerPid int32) (uint32, error) {
	// Find the bpfman binary (which also serves as bpfman-ns)
	bpfmanPath, err := os.Executable()
	if err != nil {
		k.logger.Error("failed to get executable path", "error", err)
		return 0, fmt.Errorf("get executable path: %w", err)
	}

	// Load pinned program - we'll pass the fd to the child
	prog, err := ebpf.LoadPinnedProgram(progPinPath, nil)
	if err != nil {
		k.logger.Error("failed to load pinned program", "path", progPinPath, "error", err)
		return 0, fmt.Errorf("load pinned program %s: %w", progPinPath, err)
	}
	defer prog.Close()

	progInfo, _ := prog.Info()
	progID, _ := progInfo.ID()

	// Dup the program fd so we can pass it to child via ExtraFiles.
	// This avoids ownership issues between ebpf.Program and os.File.
	progFd := prog.FD()
	dupFd, err := syscall.Dup(progFd)
	if err != nil {
		k.logger.Error("failed to dup program fd", "fd", progFd, "error", err)
		return 0, fmt.Errorf("dup program fd: %w", err)
	}
	progFile := os.NewFile(uintptr(dupFd), "bpf-program")
	defer progFile.Close()

	// Create socketpair for receiving link fd from child.
	// Child will send the perf_event fd via SCM_RIGHTS.
	parentSocket, childSocket, err := nsenter.Socketpair()
	if err != nil {
		k.logger.Error("failed to create socketpair", "error", err)
		return 0, fmt.Errorf("create socketpair: %w", err)
	}
	defer parentSocket.Close()
	defer childSocket.Close()

	// Get current mount namespace inode for logging
	currentMntNs, _ := nsenter.GetCurrentMntNsInode()

	// Determine target namespace path - try /proc first, then /host/proc for k8s
	nsPath := fmt.Sprintf("/proc/%d/ns/mnt", containerPid)
	if _, err := os.Stat(nsPath); err != nil {
		altPath := fmt.Sprintf("/host/proc/%d/ns/mnt", containerPid)
		if _, err := os.Stat(altPath); err != nil {
			k.logger.Error("container namespace not accessible",
				"container_pid", containerPid,
				"tried_paths", []string{nsPath, altPath},
				"error", err,
				"hint", "ensure container PID is valid and /proc or /host/proc is accessible")
			return 0, fmt.Errorf("container namespace for PID %d not accessible (tried %s and %s): %w", containerPid, nsPath, altPath, err)
		}
		nsPath = altPath
	}

	k.logger.Info("preparing container uprobe attachment",
		"container_pid", containerPid,
		"current_mnt_ns_inode", currentMntNs,
		"target_ns_path", nsPath,
		"target_binary", target,
		"fn_name", fnName,
		"offset", offset,
		"retprobe", retprobe,
		"prog_pin_path", progPinPath,
		"prog_id", progID,
		"link_pin_path", linkPinPath)

	// Build arguments for bpfman-ns uprobe command.
	// Program fd passed via ExtraFiles[0] (fd 3 in child).
	// Socket fd passed via ExtraFiles[1] (fd 4 in child) for returning link fd.
	args := []string{
		"bpfman-ns", "uprobe",
		target,
		"--fn-name", fnName,
		"--offset", fmt.Sprintf("%d", offset),
	}
	if retprobe {
		args = append(args, "--retprobe")
	}

	// Determine log level for child process based on our logger's level
	childLogLevel := nsenter.LogLevelInfo
	if k.logger.Enabled(context.TODO(), slog.LevelDebug) {
		childLogLevel = nsenter.LogLevelDebug
	}

	// Use nsenter.CommandWithOptions with ExtraFiles to pass program fd and socket
	cmd := nsenter.CommandWithOptions(containerPid, bpfmanPath, nsenter.CommandOptions{
		Logger:     k.logger,
		LogLevel:   childLogLevel,
		ExtraFiles: []*os.File{progFile, childSocket}, // fd 3, fd 4 in child
	}, args...)

	k.logger.Debug("executing bpfman-ns helper subprocess",
		"executable", bpfmanPath,
		"args", args,
		"child_log_level", childLogLevel,
		"program_fd_passed", true,
		"socket_fd_passed", true)

	// Close child's socket end before running - child gets it via ExtraFiles
	// We need to close it in parent so recvmsg doesn't block forever
	// Actually, we close it AFTER cmd.Start() - let me restructure this

	// Start the child process
	cmd.Stderr = nil // Let it inherit stderr for logging
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		k.logger.Error("failed to get stdout pipe", "error", err)
		return 0, fmt.Errorf("get stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		k.logger.Error("failed to start bpfman-ns helper",
			"error", err,
			"container_pid", containerPid,
			"ns_path", nsPath)
		return 0, fmt.Errorf("start bpfman-ns for container %d: %w", containerPid, err)
	}

	// Close child's socket end in parent - child has its own copy via ExtraFiles
	childSocket.Close()

	// Receive link fd from child via socket
	k.logger.Debug("waiting for link fd from child")
	linkFd, name, err := nsenter.RecvFd(parentSocket)
	if err != nil {
		k.logger.Error("failed to receive link fd from child",
			"error", err,
			"container_pid", containerPid)
		cmd.Process.Kill()
		cmd.Wait()
		return 0, fmt.Errorf("receive link fd from child: %w", err)
	}
	k.logger.Debug("received link fd from child",
		"link_fd", linkFd,
		"name", name)

	// Read stdout for "ok" confirmation
	outputBuf := make([]byte, 64)
	n, _ := stdout.Read(outputBuf)
	outputStr := strings.TrimSpace(string(outputBuf[:n]))

	// Wait for child to exit
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			k.logger.Error("bpfman-ns helper failed",
				"exit_code", exitErr.ExitCode(),
				"container_pid", containerPid,
				"target", target,
				"fn_name", fnName,
				"ns_path", nsPath)
			syscall.Close(linkFd) // Clean up received fd
			return 0, fmt.Errorf("bpfman-ns failed attaching %s to %q in container %d (exit %d)", fnName, target, containerPid, exitErr.ExitCode())
		}
		k.logger.Error("failed to wait for bpfman-ns helper",
			"error", err,
			"container_pid", containerPid)
		syscall.Close(linkFd)
		return 0, fmt.Errorf("wait for bpfman-ns: %w", err)
	}

	if outputStr != "ok" {
		k.logger.Error("unexpected output from bpfman-ns",
			"output", outputStr,
			"expected", "ok")
		syscall.Close(linkFd)
		return 0, fmt.Errorf("bpfman-ns returned %q, expected 'ok'", outputStr)
	}

	// We now have the link fd. For perf_event-based uprobes, we cannot pin them.
	// We keep the fd open to maintain the uprobe attachment.
	// The link will be released when this fd is closed.
	k.logger.Info("container uprobe attachment succeeded",
		"link_fd", linkFd,
		"container_pid", containerPid,
		"target", target,
		"fn_name", fnName)

	// Perf_event-based links cannot be pinned to bpffs. We store the fd in a
	// map to keep the uprobe attached for the lifetime of this process.
	// The key uniquely identifies this attachment.
	linkKey := fmt.Sprintf("%d:%s:%s", containerPid, target, fnName)
	k.linkFds.Store(linkKey, linkFd)

	// Generate a synthetic link ID for database storage. Real kernel link IDs
	// are small sequential numbers; synthetic IDs are in range 0x80000000+ to
	// avoid collision. This allows the database to maintain a unique constraint
	// on link IDs while supporting perf_event-based attachments that lack
	// kernel link IDs.
	syntheticID := generateSyntheticLinkID()

	k.logger.Info("stored link fd for container uprobe",
		"key", linkKey,
		"link_fd", linkFd,
		"synthetic_link_id", syntheticID,
		"note", "perf_event links cannot be pinned; link will be released when daemon exits")

	return syntheticID, nil
}

// AttachFentry attaches a pinned fentry program to a kernel function.
// The target function was specified at load time and is stored in the program.
func (k *kernelAdapter) AttachFentry(progPinPath, fnName, linkPinPath string) (bpfman.ManagedLink, error) {
	return k.attachTracing(progPinPath, fnName, linkPinPath, bpfman.LinkTypeFentry)
}

// AttachFexit attaches a pinned fexit program to a kernel function.
// The target function was specified at load time and is stored in the program.
func (k *kernelAdapter) AttachFexit(progPinPath, fnName, linkPinPath string) (bpfman.ManagedLink, error) {
	return k.attachTracing(progPinPath, fnName, linkPinPath, bpfman.LinkTypeFexit)
}

// attachTracing is the shared implementation for fentry and fexit attachment.
func (k *kernelAdapter) attachTracing(progPinPath, fnName, linkPinPath string, linkType bpfman.LinkType) (bpfman.ManagedLink, error) {
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

	// Attach using link.AttachTracing - the program already has the target
	// function and attach type set from load time (via ELF section name).
	lnk, err := link.AttachTracing(link.TracingOptions{
		Program: prog,
	})
	if err != nil {
		return bpfman.ManagedLink{}, fmt.Errorf("attach tracing to %s: %w", fnName, err)
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

	// Build details based on link type
	var details bpfman.LinkDetails
	if linkType == bpfman.LinkTypeFentry {
		details = bpfman.FentryDetails{FnName: fnName}
	} else {
		details = bpfman.FexitDetails{FnName: fnName}
	}

	return bpfman.ManagedLink{
		Managed: &bpfman.LinkInfo{
			KernelLinkID:    uint32(linkInfo.ID),
			KernelProgramID: uint32(progID),
			Type:            linkType,
			PinPath:         linkPinPath,
			CreatedAt:       time.Now(),
			Details:         details,
		},
		Kernel: NewLinkInfo(linkInfo),
	}, nil
}
