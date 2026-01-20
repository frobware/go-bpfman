// Package ebpf provides kernel operations using cilium/ebpf.
package ebpf

import (
	"context"
	"fmt"
	"iter"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"

	"github.com/frobware/bpffs-csi-driver/bpfman/domain"
)

// Kernel implements interpreter.KernelOperations using cilium/ebpf.
type Kernel struct{}

// New creates a new kernel adapter.
func New() *Kernel {
	return &Kernel{}
}

// Programs returns an iterator over kernel BPF programs.
func (k *Kernel) Programs(ctx context.Context) iter.Seq2[domain.KernelProgram, error] {
	return func(yield func(domain.KernelProgram, error) bool) {
		var id ebpf.ProgramID
		for {
			nextID, err := ebpf.ProgramGetNextID(id)
			if err != nil {
				return // No more programs
			}
			id = nextID

			prog, err := ebpf.NewProgramFromID(id)
			if err != nil {
				if !yield(domain.KernelProgram{}, err) {
					return
				}
				continue
			}

			info, err := prog.Info()
			prog.Close()
			if err != nil {
				if !yield(domain.KernelProgram{}, err) {
					return
				}
				continue
			}

			kp := infoToKernelProgram(info, uint32(id))
			if !yield(kp, nil) {
				return
			}
		}
	}
}

// Maps returns an iterator over kernel BPF maps.
func (k *Kernel) Maps(ctx context.Context) iter.Seq2[domain.KernelMap, error] {
	return func(yield func(domain.KernelMap, error) bool) {
		var id ebpf.MapID
		for {
			nextID, err := ebpf.MapGetNextID(id)
			if err != nil {
				return
			}
			id = nextID

			m, err := ebpf.NewMapFromID(id)
			if err != nil {
				if !yield(domain.KernelMap{}, err) {
					return
				}
				continue
			}

			info, err := m.Info()
			m.Close()
			if err != nil {
				if !yield(domain.KernelMap{}, err) {
					return
				}
				continue
			}

			km := infoToKernelMap(info, uint32(id))
			if !yield(km, nil) {
				return
			}
		}
	}
}

// Links returns an iterator over kernel BPF links.
func (k *Kernel) Links(ctx context.Context) iter.Seq2[domain.KernelLink, error] {
	return func(yield func(domain.KernelLink, error) bool) {
		// Links iteration not directly supported, would need /sys/fs/bpf traversal
		// For now, return empty iterator
	}
}

// Load loads a BPF program into the kernel.
func (k *Kernel) Load(ctx context.Context, spec domain.LoadSpec) (domain.LoadedProgram, error) {
	// Load the collection from the object file
	collSpec, err := ebpf.LoadCollectionSpec(spec.ObjectPath)
	if err != nil {
		return domain.LoadedProgram{}, fmt.Errorf("failed to load collection spec: %w", err)
	}

	// Set global data if provided
	for name, data := range spec.GlobalData {
		if err := collSpec.RewriteConstants(map[string]interface{}{name: data}); err != nil {
			// Ignore errors for constants that don't exist
		}
	}

	// Create pin path directory
	if err := os.MkdirAll(spec.PinPath, 0755); err != nil {
		return domain.LoadedProgram{}, fmt.Errorf("failed to create pin path: %w", err)
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
		return domain.LoadedProgram{}, fmt.Errorf("failed to load collection: %w", err)
	}

	// Find the requested program
	prog, ok := coll.Programs[spec.ProgramName]
	if !ok {
		coll.Close()
		return domain.LoadedProgram{}, fmt.Errorf("program %q not found in collection", spec.ProgramName)
	}

	// Pin the program
	progPinPath := filepath.Join(spec.PinPath, spec.ProgramName)
	if err := prog.Pin(progPinPath); err != nil {
		coll.Close()
		return domain.LoadedProgram{}, fmt.Errorf("failed to pin program: %w", err)
	}

	info, err := prog.Info()
	if err != nil {
		coll.Close()
		return domain.LoadedProgram{}, fmt.Errorf("failed to get program info: %w", err)
	}

	progID, _ := info.ID()
	ebpfMapIDs, _ := info.MapIDs()
	mapIDs := make([]uint32, len(ebpfMapIDs))
	for i, mid := range ebpfMapIDs {
		mapIDs[i] = uint32(mid)
	}

	// Don't close the collection - programs are pinned
	return domain.LoadedProgram{
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

func infoToKernelProgram(info *ebpf.ProgramInfo, id uint32) domain.KernelProgram {
	name := info.Name
	tag := info.Tag

	ebpfMapIDs, _ := info.MapIDs()
	mapIDs := make([]uint32, len(ebpfMapIDs))
	for i, mid := range ebpfMapIDs {
		mapIDs[i] = uint32(mid)
	}

	return domain.KernelProgram{
		ID:          id,
		Name:        name,
		ProgramType: info.Type.String(),
		Tag:         tag,
		MapIDs:      mapIDs,
	}
}

func infoToKernelMap(info *ebpf.MapInfo, id uint32) domain.KernelMap {
	return domain.KernelMap{
		ID:         id,
		Name:       info.Name,
		MapType:    info.Type.String(),
		KeySize:    info.KeySize,
		ValueSize:  info.ValueSize,
		MaxEntries: info.MaxEntries,
		Flags:      uint32(info.Flags),
	}
}
