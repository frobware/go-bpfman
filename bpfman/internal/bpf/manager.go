package bpf

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
)

// Manager handles BPF program lifecycle operations.
type Manager struct{}

// NewManager creates a new BPF manager.
func NewManager() *Manager {
	return &Manager{}
}

// Load loads a BPF program from an object file and pins it to the given directory.
func (m *Manager) Load(objectPath, programName, pinDir string) (*LoadResult, error) {
	// Load the collection spec (doesn't load into kernel yet)
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec: %w", err)
	}

	// Find the program in the spec
	if _, ok := spec.Programs[programName]; !ok {
		available := make([]string, 0, len(spec.Programs))
		for name := range spec.Programs {
			available = append(available, name)
		}
		return nil, fmt.Errorf("program %q not found in %s (available: %v)", programName, objectPath, available)
	}

	// Load the full collection into kernel
	// cilium/ebpf handles map references automatically
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection: %w", err)
	}

	// Get the loaded program
	prog := coll.Programs[programName]
	if prog == nil {
		coll.Close()
		return nil, fmt.Errorf("program %q not found after loading", programName)
	}

	// Ensure pin directory exists
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to create pin directory: %w", err)
	}

	// Pin the program
	progPinPath := filepath.Join(pinDir, programName)
	if err := prog.Pin(progPinPath); err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to pin program: %w", err)
	}

	// Get program info
	progInfo, err := prog.Info()
	if err != nil {
		// Clean up on failure
		os.Remove(progPinPath)
		coll.Close()
		return nil, fmt.Errorf("failed to get program info: %w", err)
	}

	progID, _ := progInfo.ID()

	result := &LoadResult{
		Program: Program{
			ID:         uint32(progID),
			Name:       progInfo.Name,
			Type:       ProgramType(prog.Type()),
			PinnedPath: progPinPath,
		},
		Maps:   make([]Map, 0),
		PinDir: pinDir,
	}

	// Pin maps and collect info
	for name, m := range coll.Maps {
		mapPinPath := filepath.Join(pinDir, name)
		if err := m.Pin(mapPinPath); err != nil {
			// Rollback: unpin program and any maps we've pinned
			os.Remove(progPinPath)
			for _, pinnedMap := range result.Maps {
				os.Remove(pinnedMap.PinnedPath)
			}
			coll.Close()
			return nil, fmt.Errorf("failed to pin map %q: %w", name, err)
		}

		mapInfo, err := m.Info()
		if err != nil {
			// Rollback
			os.Remove(progPinPath)
			os.Remove(mapPinPath)
			for _, pinnedMap := range result.Maps {
				os.Remove(pinnedMap.PinnedPath)
			}
			coll.Close()
			return nil, fmt.Errorf("failed to get map info for %q: %w", name, err)
		}

		mapID, _ := mapInfo.ID()

		result.Maps = append(result.Maps, Map{
			ID:         uint32(mapID),
			Name:       mapInfo.Name,
			Type:       MapType(m.Type()),
			KeySize:    mapInfo.KeySize,
			ValueSize:  mapInfo.ValueSize,
			MaxEntries: mapInfo.MaxEntries,
			PinnedPath: mapPinPath,
		})
	}

	// Don't close the collection - the pins keep the objects alive
	// The kernel holds references via the pins

	return result, nil
}

// Unpin removes all pins from the given directory.
func (m *Manager) Unpin(pinDir string) (int, error) {
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read pin directory: %w", err)
	}

	unpinned := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		path := filepath.Join(pinDir, entry.Name())
		if err := os.Remove(path); err != nil {
			// Continue trying to remove others
			continue
		}
		unpinned++
	}

	// Try to remove the directory itself
	os.Remove(pinDir)

	return unpinned, nil
}

// ListResult contains the results of listing a pin directory.
type ListResult struct {
	Programs []Program `json:"programs,omitempty"`
	Maps     []Map     `json:"maps,omitempty"`
}

// List returns information about all pinned objects in a directory.
func (m *Manager) List(pinDir string, includeMaps bool) (*ListResult, error) {
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		if os.IsNotExist(err) {
			return &ListResult{}, nil
		}
		return nil, fmt.Errorf("failed to read pin directory: %w", err)
	}

	result := &ListResult{}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		path := filepath.Join(pinDir, entry.Name())

		// Try as program first
		prog, err := ebpf.LoadPinnedProgram(path, nil)
		if err == nil {
			info, err := prog.Info()
			if err == nil {
				id, _ := info.ID()
				result.Programs = append(result.Programs, Program{
					ID:         uint32(id),
					Name:       info.Name,
					Type:       ProgramType(prog.Type()),
					PinnedPath: path,
				})
			}
			prog.Close()
			continue
		}

		// Try as map if requested
		if includeMaps {
			m, err := ebpf.LoadPinnedMap(path, nil)
			if err == nil {
				info, err := m.Info()
				if err == nil {
					id, _ := info.ID()
					result.Maps = append(result.Maps, Map{
						ID:         uint32(id),
						Name:       info.Name,
						Type:       MapType(m.Type()),
						KeySize:    info.KeySize,
						ValueSize:  info.ValueSize,
						MaxEntries: info.MaxEntries,
						PinnedPath: path,
					})
				}
				m.Close()
			}
		}
	}

	return result, nil
}

// Get returns information about a specific pinned program.
func (m *Manager) Get(pinPath string) (*Program, error) {
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
	return &Program{
		ID:         uint32(id),
		Name:       info.Name,
		Type:       ProgramType(prog.Type()),
		PinnedPath: pinPath,
	}, nil
}
