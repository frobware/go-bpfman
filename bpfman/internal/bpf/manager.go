// Package bpf provides BPF program management using cilium/ebpf.
// The interface mirrors the bpfman gRPC proto for 1:1 mapping.
package bpf

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	// DefaultBpfmanRoot is the default root directory for bpfman pins.
	DefaultBpfmanRoot = "/sys/fs/bpf/bpfman"
)

// LoadRequest contains parameters for loading BPF programs.
type LoadRequest struct {
	// Path to the BPF object file (mutually exclusive with ImageURL)
	ObjectPath string
	// OCI image URL (mutually exclusive with ObjectPath)
	ImageURL string
	// Programs to load from the object file
	Programs []ProgramLoadInfo
	// Metadata to attach to all loaded programs
	Metadata map[string]string
	// Global data to set in programs
	GlobalData map[string][]byte
	// UUID for this load operation (used for pin directory under root)
	UUID string
	// PinDir overrides UUID-based pin directory (for CLI use)
	PinDir string
	// MapOwnerID if sharing maps with another program
	MapOwnerID *uint32
}

// ProgramLoadInfo specifies which program to load and how.
type ProgramLoadInfo struct {
	// Name of the BPF function in the object file
	Name string
	// Type of the program (XDP, TC, Kprobe, etc.)
	Type BpfmanProgramType
	// For fentry/fexit: the kernel function to attach to
	AttachFunc string
}

// BpfmanProgramType mirrors the proto enum.
type BpfmanProgramType int32

const (
	ProgramTypeXDP BpfmanProgramType = iota
	ProgramTypeTC
	ProgramTypeTracepoint
	ProgramTypeKprobe
	ProgramTypeUprobe
	ProgramTypeFentry
	ProgramTypeFexit
	ProgramTypeTCX
)

// LoadResponse contains the results of loading programs.
type LoadResponse struct {
	Programs []LoadedProgramInfo
}

// LoadedProgramInfo contains info about a loaded program.
type LoadedProgramInfo struct {
	// Bpfman-tracked information
	Info ProgramInfo
	// Kernel-level information
	KernelInfo KernelProgramInfo
}

// ProgramInfo is bpfman's metadata about a program.
type ProgramInfo struct {
	Name       string
	Bytecode   string // file path or image URL
	Metadata   map[string]string
	GlobalData map[string][]byte
	MapPinPath string
	Links      []uint32
}

// KernelProgramInfo is the kernel's view of the program.
type KernelProgramInfo struct {
	ID            uint32
	Name          string
	ProgramType   uint32
	LoadedAt      string
	Tag           string
	GplCompatible bool
	MapIDs        []uint32
	BtfID         uint32
	BytesXlated   uint32
	Jited         bool
	BytesJited    uint32
	BytesMemlock  uint32
	VerifiedInsns uint32
}

// AttachRequest contains parameters for attaching a program.
type AttachRequest struct {
	ProgramID uint32
	Info      AttachInfo
}

// AttachInfo contains attach-type-specific parameters.
type AttachInfo struct {
	Type AttachType
	// XDP/TC/TCX
	Iface     string
	Priority  int32
	Direction string // ingress/egress for TC
	ProceedOn []int32
	Netns     string
	// Tracepoint
	Tracepoint string
	// Kprobe/Uprobe
	FnName       string
	Offset       uint64
	Target       string // for uprobe: path to binary
	Retprobe     bool
	PID          *int32
	ContainerPID *int32
	// Metadata for the link
	Metadata map[string]string
}

// AttachType specifies the type of attachment.
type AttachType int

const (
	AttachXDP AttachType = iota
	AttachTC
	AttachTCX
	AttachTracepoint
	AttachKprobe
	AttachUprobe
	AttachFentry
	AttachFexit
)

// programState tracks a loaded program.
type programState struct {
	id         uint32
	name       string
	funcName   string // original function name from request
	progType   BpfmanProgramType
	bytecode   string
	metadata   map[string]string
	globalData map[string][]byte
	mapPinPath string
	pinnedPath string
	loadedAt   time.Time
	links      []uint32
	mapIDs     []uint32
}

// linkState tracks an attachment.
type linkState struct {
	id        uint32
	programID uint32
	link      link.Link
	info      AttachInfo
}

// Manager handles BPF program lifecycle operations.
// It maintains state to track loaded programs and attachments.
type Manager struct {
	mu       sync.RWMutex
	root     string                    // bpffs root directory
	programs map[uint32]*programState  // kernel ID -> state
	links    map[uint32]*linkState     // link ID -> state
	nextLink uint32
}

// NewManager creates a new BPF manager.
func NewManager() *Manager {
	return &Manager{
		root:     DefaultBpfmanRoot,
		programs: make(map[uint32]*programState),
		links:    make(map[uint32]*linkState),
		nextLink: 1,
	}
}

// Load loads one or more BPF programs from an object file.
func (m *Manager) Load(req *LoadRequest) (*LoadResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if req.ObjectPath == "" && req.ImageURL == "" {
		return nil, fmt.Errorf("either ObjectPath or ImageURL is required")
	}
	if req.ImageURL != "" {
		return nil, fmt.Errorf("OCI image loading not yet implemented")
	}
	if len(req.Programs) == 0 {
		return nil, fmt.Errorf("at least one program is required")
	}

	// Determine pin directory
	var pinDir string
	if req.PinDir != "" {
		// Use explicit pin directory (CLI use)
		pinDir = req.PinDir
	} else if req.UUID != "" {
		// Use UUID under root (gRPC use)
		pinDir = filepath.Join(m.root, req.UUID)
	} else {
		// Use a timestamp-based directory as fallback
		pinDir = filepath.Join(m.root, fmt.Sprintf("%d", time.Now().UnixNano()))
	}

	// Load the collection spec
	spec, err := ebpf.LoadCollectionSpec(req.ObjectPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection spec: %w", err)
	}

	// Validate all requested programs exist
	for _, p := range req.Programs {
		if _, ok := spec.Programs[p.Name]; !ok {
			available := make([]string, 0, len(spec.Programs))
			for name := range spec.Programs {
				available = append(available, name)
			}
			return nil, fmt.Errorf("program %q not found (available: %v)", p.Name, available)
		}
	}

	// TODO: Apply global data to spec if provided

	// Load the full collection into kernel
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to load collection: %w", err)
	}

	// Ensure pin directory exists
	if err := os.MkdirAll(pinDir, 0755); err != nil {
		coll.Close()
		return nil, fmt.Errorf("failed to create pin directory: %w", err)
	}

	resp := &LoadResponse{
		Programs: make([]LoadedProgramInfo, 0, len(req.Programs)),
	}

	// Track what we've pinned for rollback
	pinnedPaths := []string{}
	cleanup := func() {
		for _, path := range pinnedPaths {
			os.Remove(path)
		}
		os.Remove(pinDir)
		coll.Close()
	}

	// Pin maps first (shared by all programs)
	mapIDs := []uint32{}
	for name, mp := range coll.Maps {
		mapPinPath := filepath.Join(pinDir, name)
		if err := mp.Pin(mapPinPath); err != nil {
			cleanup()
			return nil, fmt.Errorf("failed to pin map %q: %w", name, err)
		}
		pinnedPaths = append(pinnedPaths, mapPinPath)

		info, _ := mp.Info()
		if info != nil {
			id, _ := info.ID()
			mapIDs = append(mapIDs, uint32(id))
		}
	}

	// Process each requested program
	for _, progReq := range req.Programs {
		prog := coll.Programs[progReq.Name]
		if prog == nil {
			cleanup()
			return nil, fmt.Errorf("program %q not found after loading", progReq.Name)
		}

		// Pin the program
		progPinPath := filepath.Join(pinDir, progReq.Name)
		if err := prog.Pin(progPinPath); err != nil {
			cleanup()
			return nil, fmt.Errorf("failed to pin program %q: %w", progReq.Name, err)
		}
		pinnedPaths = append(pinnedPaths, progPinPath)

		// Get kernel info
		progInfo, err := prog.Info()
		if err != nil {
			cleanup()
			return nil, fmt.Errorf("failed to get program info for %q: %w", progReq.Name, err)
		}

		progID, _ := progInfo.ID()
		tag := progInfo.Tag

		// Store state
		state := &programState{
			id:         uint32(progID),
			name:       progInfo.Name,
			funcName:   progReq.Name,
			progType:   progReq.Type,
			bytecode:   req.ObjectPath,
			metadata:   req.Metadata,
			globalData: req.GlobalData,
			mapPinPath: pinDir,
			pinnedPath: progPinPath,
			loadedAt:   time.Now(),
			links:      []uint32{},
			mapIDs:     mapIDs,
		}
		m.programs[uint32(progID)] = state

		// Build response
		resp.Programs = append(resp.Programs, LoadedProgramInfo{
			Info: ProgramInfo{
				Name:       progReq.Name,
				Bytecode:   req.ObjectPath,
				Metadata:   req.Metadata,
				GlobalData: req.GlobalData,
				MapPinPath: pinDir,
				Links:      []uint32{},
			},
			KernelInfo: KernelProgramInfo{
				ID:            uint32(progID),
				Name:          progInfo.Name,
				ProgramType:   uint32(prog.Type()),
				LoadedAt:      state.loadedAt.Format(time.RFC3339),
				Tag:           tag,
				GplCompatible: true, // TODO: get from kernel
				MapIDs:        mapIDs,
				Jited:         true, // TODO: get from kernel
			},
		})
	}

	return resp, nil
}

// Unload removes a program by its kernel ID.
func (m *Manager) Unload(programID uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.programs[programID]
	if !ok {
		return fmt.Errorf("program %d not found", programID)
	}

	// Detach all links first
	for _, linkID := range state.links {
		if ls, ok := m.links[linkID]; ok {
			if ls.link != nil {
				ls.link.Close()
			}
			delete(m.links, linkID)
		}
	}

	// Remove program pin
	if state.pinnedPath != "" {
		os.Remove(state.pinnedPath)
	}

	// Check if any other programs share this pin directory
	sharedDir := false
	for id, ps := range m.programs {
		if id != programID && ps.mapPinPath == state.mapPinPath {
			sharedDir = true
			break
		}
	}

	// If no other programs share the directory, clean it up
	if !sharedDir && state.mapPinPath != "" {
		entries, _ := os.ReadDir(state.mapPinPath)
		for _, e := range entries {
			os.Remove(filepath.Join(state.mapPinPath, e.Name()))
		}
		os.Remove(state.mapPinPath)
	}

	delete(m.programs, programID)
	return nil
}

// Attach attaches a loaded program to a hook point.
func (m *Manager) Attach(req *AttachRequest) (uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	state, ok := m.programs[req.ProgramID]
	if !ok {
		return 0, fmt.Errorf("program %d not found", req.ProgramID)
	}

	// Load the pinned program
	prog, err := ebpf.LoadPinnedProgram(state.pinnedPath, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to load pinned program: %w", err)
	}
	defer prog.Close()

	var l link.Link

	switch req.Info.Type {
	case AttachXDP:
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   prog,
			Interface: m.ifaceIndex(req.Info.Iface),
		})
	case AttachTracepoint:
		// Parse tracepoint "group:name" format
		group, name := parseTracepoint(req.Info.Tracepoint)
		l, err = link.Tracepoint(group, name, prog, nil)
	case AttachKprobe:
		if req.Info.Retprobe {
			l, err = link.Kretprobe(req.Info.FnName, prog, nil)
		} else {
			l, err = link.Kprobe(req.Info.FnName, prog, nil)
		}
	case AttachFentry:
		l, err = link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
	case AttachFexit:
		l, err = link.AttachTracing(link.TracingOptions{
			Program: prog,
		})
	default:
		return 0, fmt.Errorf("attach type %d not yet implemented", req.Info.Type)
	}

	if err != nil {
		return 0, fmt.Errorf("failed to attach: %w", err)
	}

	linkID := m.nextLink
	m.nextLink++

	m.links[linkID] = &linkState{
		id:        linkID,
		programID: req.ProgramID,
		link:      l,
		info:      req.Info,
	}

	state.links = append(state.links, linkID)

	return linkID, nil
}

// ifaceIndex gets the interface index by name.
func (m *Manager) ifaceIndex(name string) int {
	// TODO: implement proper interface lookup
	return 0
}

// parseTracepoint splits a "group:name" tracepoint into components.
func parseTracepoint(tp string) (group, name string) {
	for i := 0; i < len(tp); i++ {
		if tp[i] == ':' {
			return tp[:i], tp[i+1:]
		}
	}
	// If no colon, treat the whole string as the name
	return "", tp
}

// Detach removes an attachment by link ID.
func (m *Manager) Detach(linkID uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ls, ok := m.links[linkID]
	if !ok {
		return fmt.Errorf("link %d not found", linkID)
	}

	if ls.link != nil {
		ls.link.Close()
	}

	// Remove from program's link list
	if state, ok := m.programs[ls.programID]; ok {
		for i, lid := range state.links {
			if lid == linkID {
				state.links = append(state.links[:i], state.links[i+1:]...)
				break
			}
		}
	}

	delete(m.links, linkID)
	return nil
}

// ListRequest contains filters for listing programs.
type ListRequest struct {
	ProgramType       *uint32
	BpfmanProgramsOnly bool
	MatchMetadata     map[string]string
}

// ListResult contains a single program in the list response.
type ListResult struct {
	Info       *ProgramInfo
	KernelInfo *KernelProgramInfo
}

// List returns all programs matching the filter criteria.
func (m *Manager) List(req *ListRequest) ([]ListResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var results []ListResult

	for id, state := range m.programs {
		// Filter by program type if specified
		if req.ProgramType != nil {
			// Map bpfman type to kernel type for comparison
			// This is simplified - real impl needs proper mapping
		}

		// Filter by metadata
		if len(req.MatchMetadata) > 0 {
			match := true
			for k, v := range req.MatchMetadata {
				if state.metadata[k] != v {
					match = false
					break
				}
			}
			if !match {
				continue
			}
		}

		results = append(results, ListResult{
			Info: &ProgramInfo{
				Name:       state.funcName,
				Bytecode:   state.bytecode,
				Metadata:   state.metadata,
				GlobalData: state.globalData,
				MapPinPath: state.mapPinPath,
				Links:      state.links,
			},
			KernelInfo: &KernelProgramInfo{
				ID:          id,
				Name:        state.name,
				ProgramType: uint32(state.progType),
				LoadedAt:    state.loadedAt.Format(time.RFC3339),
				MapIDs:      state.mapIDs,
			},
		})
	}

	return results, nil
}

// Get returns information about a single program by ID.
func (m *Manager) Get(programID uint32) (*ListResult, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	state, ok := m.programs[programID]
	if !ok {
		return nil, fmt.Errorf("program %d not found", programID)
	}

	return &ListResult{
		Info: &ProgramInfo{
			Name:       state.funcName,
			Bytecode:   state.bytecode,
			Metadata:   state.metadata,
			GlobalData: state.globalData,
			MapPinPath: state.mapPinPath,
			Links:      state.links,
		},
		KernelInfo: &KernelProgramInfo{
			ID:          programID,
			Name:        state.name,
			ProgramType: uint32(state.progType),
			LoadedAt:    state.loadedAt.Format(time.RFC3339),
			MapIDs:      state.mapIDs,
		},
	}, nil
}

// GetLink returns information about a link by ID.
func (m *Manager) GetLink(linkID uint32) (*linkState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	ls, ok := m.links[linkID]
	if !ok {
		return nil, fmt.Errorf("link %d not found", linkID)
	}

	return ls, nil
}

// ============================================================================
// Filesystem helpers for CLI use (don't require in-memory state tracking)
// ============================================================================

// PinnedProgram represents a program loaded directly from bpffs.
type PinnedProgram struct {
	ID         uint32 `json:"id"`
	Name       string `json:"name"`
	Type       uint32 `json:"type"`
	PinnedPath string `json:"pinned_path"`
}

// PinnedMap represents a map loaded directly from bpffs.
type PinnedMap struct {
	ID         uint32 `json:"id"`
	Name       string `json:"name"`
	Type       uint32 `json:"type"`
	KeySize    uint32 `json:"key_size"`
	ValueSize  uint32 `json:"value_size"`
	MaxEntries uint32 `json:"max_entries"`
	PinnedPath string `json:"pinned_path"`
}

// PinDirContents holds programs and maps found in a pin directory.
type PinDirContents struct {
	Programs []PinnedProgram `json:"programs,omitempty"`
	Maps     []PinnedMap     `json:"maps,omitempty"`
}

// LoadResult contains the result of loading a single program (for CLI).
type LoadResult struct {
	Program PinnedProgram `json:"program"`
	Maps    []PinnedMap   `json:"maps"`
	PinDir  string        `json:"pin_dir"`
}

// LoadSingle loads a single program by name from an object file (CLI helper).
func (m *Manager) LoadSingle(objectPath, programName, pinDir string) (*LoadResult, error) {
	req := &LoadRequest{
		ObjectPath: objectPath,
		Programs: []ProgramLoadInfo{
			{Name: programName, Type: ProgramTypeXDP}, // Type doesn't matter for loading
		},
		PinDir: pinDir, // Use explicit pin directory for CLI
	}

	resp, err := m.Load(req)
	if err != nil {
		return nil, err
	}

	if len(resp.Programs) == 0 {
		return nil, fmt.Errorf("no programs loaded")
	}

	prog := resp.Programs[0]
	result := &LoadResult{
		Program: PinnedProgram{
			ID:         prog.KernelInfo.ID,
			Name:       prog.KernelInfo.Name,
			Type:       prog.KernelInfo.ProgramType,
			PinnedPath: filepath.Join(pinDir, programName),
		},
		PinDir: pinDir,
	}

	// Get map info
	for _, mapID := range prog.KernelInfo.MapIDs {
		result.Maps = append(result.Maps, PinnedMap{
			ID: mapID,
		})
	}

	return result, nil
}

// Unpin removes all pins from a directory (CLI helper).
func (m *Manager) Unpin(pinDir string) (int, error) {
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		return 0, fmt.Errorf("failed to read pin directory: %w", err)
	}

	count := 0
	for _, entry := range entries {
		path := filepath.Join(pinDir, entry.Name())
		if err := os.Remove(path); err != nil {
			return count, fmt.Errorf("failed to unpin %s: %w", path, err)
		}
		count++
	}

	// Remove the directory itself
	if err := os.Remove(pinDir); err != nil && !os.IsNotExist(err) {
		return count, fmt.Errorf("failed to remove pin directory: %w", err)
	}

	return count, nil
}

// ListPinDir scans a bpffs directory and returns its contents (CLI helper).
func (m *Manager) ListPinDir(pinDir string, includeMaps bool) (*PinDirContents, error) {
	entries, err := os.ReadDir(pinDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read pin directory: %w", err)
	}

	result := &PinDirContents{}

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
				result.Programs = append(result.Programs, PinnedProgram{
					ID:         uint32(id),
					Name:       info.Name,
					Type:       uint32(prog.Type()),
					PinnedPath: path,
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
					result.Maps = append(result.Maps, PinnedMap{
						ID:         uint32(id),
						Name:       info.Name,
						Type:       uint32(info.Type),
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

// GetPinned loads and returns info about a pinned program (CLI helper).
func (m *Manager) GetPinned(pinPath string) (*PinnedProgram, error) {
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
	return &PinnedProgram{
		ID:         uint32(id),
		Name:       info.Name,
		Type:       uint32(prog.Type()),
		PinnedPath: pinPath,
	}, nil
}
