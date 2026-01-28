package manager

import (
	"context"
	"errors"
	"fmt"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/kernel"
)

// ManagedProgram combines kernel and metadata info.
type ManagedProgram struct {
	KernelProgram kernel.Program  `json:"kernel"`
	Metadata      *bpfman.Program `json:"metadata,omitempty"`
}

// ProgramInfo is the complete view of a managed program.
type ProgramInfo struct {
	Kernel *KernelInfo `json:"kernel,omitempty"`
	Bpfman *BpfmanInfo `json:"bpfman,omitempty"`
}

// KernelInfo contains live kernel state.
type KernelInfo struct {
	Program *kernel.Program `json:"program,omitempty"`
	Links   []kernel.Link   `json:"links,omitempty"`
	Maps    []kernel.Map    `json:"maps,omitempty"`
}

// BpfmanInfo contains managed metadata.
type BpfmanInfo struct {
	Program *bpfman.Program   `json:"program,omitempty"`
	Links   []LinkWithDetails `json:"links,omitempty"`
}

// LinkWithDetails combines a link summary with its type-specific details.
type LinkWithDetails struct {
	Summary bpfman.LinkSummary `json:"summary"`
	Details bpfman.LinkDetails `json:"details"`
}

// LoadedProgram pairs a program's database metadata with its kernel info.
type LoadedProgram struct {
	KernelID   uint32
	Program    bpfman.Program
	KernelInfo kernel.Program
}

// ErrMultipleProgramsFound is returned when multiple programs match the
// search criteria and none is the map owner.
var ErrMultipleProgramsFound = errors.New("multiple programs found")

// ErrMultipleMapOwners is returned when multiple programs claim to be
// the map owner (MapOwnerID == 0). This indicates a data inconsistency.
var ErrMultipleMapOwners = errors.New("multiple map owners found")

// List returns all managed programs with their kernel info.
func (m *Manager) List(ctx context.Context) ([]ManagedProgram, error) {
	// FETCH - get store and kernel data
	stored, err := m.store.List(ctx)
	if err != nil {
		return nil, err
	}

	var kernelPrograms []kernel.Program
	for kp, err := range m.kernel.Programs(ctx) {
		if err != nil {
			continue // Skip programs we can't read
		}
		kernelPrograms = append(kernelPrograms, kp)
	}

	// COMPUTE - join data (pure)
	return joinManagedPrograms(stored, kernelPrograms), nil
}

// joinManagedPrograms is a pure function that joins kernel and store data.
func joinManagedPrograms(
	stored map[uint32]bpfman.Program,
	kps []kernel.Program,
) []ManagedProgram {
	result := make([]ManagedProgram, 0, len(kps))

	for _, kp := range kps {
		mp := ManagedProgram{
			KernelProgram: kp,
		}
		if metadata, ok := stored[kp.ID]; ok {
			mp.Metadata = &metadata
		}
		result = append(result, mp)
	}

	return result
}

// FilterManaged returns only managed programs.
func FilterManaged(programs []ManagedProgram) []ManagedProgram {
	var result []ManagedProgram
	for _, p := range programs {
		if p.Metadata != nil {
			result = append(result, p)
		}
	}
	return result
}

// FilterUnmanaged returns only unmanaged programs.
func FilterUnmanaged(programs []ManagedProgram) []ManagedProgram {
	var result []ManagedProgram
	for _, p := range programs {
		if p.Metadata == nil {
			result = append(result, p)
		}
	}
	return result
}

// Get retrieves a managed program by its kernel ID.
// Returns both the stored metadata and the live kernel state, including
// associated links and maps from both the kernel and the store.
// Returns an error if the program exists in the store but not in the kernel,
// as this indicates an inconsistent state that requires reconciliation.
func (m *Manager) Get(ctx context.Context, kernelID uint32) (ProgramInfo, error) {
	// Fetch program from store
	metadata, err := m.store.Get(ctx, kernelID)
	if err != nil {
		return ProgramInfo{}, err
	}

	// Fetch program from kernel
	kp, err := m.kernel.GetProgramByID(ctx, kernelID)
	if err != nil {
		return ProgramInfo{}, fmt.Errorf("program %d exists in store but not in kernel (requires reconciliation): %w", kernelID, err)
	}

	// Fetch links from store (summaries only)
	storedLinks, err := m.store.ListLinksByProgram(ctx, kernelID)
	if err != nil {
		return ProgramInfo{}, fmt.Errorf("list links: %w", err)
	}

	// Fetch each link's details and kernel info
	var kernelLinks []kernel.Link
	var linksWithDetails []LinkWithDetails
	for _, sl := range storedLinks {
		// Fetch details for this link
		_, details, err := m.store.GetLink(ctx, sl.KernelLinkID)
		if err != nil {
			m.logger.WarnContext(ctx, "failed to get link details", "kernel_link_id", sl.KernelLinkID, "error", err)
			// Include summary only with nil details
			linksWithDetails = append(linksWithDetails, LinkWithDetails{
				Summary: sl,
				Details: nil,
			})
		} else {
			linksWithDetails = append(linksWithDetails, LinkWithDetails{
				Summary: sl,
				Details: details,
			})
		}

		// Fetch from kernel if we have a kernel link ID
		if sl.KernelLinkID == 0 {
			continue // Link not pinned or no kernel ID
		}
		kl, err := m.kernel.GetLinkByID(ctx, sl.KernelLinkID)
		if err != nil {
			// Link exists in store but not kernel - skip
			continue
		}
		kernelLinks = append(kernelLinks, kl)
	}

	// Fetch each map from kernel using the program's map IDs
	var kernelMaps []kernel.Map
	for _, mapID := range kp.MapIDs {
		km, err := m.kernel.GetMapByID(ctx, mapID)
		if err != nil {
			// Map exists in program but not accessible - skip
			continue
		}
		kernelMaps = append(kernelMaps, km)
	}

	return ProgramInfo{
		Kernel: &KernelInfo{
			Program: &kp,
			Links:   kernelLinks,
			Maps:    kernelMaps,
		},
		Bpfman: &BpfmanInfo{
			Program: &metadata,
			Links:   linksWithDetails,
		},
	}, nil
}

// ListLinks returns all managed links (summaries only).
func (m *Manager) ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error) {
	return m.store.ListLinks(ctx)
}

// ListLinksByProgram returns all links for a given program.
func (m *Manager) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkSummary, error) {
	return m.store.ListLinksByProgram(ctx, programKernelID)
}

// GetLink retrieves a link by kernel link ID, returning both summary and type-specific details.
func (m *Manager) GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error) {
	return m.store.GetLink(ctx, kernelLinkID)
}

// ListLoadedPrograms returns all programs that exist in both the database
// and the kernel. This reconciles DB state with kernel state, filtering out
// stale entries where a program exists in DB but not in the kernel (e.g.,
// after a daemon restart or failed unload).
func (m *Manager) ListLoadedPrograms(ctx context.Context) ([]LoadedProgram, error) {
	// Get all programs from DB
	dbPrograms, err := m.store.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list programs from store: %w", err)
	}

	// Filter to only those that exist in kernel
	var loaded []LoadedProgram
	for kernelID, prog := range dbPrograms {
		kp, err := m.kernel.GetProgramByID(ctx, kernelID)
		if err != nil {
			// Program not in kernel - skip (stale DB entry)
			m.logger.DebugContext(ctx, "skipping stale program",
				"kernel_id", kernelID,
				"name", prog.ProgramName,
				"reason", "not in kernel",
			)
			continue
		}
		loaded = append(loaded, LoadedProgram{
			KernelID:   kernelID,
			Program:    prog,
			KernelInfo: kp,
		})
	}

	return loaded, nil
}

// FindLoadedProgramByMetadata finds a program by metadata key/value from
// the reconciled list of loaded programs (those in both DB and kernel).
//
// When multiple programs match (e.g., multi-program applications), this
// returns the map owner (the program with MapOwnerID == 0). All maps are
// pinned at the owner's MapPinPath, so the CSI can find them there.
//
// Returns an error if no programs match, or if multiple map owners exist
// (data inconsistency).
func (m *Manager) FindLoadedProgramByMetadata(ctx context.Context, key, value string) (bpfman.Program, uint32, error) {
	programs, err := m.ListLoadedPrograms(ctx)
	if err != nil {
		return bpfman.Program{}, 0, fmt.Errorf("list loaded programs: %w", err)
	}

	var matches []LoadedProgram
	for _, lp := range programs {
		if lp.Program.UserMetadata[key] == value {
			matches = append(matches, lp)
		}
	}

	switch len(matches) {
	case 0:
		return bpfman.Program{}, 0, fmt.Errorf("program with %s=%s: %w", key, value, store.ErrNotFound)
	case 1:
		return matches[0].Program, matches[0].KernelID, nil
	default:
		// Multiple programs match - find the map owner (MapOwnerID == 0).
		// In multi-program loads, one program owns all maps and the others
		// reference it via MapOwnerID.
		var owners []LoadedProgram
		for _, lp := range matches {
			if lp.Program.MapOwnerID == 0 {
				owners = append(owners, lp)
			}
		}

		switch len(owners) {
		case 0:
			// No map owner found - all programs reference another owner
			// that doesn't match our metadata query. This shouldn't happen.
			ids := make([]uint32, len(matches))
			for i, m := range matches {
				ids[i] = m.KernelID
			}
			return bpfman.Program{}, 0, fmt.Errorf("%w: %d programs with %s=%s but no map owner (kernel IDs: %v)",
				ErrMultipleProgramsFound, len(matches), key, value, ids)
		case 1:
			m.logger.DebugContext(ctx, "found map owner among multiple matching programs",
				"key", key,
				"value", value,
				"total_matches", len(matches),
				"owner_kernel_id", owners[0].KernelID,
				"owner_name", owners[0].Program.ProgramName,
			)
			return owners[0].Program, owners[0].KernelID, nil
		default:
			// Multiple map owners - data inconsistency
			ids := make([]uint32, len(owners))
			for i, o := range owners {
				ids[i] = o.KernelID
			}
			return bpfman.Program{}, 0, fmt.Errorf("%w: %d map owners with %s=%s (kernel IDs: %v)",
				ErrMultipleMapOwners, len(owners), key, value, ids)
		}
	}
}
