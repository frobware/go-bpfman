package manager

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/unix"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/bpffs"
	"github.com/frobware/go-bpfman/inspect"
	"github.com/frobware/go-bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/kernel"
)

// ManagedProgram combines kernel and metadata info.
type ManagedProgram struct {
	KernelProgram kernel.Program      `json:"kernel"`
	Metadata      *bpfman.ProgramSpec `json:"metadata,omitempty"`
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
	Program *bpfman.ProgramSpec `json:"program,omitempty"`
	Links   []bpfman.LinkRecord `json:"links,omitempty"`
}

// HostInfo contains system information about the observed host.
type HostInfo struct {
	Sysname  string `json:"sysname"`
	Nodename string `json:"nodename"`
	Release  string `json:"release"`
	Version  string `json:"version"`
	Machine  string `json:"machine"`
}

// GetHostInfo returns system information from uname.
func GetHostInfo() HostInfo {
	var utsname unix.Utsname
	if err := unix.Uname(&utsname); err != nil {
		return HostInfo{}
	}
	return HostInfo{
		Sysname:  unix.ByteSliceToString(utsname.Sysname[:]),
		Nodename: unix.ByteSliceToString(utsname.Nodename[:]),
		Release:  unix.ByteSliceToString(utsname.Release[:]),
		Version:  unix.ByteSliceToString(utsname.Version[:]),
		Machine:  unix.ByteSliceToString(utsname.Machine[:]),
	}
}

// ProgramListResult contains programs with observation metadata.
type ProgramListResult struct {
	ObservedAt time.Time        `json:"observed_at"`
	Host       HostInfo         `json:"host"`
	Programs   []bpfman.Program `json:"programs"`
}

// ErrMultipleProgramsFound is returned when multiple programs match the
// search criteria and none is the map owner.
var ErrMultipleProgramsFound = errors.New("multiple programs found")

// ErrMultipleMapOwners is returned when multiple programs claim to be
// the map owner (MapOwnerID == 0). This indicates a data inconsistency.
var ErrMultipleMapOwners = errors.New("multiple map owners found")

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

	// Fetch links from store (records with details)
	storedLinks, err := m.store.ListLinksByProgram(ctx, kernelID)
	if err != nil {
		return ProgramInfo{}, fmt.Errorf("list links: %w", err)
	}

	// Fetch complete records with details, and kernel info
	var kernelLinks []kernel.Link
	var linksWithDetails []bpfman.LinkRecord
	for _, sl := range storedLinks {
		// Fetch full record with details for this link
		record, err := m.store.GetLink(ctx, sl.ID)
		if err != nil {
			m.logger.WarnContext(ctx, "failed to get link details", "link_id", sl.ID, "error", err)
			// Include the summary record without details
			linksWithDetails = append(linksWithDetails, sl)
		} else {
			linksWithDetails = append(linksWithDetails, record)
		}

		// Fetch from kernel if we have a kernel link ID.
		// For non-synthetic links, ID is the kernel link ID.
		if sl.IsSynthetic() {
			continue // Synthetic links don't have kernel link IDs
		}
		kl, err := m.kernel.GetLinkByID(ctx, uint32(sl.ID))
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

// ListLinks returns all managed links (records only).
func (m *Manager) ListLinks(ctx context.Context) ([]bpfman.LinkRecord, error) {
	return m.store.ListLinks(ctx)
}

// ListLinksByProgram returns all links for a given program.
func (m *Manager) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkRecord, error) {
	return m.store.ListLinksByProgram(ctx, programKernelID)
}

// GetLink retrieves a link by link ID, returning the full record with details.
func (m *Manager) GetLink(ctx context.Context, linkID bpfman.LinkID) (bpfman.LinkRecord, error) {
	return m.store.GetLink(ctx, linkID)
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
func (m *Manager) FindLoadedProgramByMetadata(ctx context.Context, key, value string) (bpfman.ProgramRecord, uint32, error) {
	scanner := bpffs.NewScanner(m.dirs.ScannerDirs())
	world, err := inspect.Snapshot(ctx, m.store, m.kernel, scanner)
	if err != nil {
		return bpfman.ProgramRecord{}, 0, fmt.Errorf("snapshot: %w", err)
	}

	// Find managed programs that are also in kernel and match the metadata
	var matches []inspect.ProgramView
	for _, row := range world.Programs {
		if !row.Presence.InStore || !row.Presence.InKernel {
			continue
		}
		if row.Managed.Meta.Metadata[key] == value {
			matches = append(matches, row)
		}
	}

	switch len(matches) {
	case 0:
		return bpfman.ProgramRecord{}, 0, fmt.Errorf("program with %s=%s: %w", key, value, store.ErrNotFound)
	case 1:
		return *matches[0].Managed, matches[0].KernelID, nil
	default:
		// Multiple programs match - find the map owner (MapOwnerID == nil).
		// In multi-program loads, one program owns all maps and the others
		// reference it via MapOwnerID.
		var owners []inspect.ProgramView
		for _, row := range matches {
			if row.Managed.Handles.MapOwnerID == nil {
				owners = append(owners, row)
			}
		}

		switch len(owners) {
		case 0:
			// No map owner found - all programs reference another owner
			// that doesn't match our metadata query. This shouldn't happen.
			ids := make([]uint32, len(matches))
			for i, row := range matches {
				ids[i] = row.KernelID
			}
			return bpfman.ProgramRecord{}, 0, fmt.Errorf("%w: %d programs with %s=%s but no map owner (kernel IDs: %v)",
				ErrMultipleProgramsFound, len(matches), key, value, ids)
		case 1:
			m.logger.DebugContext(ctx, "found map owner among multiple matching programs",
				"key", key,
				"value", value,
				"total_matches", len(matches),
				"owner_kernel_id", owners[0].KernelID,
				"owner_name", owners[0].Managed.Meta.Name,
			)
			return *owners[0].Managed, owners[0].KernelID, nil
		default:
			// Multiple map owners - data inconsistency
			ids := make([]uint32, len(owners))
			for i, row := range owners {
				ids[i] = row.KernelID
			}
			return bpfman.ProgramRecord{}, 0, fmt.Errorf("%w: %d map owners with %s=%s (kernel IDs: %v)",
				ErrMultipleMapOwners, len(owners), key, value, ids)
		}
	}
}

// ListPrograms returns all managed programs with full spec and status.
// This returns the canonical bpfman.Program type with both Spec (from store)
// and Status (from kernel enumeration + filesystem checks).
func (m *Manager) ListPrograms(ctx context.Context) (ProgramListResult, error) {
	scanner := bpffs.NewScanner(m.dirs.ScannerDirs())
	world, err := inspect.Snapshot(ctx, m.store, m.kernel, scanner)
	if err != nil {
		return ProgramListResult{}, fmt.Errorf("snapshot: %w", err)
	}

	var programs []bpfman.Program
	for _, row := range world.ManagedPrograms() {
		if prog, ok := row.AsProgram(); ok {
			programs = append(programs, prog)
		}
	}
	return ProgramListResult{
		ObservedAt: world.Meta.ObservedAt,
		Host:       GetHostInfo(),
		Programs:   programs,
	}, nil
}
