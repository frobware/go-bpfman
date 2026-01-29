// Package inspect provides a correlated view of bpfman's state across
// store, kernel, and filesystem. It is the "state of the bpfman world"
// abstraction used by CLI commands and diagnostics.
package inspect

import (
	"context"
	"iter"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/bpffs"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/kernel"
)

// StoreLister is the subset of interpreter.Store needed by Snapshot.
type StoreLister interface {
	List(ctx context.Context) (map[uint32]bpfman.Program, error)
	ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error)
	ListDispatchers(ctx context.Context) ([]dispatcher.State, error)
}

// KernelLister is the subset of interpreter.KernelSource needed by Snapshot.
type KernelLister interface {
	Programs(ctx context.Context) iter.Seq2[kernel.Program, error]
	Links(ctx context.Context) iter.Seq2[kernel.Link, error]
}

// Presence indicates where an object exists across the three sources.
type Presence struct {
	InStore  bool
	InKernel bool
	InFS     bool
}

// Managed returns true if the object is tracked in the store.
func (p Presence) Managed() bool { return p.InStore }

// OrphanFS returns true if the object exists only on the filesystem.
func (p Presence) OrphanFS() bool { return p.InFS && !p.InStore && !p.InKernel }

// KernelOnly returns true if the object exists only in the kernel.
func (p Presence) KernelOnly() bool { return p.InKernel && !p.InStore }

// ProgramRow is a store-first view of a program with presence annotations.
type ProgramRow struct {
	KernelID uint32

	// Store fields (valid when Presence.InStore is true)
	StoreProgram *bpfman.Program

	// Kernel fields (valid when Presence.InKernel is true)
	KernelProgram *kernel.Program

	// FS fields
	FSPinPath string // from bpffs scan (may differ from store)

	Presence Presence
}

// Name returns the program name (from store if available, else kernel).
func (r ProgramRow) Name() string {
	if r.StoreProgram != nil {
		return r.StoreProgram.ProgramName
	}
	if r.KernelProgram != nil {
		return r.KernelProgram.Name
	}
	return ""
}

// Type returns the program type (from store if available, else kernel).
func (r ProgramRow) Type() string {
	if r.StoreProgram != nil {
		return r.StoreProgram.ProgramType.String()
	}
	if r.KernelProgram != nil {
		return r.KernelProgram.ProgramType
	}
	return ""
}

// PinPath returns the pin path (from store if available, else FS).
func (r ProgramRow) PinPath() string {
	if r.StoreProgram != nil && r.StoreProgram.PinPath != "" {
		return r.StoreProgram.PinPath
	}
	return r.FSPinPath
}

// LinkRow is a store-first view of a link with presence annotations.
type LinkRow struct {
	KernelLinkID    uint32
	KernelProgramID uint32

	// Store fields (valid when Presence.InStore is true)
	LinkType   string
	PinPath    string
	HasPinPath bool
	Synthetic  bool

	Presence Presence
}

// DispatcherRow is a store-first view of a dispatcher with presence annotations.
type DispatcherRow struct {
	// Key fields
	DispType string
	Nsid     uint64
	Ifindex  uint32

	// Store fields (valid when Presence.InStore is true)
	Revision uint32
	KernelID uint32
	LinkID   uint32
	Priority uint32

	// Presence tracks where the dispatcher's components exist
	ProgPresence Presence // dispatcher program
	LinkPresence Presence // XDP link (for XDP dispatchers)

	// FS-derived
	FSLinkCount int // count of link_* files in revision dir (-1 if unknown)
}

// SnapshotMeta contains metadata about the snapshot.
type SnapshotMeta struct {
	// Errors encountered during snapshot (non-fatal)
	Errors []error
}

// World is a point-in-time snapshot of bpfman's state across all sources.
type World struct {
	Programs    []ProgramRow
	Links       []LinkRow
	Dispatchers []DispatcherRow
	Meta        SnapshotMeta
}

// ManagedPrograms returns only store-managed programs.
func (w *World) ManagedPrograms() []ProgramRow {
	var out []ProgramRow
	for _, r := range w.Programs {
		if r.Presence.InStore {
			out = append(out, r)
		}
	}
	return out
}

// ManagedLinks returns only store-managed links.
func (w *World) ManagedLinks() []LinkRow {
	var out []LinkRow
	for _, r := range w.Links {
		if r.Presence.InStore {
			out = append(out, r)
		}
	}
	return out
}

// ManagedDispatchers returns only store-managed dispatchers.
func (w *World) ManagedDispatchers() []DispatcherRow {
	var out []DispatcherRow
	for _, r := range w.Dispatchers {
		if r.ProgPresence.InStore {
			out = append(out, r)
		}
	}
	return out
}

// Snapshot builds a World by reading from store, kernel, and filesystem.
// The returned World contains all objects from all sources, correlated
// by kernel ID. Use ManagedPrograms() etc. for the default store-first view.
func Snapshot(
	ctx context.Context,
	store StoreLister,
	kern KernelLister,
	scanner *bpffs.Scanner,
) (*World, error) {
	w := &World{}

	// Phase 1: Build indexes from kernel and filesystem
	kernelProgs := make(map[uint32]kernel.Program)
	kernelLinks := make(map[uint32]bool)

	for kp, err := range kern.Programs(ctx) {
		if err != nil {
			w.Meta.Errors = append(w.Meta.Errors, err)
			continue
		}
		kernelProgs[kp.ID] = kp
	}

	for kl, err := range kern.Links(ctx) {
		if err != nil {
			w.Meta.Errors = append(w.Meta.Errors, err)
			continue
		}
		kernelLinks[kl.ID] = true
	}

	// FS indexes
	fsProgPins := make(map[uint32]string)               // kernelID -> path
	fsLinkDirs := make(map[uint32]string)               // programID -> path
	fsMapDirs := make(map[uint32]string)                // programID -> path
	fsDispDirs := make(map[string]*bpffs.DispatcherDir) // "type/nsid/ifindex" -> dir
	fsDispLinks := make(map[string]string)              // "type/nsid/ifindex" -> path

	for pin, err := range scanner.ProgPins(ctx) {
		if err != nil {
			w.Meta.Errors = append(w.Meta.Errors, err)
			continue
		}
		fsProgPins[pin.KernelID] = pin.Path
	}

	for dir, err := range scanner.LinkDirs(ctx) {
		if err != nil {
			w.Meta.Errors = append(w.Meta.Errors, err)
			continue
		}
		fsLinkDirs[dir.ProgramID] = dir.Path
	}

	for dir, err := range scanner.MapDirs(ctx) {
		if err != nil {
			w.Meta.Errors = append(w.Meta.Errors, err)
			continue
		}
		fsMapDirs[dir.ProgramID] = dir.Path
	}

	for dir, err := range scanner.DispatcherDirs(ctx) {
		if err != nil {
			w.Meta.Errors = append(w.Meta.Errors, err)
			continue
		}
		key := dispatcherKey(dir.DispType, dir.Nsid, dir.Ifindex)
		d := dir // copy
		fsDispDirs[key] = &d
	}

	for pin, err := range scanner.DispatcherLinkPins(ctx) {
		if err != nil {
			w.Meta.Errors = append(w.Meta.Errors, err)
			continue
		}
		key := dispatcherKey(pin.DispType, pin.Nsid, pin.Ifindex)
		fsDispLinks[key] = pin.Path
	}

	// Phase 2: Build program rows (store-first)
	storeProgs, err := store.List(ctx)
	if err != nil {
		return nil, err
	}

	seenProgIDs := make(map[uint32]bool)
	for kernelID, prog := range storeProgs {
		seenProgIDs[kernelID] = true
		fsPath, inFS := fsProgPins[kernelID]
		kp, inKernel := kernelProgs[kernelID]

		row := ProgramRow{
			KernelID:     kernelID,
			StoreProgram: &prog,
			FSPinPath:    fsPath,
			Presence: Presence{
				InStore:  true,
				InKernel: inKernel,
				InFS:     inFS,
			},
		}
		if inKernel {
			row.KernelProgram = &kp
		}
		w.Programs = append(w.Programs, row)
	}

	// Add kernel-only programs (not in store)
	for kernelID, kp := range kernelProgs {
		if seenProgIDs[kernelID] {
			continue
		}
		fsPath, inFS := fsProgPins[kernelID]
		kpCopy := kp
		row := ProgramRow{
			KernelID:      kernelID,
			KernelProgram: &kpCopy,
			FSPinPath:     fsPath,
			Presence: Presence{
				InStore:  false,
				InKernel: true,
				InFS:     inFS,
			},
		}
		w.Programs = append(w.Programs, row)
		seenProgIDs[kernelID] = true
	}

	// Add FS-only programs (not in store, not in kernel)
	for kernelID, fsPath := range fsProgPins {
		if seenProgIDs[kernelID] {
			continue
		}
		row := ProgramRow{
			KernelID:  kernelID,
			FSPinPath: fsPath,
			Presence: Presence{
				InStore:  false,
				InKernel: false,
				InFS:     true,
			},
		}
		w.Programs = append(w.Programs, row)
	}

	// Phase 3: Build link rows (store-first)
	storeLinks, err := store.ListLinks(ctx)
	if err != nil {
		return nil, err
	}

	seenLinkIDs := make(map[uint32]bool)
	for _, link := range storeLinks {
		seenLinkIDs[link.KernelLinkID] = true
		synthetic := bpfman.IsSyntheticLinkID(link.KernelLinkID)
		inKernel := false
		if !synthetic {
			inKernel = kernelLinks[link.KernelLinkID]
		}
		row := LinkRow{
			KernelLinkID:    link.KernelLinkID,
			KernelProgramID: link.KernelProgramID,
			LinkType:        string(link.LinkType),
			PinPath:         link.PinPath,
			HasPinPath:      link.PinPath != "",
			Synthetic:       synthetic,
			Presence: Presence{
				InStore:  true,
				InKernel: inKernel,
				InFS:     link.PinPath != "" && scanner.PathExists(link.PinPath),
			},
		}
		w.Links = append(w.Links, row)
	}

	// Add kernel-only links (not in store)
	for kernelLinkID := range kernelLinks {
		if seenLinkIDs[kernelLinkID] {
			continue
		}
		row := LinkRow{
			KernelLinkID: kernelLinkID,
			Presence: Presence{
				InStore:  false,
				InKernel: true,
				InFS:     false,
			},
		}
		w.Links = append(w.Links, row)
	}

	// Phase 4: Build dispatcher rows (store-first)
	storeDisps, err := store.ListDispatchers(ctx)
	if err != nil {
		return nil, err
	}

	seenDispKeys := make(map[string]bool)
	for _, disp := range storeDisps {
		key := dispatcherKey(string(disp.Type), disp.Nsid, disp.Ifindex)
		seenDispKeys[key] = true

		fsDir := fsDispDirs[key]
		_, linkPinExists := fsDispLinks[key]

		fsLinkCount := -1
		progInFS := false
		if fsDir != nil {
			fsLinkCount = fsDir.LinkCount
			progInFS = true
		}

		_, progInKernel := kernelProgs[disp.KernelID]
		row := DispatcherRow{
			DispType:    string(disp.Type),
			Nsid:        disp.Nsid,
			Ifindex:     disp.Ifindex,
			Revision:    disp.Revision,
			KernelID:    disp.KernelID,
			LinkID:      disp.LinkID,
			Priority:    uint32(disp.Priority),
			FSLinkCount: fsLinkCount,
			ProgPresence: Presence{
				InStore:  true,
				InKernel: progInKernel,
				InFS:     progInFS,
			},
			LinkPresence: Presence{
				InStore:  disp.LinkID != 0,
				InKernel: disp.LinkID != 0 && kernelLinks[disp.LinkID],
				InFS:     linkPinExists,
			},
		}
		w.Dispatchers = append(w.Dispatchers, row)
	}

	// Add FS-only dispatchers (orphan dirs)
	for key, fsDir := range fsDispDirs {
		if seenDispKeys[key] {
			continue
		}
		_, linkPinExists := fsDispLinks[key]
		row := DispatcherRow{
			DispType:    fsDir.DispType,
			Nsid:        fsDir.Nsid,
			Ifindex:     fsDir.Ifindex,
			Revision:    fsDir.Revision,
			FSLinkCount: fsDir.LinkCount,
			ProgPresence: Presence{
				InStore:  false,
				InKernel: false,
				InFS:     true,
			},
			LinkPresence: Presence{
				InStore:  false,
				InKernel: false,
				InFS:     linkPinExists,
			},
		}
		w.Dispatchers = append(w.Dispatchers, row)
	}

	return w, nil
}

func dispatcherKey(dispType string, nsid uint64, ifindex uint32) string {
	return dispType + "/" + uitoa64(nsid) + "/" + uitoa32(ifindex)
}

func uitoa32(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func uitoa64(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
