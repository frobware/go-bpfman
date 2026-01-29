// Package inspect provides a correlated view of bpfman's state across
// store, kernel, and filesystem. It is the "state of the bpfman world"
// abstraction used by CLI commands and diagnostics.
package inspect

import (
	"context"
	"errors"
	"iter"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/bpffs"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/kernel"
)

// ErrNotFound is returned when a program is not found in any source.
var ErrNotFound = errors.New("not found")

// StoreLister is the subset of interpreter.Store needed by Snapshot.
type StoreLister interface {
	List(ctx context.Context) (map[uint32]bpfman.Program, error)
	ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error)
	ListDispatchers(ctx context.Context) ([]dispatcher.State, error)
}

// StoreGetter is the subset of interpreter.Store needed by GetProgram.
type StoreGetter interface {
	Get(ctx context.Context, kernelID uint32) (bpfman.Program, error)
}

// KernelLister is the subset of interpreter.KernelSource needed by Snapshot.
type KernelLister interface {
	Programs(ctx context.Context) iter.Seq2[kernel.Program, error]
	Links(ctx context.Context) iter.Seq2[kernel.Link, error]
}

// KernelGetter is the subset of interpreter.KernelSource needed by GetProgram.
type KernelGetter interface {
	GetProgramByID(ctx context.Context, id uint32) (kernel.Program, error)
}

// LinkGetter is the subset of interpreter.Store needed by GetLink.
type LinkGetter interface {
	GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error)
}

// KernelLinkGetter is the subset of interpreter.KernelSource needed by GetLink.
type KernelLinkGetter interface {
	GetLinkByID(ctx context.Context, id uint32) (kernel.Link, error)
}

// LinkInfo is the result of GetLink, containing summary, details, and presence.
type LinkInfo struct {
	Summary  bpfman.LinkSummary
	Details  bpfman.LinkDetails // may be nil if not in store
	Presence Presence
}

// DispatcherGetter is the subset of interpreter.Store needed by GetDispatcher.
type DispatcherGetter interface {
	GetDispatcher(ctx context.Context, dispType string, nsid uint64, ifindex uint32) (dispatcher.State, error)
}

// DispatcherInfo is the result of GetDispatcher, containing state and presence.
type DispatcherInfo struct {
	State        dispatcher.State
	ProgPresence Presence // dispatcher program presence
	LinkPresence Presence // XDP link presence (for XDP dispatchers)
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

// GetProgram retrieves a single program by kernel ID, correlating state
// from store, kernel, and filesystem. This is more efficient than Snapshot
// for single-program lookups as it performs targeted queries rather than
// enumerating everything.
//
// Returns ErrNotFound if the program does not exist in any source.
func GetProgram(
	ctx context.Context,
	storeGetter StoreGetter,
	kern KernelGetter,
	scanner *bpffs.Scanner,
	kernelID uint32,
) (ProgramRow, error) {
	row := ProgramRow{KernelID: kernelID}

	// Try store
	prog, err := storeGetter.Get(ctx, kernelID)
	if err == nil {
		row.StoreProgram = &prog
		row.Presence.InStore = true
	} else if !errors.Is(err, store.ErrNotFound) {
		// Real error (not just "not found")
		return ProgramRow{}, err
	}

	// Try kernel
	kp, err := kern.GetProgramByID(ctx, kernelID)
	if err == nil {
		row.KernelProgram = &kp
		row.Presence.InKernel = true
	}
	// Kernel errors (program not found) are not fatal - just means not in kernel

	// Try filesystem
	// If we have store metadata with a pin path, check that specific path
	if row.StoreProgram != nil && row.StoreProgram.PinPath != "" {
		if scanner.PathExists(row.StoreProgram.PinPath) {
			row.FSPinPath = row.StoreProgram.PinPath
			row.Presence.InFS = true
		}
	}

	// If not found in any source, return error
	if !row.Presence.InStore && !row.Presence.InKernel && !row.Presence.InFS {
		return ProgramRow{}, ErrNotFound
	}

	return row, nil
}

// GetLink retrieves a single link by kernel link ID, correlating state
// from store, kernel, and filesystem. This is more efficient than Snapshot
// for single-link lookups as it performs targeted queries rather than
// enumerating everything.
//
// Returns ErrNotFound if the link does not exist in any source.
func GetLink(
	ctx context.Context,
	linkGetter LinkGetter,
	kern KernelLinkGetter,
	scanner *bpffs.Scanner,
	kernelLinkID uint32,
) (LinkInfo, error) {
	info := LinkInfo{}

	// Try store - this returns both summary and details
	summary, details, err := linkGetter.GetLink(ctx, kernelLinkID)
	if err == nil {
		info.Summary = summary
		info.Details = details
		info.Presence.InStore = true
	} else if !errors.Is(err, store.ErrNotFound) {
		// Real error (not just "not found")
		return LinkInfo{}, err
	}

	// Try kernel (skip for synthetic link IDs which don't exist in kernel)
	if !bpfman.IsSyntheticLinkID(kernelLinkID) {
		_, err := kern.GetLinkByID(ctx, kernelLinkID)
		if err == nil {
			info.Presence.InKernel = true
		}
		// Kernel errors (link not found) are not fatal - just means not in kernel
	}

	// Try filesystem - check if pin path exists
	if info.Presence.InStore && info.Summary.PinPath != "" {
		if scanner.PathExists(info.Summary.PinPath) {
			info.Presence.InFS = true
		}
	}

	// If not found in any source, return error
	if !info.Presence.InStore && !info.Presence.InKernel && !info.Presence.InFS {
		return LinkInfo{}, ErrNotFound
	}

	return info, nil
}

// GetDispatcher retrieves a single dispatcher by its key (type, nsid, ifindex),
// correlating state from store, kernel, and filesystem. This is more efficient
// than Snapshot for single-dispatcher lookups.
//
// Returns ErrNotFound if the dispatcher does not exist in any source.
func GetDispatcher(
	ctx context.Context,
	dispGetter DispatcherGetter,
	kern KernelGetter,
	kernLinkGetter KernelLinkGetter,
	scanner *bpffs.Scanner,
	dispType string,
	nsid uint64,
	ifindex uint32,
) (DispatcherInfo, error) {
	info := DispatcherInfo{}

	// Try store
	state, err := dispGetter.GetDispatcher(ctx, dispType, nsid, ifindex)
	if err == nil {
		info.State = state
		info.ProgPresence.InStore = true
		if state.LinkID != 0 {
			info.LinkPresence.InStore = true
		}
	} else if !errors.Is(err, store.ErrNotFound) {
		// Real error (not just "not found")
		return DispatcherInfo{}, err
	}

	// Try kernel for dispatcher program
	if info.ProgPresence.InStore && info.State.KernelID != 0 {
		_, err := kern.GetProgramByID(ctx, info.State.KernelID)
		if err == nil {
			info.ProgPresence.InKernel = true
		}
	}

	// Try kernel for dispatcher link (XDP only)
	if info.LinkPresence.InStore && info.State.LinkID != 0 {
		_, err := kernLinkGetter.GetLinkByID(ctx, info.State.LinkID)
		if err == nil {
			info.LinkPresence.InKernel = true
		}
	}

	// Try filesystem for dispatcher directory
	// Dispatcher dirs follow pattern: {dispType}/dispatcher_{nsid}_{ifindex}_{revision}
	if info.ProgPresence.InStore {
		// Check if the dispatcher directory exists
		key := dispatcherKey(dispType, nsid, ifindex)
		for dir, err := range scanner.DispatcherDirs(ctx) {
			if err != nil {
				continue
			}
			dirKey := dispatcherKey(dir.DispType, dir.Nsid, dir.Ifindex)
			if dirKey == key {
				info.ProgPresence.InFS = true
				break
			}
		}
	}

	// Try filesystem for dispatcher link pin (XDP only)
	if info.LinkPresence.InStore {
		for pin, err := range scanner.DispatcherLinkPins(ctx) {
			if err != nil {
				continue
			}
			if pin.DispType == dispType && pin.Nsid == nsid && pin.Ifindex == ifindex {
				info.LinkPresence.InFS = true
				break
			}
		}
	}

	// If not found in store, return error (dispatchers are always store-first)
	if !info.ProgPresence.InStore {
		return DispatcherInfo{}, ErrNotFound
	}

	return info, nil
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
