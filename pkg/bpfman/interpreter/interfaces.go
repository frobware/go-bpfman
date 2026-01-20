// Package interpreter contains interfaces and executors for effects.
// This is the only package that performs actual I/O.
package interpreter

import (
	"context"
	"iter"

	"github.com/frobware/go-bpfman/pkg/bpfman"
	"github.com/frobware/go-bpfman/pkg/bpfman/kernel"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

// LinkWriter writes link metadata to the store.
type LinkWriter interface {
	SaveLink(ctx context.Context, link managed.Link) error
	DeleteLink(ctx context.Context, uuid string) error
}

// LinkReader reads link metadata from the store.
type LinkReader interface {
	GetLink(ctx context.Context, uuid string) (managed.Link, error)
	GetLinkByKernelID(ctx context.Context, kernelLinkID uint32) (managed.Link, error)
}

// LinkLister lists links from the store.
type LinkLister interface {
	ListLinks(ctx context.Context) ([]managed.Link, error)
	ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.Link, error)
}

// LinkStore combines all link store operations.
type LinkStore interface {
	LinkWriter
	LinkReader
	LinkLister
}

// Store combines program and link store operations.
type Store interface {
	ProgramStore
	LinkStore
}

// ProgramReader reads program metadata from the store.
// Get returns store.ErrNotFound if the program does not exist.
type ProgramReader interface {
	Get(ctx context.Context, kernelID uint32) (managed.Program, error)
}

// ProgramWriter writes program metadata to the store.
type ProgramWriter interface {
	Save(ctx context.Context, kernelID uint32, metadata managed.Program) error
	Delete(ctx context.Context, kernelID uint32) error
	// MarkUnloading transitions a program to unloading state.
	// This is phase 1 of unload 2PC.
	MarkUnloading(ctx context.Context, kernelID uint32) error
}

// ReservationWriter handles the reservation phase of transactional loads.
type ReservationWriter interface {
	// Reserve creates a loading reservation (state=loading) keyed by UUID.
	// Returns an error if a reservation with this UUID already exists.
	Reserve(ctx context.Context, uuid string, metadata managed.Program) error
	// CommitReservation transitions a reservation from loading to loaded,
	// updating the primary key from UUID to kernel ID.
	CommitReservation(ctx context.Context, uuid string, kernelID uint32) error
	// MarkError transitions a reservation to error state with a message.
	MarkError(ctx context.Context, uuid string, errMsg string) error
	// DeleteReservation removes a reservation by UUID (for cleanup).
	DeleteReservation(ctx context.Context, uuid string) error
}

// ProgramLister lists all program metadata from the store.
type ProgramLister interface {
	List(ctx context.Context) (map[uint32]managed.Program, error)
}

// StateEntry represents a program entry with its kernel ID (if loaded).
type StateEntry struct {
	KernelID uint32 // 0 for reservations not yet committed
	Metadata managed.Program
}

// StateReader queries programs by lifecycle state.
type StateReader interface {
	// ListByState returns all entries with the given state.
	// Unlike List, this includes loading and error entries.
	ListByState(ctx context.Context, state managed.State) ([]StateEntry, error)
}

// ProgramStore combines all store operations.
type ProgramStore interface {
	ProgramReader
	ProgramWriter
	ProgramLister
	ReservationWriter
	StateReader
}

// KernelSource provides access to kernel BPF objects.
type KernelSource interface {
	Programs(ctx context.Context) iter.Seq2[kernel.Program, error]
	Maps(ctx context.Context) iter.Seq2[kernel.Map, error]
	Links(ctx context.Context) iter.Seq2[kernel.Link, error]
}

// ProgramLoader loads BPF programs into the kernel.
type ProgramLoader interface {
	Load(ctx context.Context, spec managed.LoadSpec) (managed.Loaded, error)
}

// ProgramUnloader removes BPF programs from the kernel.
type ProgramUnloader interface {
	Unload(ctx context.Context, pinPath string) error
}

// PinInspector provides raw inspection of bpffs pins.
type PinInspector interface {
	// ListPinDir scans a bpffs directory and returns its contents.
	ListPinDir(pinDir string, includeMaps bool) (*kernel.PinDirContents, error)
	// GetPinned loads and returns info about a pinned program.
	GetPinned(pinPath string) (*kernel.PinnedProgram, error)
}

// ProgramAttacher attaches programs to hooks.
type ProgramAttacher interface {
	// AttachTracepoint attaches a pinned program to a tracepoint.
	AttachTracepoint(progPinPath, group, name, linkPinPath string) (*bpfman.AttachedLink, error)
}

// KernelOperations combines all kernel operations.
type KernelOperations interface {
	KernelSource
	ProgramLoader
	ProgramUnloader
	PinInspector
	ProgramAttacher
}
