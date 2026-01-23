// Package interpreter contains interfaces and executors for effects.
// This is the only package that performs actual I/O.
package interpreter

import (
	"context"
	"io"
	"iter"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/kernel"
)

// LinkWriter writes link metadata to the store.
// Each link type has its own save method to enforce type safety.
type LinkWriter interface {
	SaveTracepointLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.TracepointDetails) error
	SaveKprobeLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.KprobeDetails) error
	SaveUprobeLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.UprobeDetails) error
	SaveFentryLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.FentryDetails) error
	SaveFexitLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.FexitDetails) error
	SaveXDPLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.XDPDetails) error
	SaveTCLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.TCDetails) error
	SaveTCXLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.TCXDetails) error
	DeleteLink(ctx context.Context, kernelLinkID uint32) error
}

// LinkReader reads link metadata from the store.
// GetLink performs a two-phase lookup: registry then type-specific details.
type LinkReader interface {
	GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error)
}

// LinkLister lists links from the store.
// Returns only LinkSummary for efficiency; use GetLink for full details.
type LinkLister interface {
	ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error)
	ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkSummary, error)
}

// LinkStore combines all link store operations.
type LinkStore interface {
	LinkWriter
	LinkReader
	LinkLister
}

// DispatcherStore manages dispatcher state.
type DispatcherStore interface {
	// GetDispatcher retrieves a dispatcher by type, nsid, and ifindex.
	// Returns store.ErrNotFound if the dispatcher does not exist.
	GetDispatcher(ctx context.Context, dispType string, nsid uint64, ifindex uint32) (dispatcher.State, error)

	// SaveDispatcher creates or updates a dispatcher.
	SaveDispatcher(ctx context.Context, state dispatcher.State) error

	// DeleteDispatcher removes a dispatcher by type, nsid, and ifindex.
	DeleteDispatcher(ctx context.Context, dispType string, nsid uint64, ifindex uint32) error

	// IncrementRevision atomically increments the dispatcher revision.
	// Returns the new revision number. Wraps from MaxUint32 to 1.
	IncrementRevision(ctx context.Context, dispType string, nsid uint64, ifindex uint32) (uint32, error)
}

// Store combines program, link, and dispatcher store operations.
type Store interface {
	io.Closer
	ProgramStore
	LinkStore
	DispatcherStore
	Transactional
}

// Transactional provides atomic execution of store operations.
// The callback receives a Store that participates in the transaction.
// If the callback returns nil, the transaction commits.
// If the callback returns an error, the transaction rolls back.
type Transactional interface {
	RunInTransaction(ctx context.Context, fn func(Store) error) error
}

// ProgramReader reads program metadata from the store.
// Get returns store.ErrNotFound if the program does not exist.
type ProgramReader interface {
	Get(ctx context.Context, kernelID uint32) (bpfman.Program, error)
}

// ProgramWriter writes program metadata to the store.
type ProgramWriter interface {
	Save(ctx context.Context, kernelID uint32, metadata bpfman.Program) error
	Delete(ctx context.Context, kernelID uint32) error
}

// ProgramLister lists all program metadata from the store.
type ProgramLister interface {
	List(ctx context.Context) (map[uint32]bpfman.Program, error)
}

// ProgramFinder finds programs by criteria.
type ProgramFinder interface {
	// FindProgramByMetadata finds a program by a metadata key/value pair.
	// Returns store.ErrNotFound if no matching program exists.
	FindProgramByMetadata(ctx context.Context, key, value string) (bpfman.Program, uint32, error)
}

// ProgramStore combines all store operations.
type ProgramStore interface {
	ProgramReader
	ProgramWriter
	ProgramLister
	ProgramFinder
}

// KernelSource provides access to kernel BPF objects.
type KernelSource interface {
	Programs(ctx context.Context) iter.Seq2[kernel.Program, error]
	GetProgramByID(ctx context.Context, id uint32) (kernel.Program, error)
	GetLinkByID(ctx context.Context, id uint32) (kernel.Link, error)
	GetMapByID(ctx context.Context, id uint32) (kernel.Map, error)
	Maps(ctx context.Context) iter.Seq2[kernel.Map, error]
	Links(ctx context.Context) iter.Seq2[kernel.Link, error]
}

// ProgramLoader loads BPF programs into the kernel.
type ProgramLoader interface {
	Load(ctx context.Context, spec bpfman.LoadSpec) (bpfman.ManagedProgram, error)
}

// ProgramUnloader removes BPF programs from the kernel.
type ProgramUnloader interface {
	Unload(ctx context.Context, pinPath string) error
	// UnloadProgram removes a program and its maps using the upstream pin layout.
	UnloadProgram(ctx context.Context, progPinPath, mapsDir string) error
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
	AttachTracepoint(progPinPath, group, name, linkPinPath string) (bpfman.ManagedLink, error)
	// AttachXDP attaches a pinned XDP program to a network interface.
	AttachXDP(progPinPath string, ifindex int, linkPinPath string) (bpfman.ManagedLink, error)
}

// XDPDispatcherResult holds the result of loading an XDP dispatcher.
type XDPDispatcherResult struct {
	DispatcherID  uint32 // Kernel program ID of the dispatcher
	LinkID        uint32 // Kernel link ID
	DispatcherPin string // Pin path for dispatcher program
	LinkPin       string // Pin path for link
}

// DispatcherAttacher attaches dispatcher programs for multi-program chaining.
type DispatcherAttacher interface {
	// AttachXDPDispatcher loads and attaches an XDP dispatcher to an interface.
	// The dispatcher allows multiple XDP programs to be chained together.
	// numProgs specifies how many slots to enable, proceedOn is the bitmask for chain behaviour.
	AttachXDPDispatcher(ifindex int, pinDir string, numProgs int, proceedOn uint32) (*XDPDispatcherResult, error)

	// AttachXDPDispatcherWithPaths loads and attaches an XDP dispatcher to an interface
	// with explicit paths for the dispatcher program and link.
	// This is used when the caller has computed paths according to the Rust bpfman convention.
	//
	// Parameters:
	//   - ifindex: Network interface index
	//   - progPinPath: Path to pin the dispatcher program (e.g., .../dispatcher_{nsid}_{ifindex}_{revision}/dispatcher)
	//   - linkPinPath: Stable path to pin the XDP link (e.g., .../xdp/dispatcher_{nsid}_{ifindex}_link)
	//   - numProgs: Number of extension slots to enable
	//   - proceedOn: Bitmask of XDP return codes that trigger continuation to next program
	AttachXDPDispatcherWithPaths(ifindex int, progPinPath, linkPinPath string, numProgs int, proceedOn uint32) (*XDPDispatcherResult, error)

	// AttachXDPExtension loads a program from ELF as Extension type and attaches
	// it to a dispatcher slot. The program is loaded with BPF_PROG_TYPE_EXT
	// targeting the dispatcher's slot function.
	AttachXDPExtension(dispatcherPinPath, objectPath, programName string, position int, linkPinPath string) (bpfman.ManagedLink, error)
}

// LinkDetacher detaches links from hooks.
type LinkDetacher interface {
	// DetachLink removes a pinned link by deleting its pin from bpffs.
	// This releases the kernel link if it was the last reference.
	DetachLink(linkPinPath string) error
}

// PinRemover removes pins from bpffs.
type PinRemover interface {
	// RemovePin removes a pin or empty directory from bpffs.
	// Returns nil if the path does not exist.
	RemovePin(path string) error
}

// MapRepinner re-pins maps to new locations.
type MapRepinner interface {
	// RepinMap loads a pinned map and re-pins it to a new path.
	// Used by CSI to expose maps to per-pod bpffs.
	RepinMap(srcPath, dstPath string) error
}

// KernelOperations combines all kernel operations.
type KernelOperations interface {
	KernelSource
	ProgramLoader
	ProgramUnloader
	PinInspector
	ProgramAttacher
	DispatcherAttacher
	LinkDetacher
	PinRemover
	MapRepinner
}

// ImageRef describes an OCI image to pull.
type ImageRef struct {
	// URL is the OCI image reference (e.g., "quay.io/bpfman-bytecode/xdp_pass:latest").
	URL string
	// PullPolicy specifies when to pull the image.
	PullPolicy bpfman.ImagePullPolicy
	// Auth contains optional authentication credentials. Nil for anonymous access.
	Auth *ImageAuth
}

// ImageAuth contains credentials for authenticating to an OCI registry.
type ImageAuth struct {
	Username string
	Password string
}

// PulledImage is the result of successfully pulling an OCI image.
type PulledImage struct {
	// ObjectPath is the path to the extracted ELF bytecode file.
	ObjectPath string
	// Programs maps program names to their types from the io.ebpf.programs label.
	Programs map[string]string
	// Maps maps map names to their types from the io.ebpf.maps label.
	Maps map[string]string
	// Digest is the resolved image digest.
	Digest string
}

// ImagePuller fetches BPF bytecode from OCI images.
type ImagePuller interface {
	// Pull downloads an image and returns the extracted bytecode.
	// The returned ObjectPath is valid until the puller is closed or
	// the cache is cleaned.
	Pull(ctx context.Context, ref ImageRef) (PulledImage, error)
}

// SignatureVerifier verifies OCI image signatures.
type SignatureVerifier interface {
	// Verify checks that the image has a valid signature.
	// Returns nil if verification succeeds or is not required.
	// Returns an error if the image signature is invalid or missing
	// (when unsigned images are not allowed).
	Verify(ctx context.Context, imageRef string) error
}
