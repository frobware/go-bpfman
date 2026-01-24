// Package action contains reified effects - descriptions of what to do
// without actually doing it. These are pure data structures.
package action

import (
	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/dispatcher"
)

// Action represents an effect to be executed.
// Actions are data - they describe what to do, not how.
type Action interface {
	isAction()
}

// Store actions - operations on the metadata store

// SaveProgram saves program metadata to the store.
type SaveProgram struct {
	KernelID uint32
	Metadata bpfman.Program
}

func (SaveProgram) isAction() {}

// DeleteProgram removes program metadata from the store.
type DeleteProgram struct {
	KernelID uint32
}

func (DeleteProgram) isAction() {}

// Link actions - operations on link metadata

// DeleteLink removes a link from the store by kernel link ID.
type DeleteLink struct {
	KernelLinkID uint32
}

func (DeleteLink) isAction() {}

// SaveTracepointLink saves a tracepoint link to the store.
type SaveTracepointLink struct {
	Summary bpfman.LinkSummary
	Details bpfman.TracepointDetails
}

func (SaveTracepointLink) isAction() {}

// SaveXDPLink saves an XDP link to the store.
type SaveXDPLink struct {
	Summary bpfman.LinkSummary
	Details bpfman.XDPDetails
}

func (SaveXDPLink) isAction() {}

// SaveTCLink saves a TC link to the store.
type SaveTCLink struct {
	Summary bpfman.LinkSummary
	Details bpfman.TCDetails
}

func (SaveTCLink) isAction() {}

// SaveTCXLink saves a TCX link to the store.
type SaveTCXLink struct {
	Summary bpfman.LinkSummary
	Details bpfman.TCXDetails
}

func (SaveTCXLink) isAction() {}

// SaveKprobeLink saves a kprobe link to the store.
type SaveKprobeLink struct {
	Summary bpfman.LinkSummary
	Details bpfman.KprobeDetails
}

func (SaveKprobeLink) isAction() {}

// SaveUprobeLink saves a uprobe link to the store.
type SaveUprobeLink struct {
	Summary bpfman.LinkSummary
	Details bpfman.UprobeDetails
}

func (SaveUprobeLink) isAction() {}

// SaveFentryLink saves a fentry link to the store.
type SaveFentryLink struct {
	Summary bpfman.LinkSummary
	Details bpfman.FentryDetails
}

func (SaveFentryLink) isAction() {}

// SaveFexitLink saves a fexit link to the store.
type SaveFexitLink struct {
	Summary bpfman.LinkSummary
	Details bpfman.FexitDetails
}

func (SaveFexitLink) isAction() {}

// Kernel actions - operations on the BPF subsystem

// LoadProgram loads a BPF program into the kernel.
type LoadProgram struct {
	Spec bpfman.LoadSpec
}

func (LoadProgram) isAction() {}

// UnloadProgram removes a BPF program from the kernel.
type UnloadProgram struct {
	PinPath string
}

func (UnloadProgram) isAction() {}

// Batch groups multiple actions to be executed together.
type Batch struct {
	Actions []Action
}

func (Batch) isAction() {}

// Sequence executes actions in order, stopping on first error.
type Sequence struct {
	Actions []Action
}

func (Sequence) isAction() {}

// Dispatcher actions - operations on dispatcher state

// SaveDispatcher creates or updates a dispatcher in the store.
type SaveDispatcher struct {
	State dispatcher.State
}

func (SaveDispatcher) isAction() {}

// DeleteDispatcher removes a dispatcher from the store.
type DeleteDispatcher struct {
	Type    string
	Nsid    uint64
	Ifindex uint32
}

func (DeleteDispatcher) isAction() {}

// Kernel link actions - operations on kernel links

// DetachLink removes a link pin from bpffs, releasing the kernel link.
type DetachLink struct {
	PinPath string
}

func (DetachLink) isAction() {}

// Filesystem actions - operations on bpffs pins

// RemovePin removes a pin from bpffs. Ignores "not exist" errors.
type RemovePin struct {
	Path string
}

func (RemovePin) isAction() {}
