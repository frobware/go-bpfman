// Package action contains reified effects - descriptions of what to do
// without actually doing it. These are pure data structures.
package action

import "github.com/frobware/go-bpfman/pkg/bpfman/managed"

// Action represents an effect to be executed.
// Actions are data - they describe what to do, not how.
type Action interface {
	isAction()
}

// Store actions - operations on the metadata store

// SaveProgram saves program metadata to the store.
type SaveProgram struct {
	KernelID uint32
	Metadata managed.Program
}

func (SaveProgram) isAction() {}

// DeleteProgram removes program metadata from the store.
type DeleteProgram struct {
	KernelID uint32
}

func (DeleteProgram) isAction() {}

// MarkProgramUnloading transitions a program to unloading state.
type MarkProgramUnloading struct {
	KernelID uint32
}

func (MarkProgramUnloading) isAction() {}

// Link actions - operations on link metadata

// DeleteLink removes a link from the store.
type DeleteLink struct {
	UUID string
}

func (DeleteLink) isAction() {}

// SaveTracepointLink saves a tracepoint link to the store.
type SaveTracepointLink struct {
	Summary managed.LinkSummary
	Details managed.TracepointDetails
}

func (SaveTracepointLink) isAction() {}

// SaveXDPLink saves an XDP link to the store.
type SaveXDPLink struct {
	Summary managed.LinkSummary
	Details managed.XDPDetails
}

func (SaveXDPLink) isAction() {}

// SaveTCLink saves a TC link to the store.
type SaveTCLink struct {
	Summary managed.LinkSummary
	Details managed.TCDetails
}

func (SaveTCLink) isAction() {}

// Kernel actions - operations on the BPF subsystem

// LoadProgram loads a BPF program into the kernel.
type LoadProgram struct {
	Spec managed.LoadSpec
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
	State managed.DispatcherState
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
